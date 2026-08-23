module Wiretap
  # :nodoc:
  module Interceptor
    def self.handle(
      transcript : Transcript,
      client : HTTP::Client,
      request : HTTP::Request,
      &real_request : -> HTTP::Client::Response
    ) : HTTP::Client::Response
      url = build_url(client, request)

      raw_body = peek_body(request)
      normalized_body = raw_body ? Wiretap.config.apply_body_normalization(raw_body) : nil
      body_digest = compute_body_digest(normalized_body)

      case transcript.mode
      when :none
        replay_or_raise(transcript, request.method, url, body_digest)
      when :always
        record_and_return(transcript, request, url, real_request)
      when :once
        if transcript.loaded?
          replay_or_raise(transcript, request.method, url, body_digest)
        else
          record_and_return(transcript, request, url, real_request)
        end
      else
        real_request.call
      end
    end

    def self.handle_streaming(
      transcript : Transcript,
      client : HTTP::Client,
      request : HTTP::Request,
      user_block : HTTP::Client::Response ->,
      &real_request : (HTTP::Client::Response ->) ->
    ) : Nil
      url = build_url(client, request)

      raw_body = peek_body(request)
      normalized_body = raw_body ? Wiretap.config.apply_body_normalization(raw_body) : nil
      body_digest = compute_body_digest(normalized_body)

      case transcript.mode
      when :none
        replay_streaming_or_raise(transcript, request.method, url, body_digest, user_block)
      when :always
        record_and_stream(transcript, request, url, user_block, real_request)
      when :once
        if transcript.loaded?
          replay_streaming_or_raise(transcript, request.method, url, body_digest, user_block)
        else
          record_and_stream(transcript, request, url, user_block, real_request)
        end
      else
        real_request.call(user_block)
      end
    end

    private def self.replay_or_raise(transcript : Transcript, method : String, url : String, body_digest : String?) : HTTP::Client::Response
      normalized = Wiretap.config.apply_url_normalization(url)
      interaction = transcript.find_interaction(method, normalized, body_digest)
      raise Wiretap::Error.new(miss_message(transcript, method, normalized, body_digest)) unless interaction
      build_response(interaction.response.status, interaction.response.headers, interaction.response.body)
    end

    # Builds a diagnostic message for a replay miss.
    #
    # Distinguishes "nothing shares this method and URL" from "something
    # does, but the request body digest differs" — the latter is the far
    # more common and more confusing case in practice.
    private def self.miss_message(transcript : Transcript, method : String, url : String, body_digest : String?) : String
      base = "No recorded interaction for #{method} #{url}"
      return base if body_digest.nil?

      candidates = transcript.matching_method_and_url(method, url)
      return base if candidates.empty?

      noun = candidates.size == 1 ? "interaction" : "interactions"
      "#{base} — #{candidates.size} #{noun} matched method and URL but the request body digest differed"
    end

    private def self.record_and_return(
      transcript : Transcript,
      request : HTTP::Request,
      url : String,
      real_request : -> HTTP::Client::Response,
    ) : HTTP::Client::Response
      req_body = read_and_reset_body(request)

      raw = real_request.call
      body = raw.body

      normalized_url = Wiretap.config.apply_url_normalization(url)
      normalized_body = req_body ? Wiretap.config.apply_body_normalization(req_body) : nil
      body_digest = compute_body_digest(normalized_body)

      req_data = RequestData.new(
        method: request.method,
        url: normalized_url,
        headers: filter_headers(request.headers),
        body: req_body,
        body_digest: body_digest
      )
      resp_data = ResponseData.new(
        status: raw.status.code,
        headers: normalize_headers(raw.headers),
        body: body
      )
      transcript.record(Interaction.new(req_data, resp_data))

      build_response(raw.status.code, raw.headers, body)
    end

    private def self.build_response(status : Int32, headers : HTTP::Headers, body : String) : HTTP::Client::Response
      HTTP::Client::Response.new(status, body: body, headers: headers)
    end

    private def self.build_response(status : Int32, headers : Hash(String, String), body : String) : HTTP::Client::Response
      h = HTTP::Headers.new
      headers.each { |k, v| h[k] = v }
      HTTP::Client::Response.new(status, body: body, headers: h)
    end

    private def self.replay_streaming_or_raise(
      transcript : Transcript,
      method : String,
      url : String,
      body_digest : String?,
      user_block : HTTP::Client::Response ->,
    ) : Nil
      normalized = Wiretap.config.apply_url_normalization(url)
      interaction = transcript.find_interaction(method, normalized, body_digest)
      raise Wiretap::Error.new(miss_message(transcript, method, normalized, body_digest)) unless interaction

      h = HTTP::Headers.new
      interaction.response.headers.each { |k, v| h[k] = v }
      io = IO::Memory.new(interaction.response.body)
      response = HTTP::Client::Response.new(interaction.response.status, body_io: io, headers: h)
      user_block.call(response)
    end

    private def self.record_and_stream(
      transcript : Transcript,
      request : HTTP::Request,
      url : String,
      user_block : HTTP::Client::Response ->,
      real_request : (HTTP::Client::Response ->) ->,
    ) : Nil
      req_body = read_and_reset_body(request)

      real_request.call(->(response : HTTP::Client::Response) {
        body = response.body_io.gets_to_end

        normalized_url = Wiretap.config.apply_url_normalization(url)
        normalized_body = req_body ? Wiretap.config.apply_body_normalization(req_body) : nil
        body_digest = compute_body_digest(normalized_body)

        req_data = RequestData.new(
          method: request.method,
          url: normalized_url,
          headers: filter_headers(request.headers),
          body: req_body,
          body_digest: body_digest
        )
        resp_data = ResponseData.new(
          status: response.status.code,
          headers: normalize_headers(response.headers),
          body: body
        )
        transcript.record(Interaction.new(req_data, resp_data))

        io = IO::Memory.new(body)
        replayed = HTTP::Client::Response.new(response.status.code, body_io: io, headers: response.headers)
        user_block.call(replayed)
      })
    end

    private def self.build_url(client : HTTP::Client, request : HTTP::Request) : String
      scheme = client.tls? ? "https" : "http"
      host = client.host
      port = client.port
      default_port = scheme == "https" ? 443 : 80
      port_suffix = port == default_port ? "" : ":#{port}"
      "#{scheme}://#{host}#{port_suffix}#{request.resource}"
    end

    private def self.peek_body(request : HTTP::Request) : String?
      body_io = request.body
      return nil unless body_io
      content = body_io.gets_to_end
      return nil if content.empty?
      request.body = content
      content
    end

    private def self.read_and_reset_body(request : HTTP::Request) : String?
      body_io = request.body
      return nil unless body_io
      content = body_io.gets_to_end
      return nil if content.empty?
      request.body = content
      content
    end

    private def self.compute_body_digest(body : String?) : String?
      return nil if body.nil? || body.empty?
      Digest::SHA256.hexdigest(body)
    end

    private def self.filter_headers(headers : HTTP::Headers) : Hash(String, String)
      filter_list = Wiretap.config.filter_headers.map(&.downcase)
      result = {} of String => String
      headers.each do |name, values|
        result[name] = filter_list.includes?(name.downcase) ? "[FILTERED]" : values.join(", ")
      end
      result
    end

    private def self.normalize_headers(headers : HTTP::Headers) : Hash(String, String)
      result = {} of String => String
      headers.each { |name, values| result[name] = values.join(", ") }
      result
    end
  end
end

# :nodoc:
class HTTP::Client
  def exec(request : HTTP::Request) : HTTP::Client::Response
    if transcript = Wiretap.active_transcript
      Wiretap::Interceptor.handle(transcript, self, request) { previous_def }
    else
      previous_def
    end
  end

  def exec(request : HTTP::Request, &block : HTTP::Client::Response ->)
    if transcript = Wiretap.active_transcript
      Wiretap::Interceptor.handle_streaming(transcript, self, request, block) do |inner|
        previous_def { |response| inner.call(response) }
      end
    else
      previous_def { |response| block.call(response) }
    end
  end
end
