module Wiretap
  module Interceptor
    # ---------------------------------------------------------------------------
    # Non-streaming entry point
    # ---------------------------------------------------------------------------

    def self.handle(
      transcript : Transcript,
      client : HTTP::Client,
      request : HTTP::Request,
      &real_request : -> HTTP::Client::Response
    ) : HTTP::Client::Response
      url = build_url(client, request)

      case transcript.mode
      when :none
        replay_or_raise(transcript, request.method, url)
      when :always
        record_and_return(transcript, request, url, real_request)
      when :once
        if transcript.loaded?
          replay_or_raise(transcript, request.method, url)
        else
          record_and_return(transcript, request, url, real_request)
        end
      else
        real_request.call
      end
    end

    # ---------------------------------------------------------------------------
    # Streaming entry point
    #
    # user_block   — the block the caller passed to HTTP::Client#exec; receives
    #                the (possibly replayed) response and reads body_io from it.
    # &real_request — a block that accepts an inner Proc and runs `previous_def`
    #                 with it, yielding the live response to that proc.
    # ---------------------------------------------------------------------------

    def self.handle_streaming(
      transcript : Transcript,
      client : HTTP::Client,
      request : HTTP::Request,
      user_block : HTTP::Client::Response ->,
      &real_request : (HTTP::Client::Response ->) ->
    ) : Nil
      url = build_url(client, request)

      case transcript.mode
      when :none
        replay_streaming_or_raise(transcript, request.method, url, user_block)
      when :always
        record_and_stream(transcript, request, url, user_block, real_request)
      when :once
        if transcript.loaded?
          replay_streaming_or_raise(transcript, request.method, url, user_block)
        else
          record_and_stream(transcript, request, url, user_block, real_request)
        end
      else
        real_request.call(user_block)
      end
    end

    # ---------------------------------------------------------------------------
    # Non-streaming private helpers
    # ---------------------------------------------------------------------------

    private def self.replay_or_raise(transcript : Transcript, method : String, url : String) : HTTP::Client::Response
      interaction = transcript.find_interaction(method, url)
      raise Wiretap::Error.new("No recorded interaction for #{method} #{url}") unless interaction
      build_response(interaction.response.status, interaction.response.headers, interaction.response.body)
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

      req_data = RequestData.new(
        method: request.method,
        url: url,
        headers: filter_headers(request.headers),
        body: req_body
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

    # ---------------------------------------------------------------------------
    # Streaming private helpers
    # ---------------------------------------------------------------------------

    private def self.replay_streaming_or_raise(
      transcript : Transcript,
      method : String,
      url : String,
      user_block : HTTP::Client::Response ->,
    ) : Nil
      interaction = transcript.find_interaction(method, url)
      raise Wiretap::Error.new("No recorded interaction for #{method} #{url}") unless interaction

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

        req_data = RequestData.new(
          method: request.method,
          url: url,
          headers: filter_headers(request.headers),
          body: req_body
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

    # ---------------------------------------------------------------------------
    # Shared private helpers
    # ---------------------------------------------------------------------------

    private def self.build_url(client : HTTP::Client, request : HTTP::Request) : String
      scheme = client.tls? ? "https" : "http"
      host = client.host
      port = client.port
      default_port = scheme == "https" ? 443 : 80
      port_suffix = port == default_port ? "" : ":#{port}"
      "#{scheme}://#{host}#{port_suffix}#{request.resource}"
    end

    private def self.read_and_reset_body(request : HTTP::Request) : String?
      body_io = request.body
      return nil unless body_io

      content = body_io.gets_to_end
      return nil if content.empty?

      request.body = content
      content
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

# ---------------------------------------------------------------------------
# HTTP::Client reopen
# ---------------------------------------------------------------------------

class HTTP::Client
  # Non-streaming — fully buffers response body.
  def exec(request : HTTP::Request) : HTTP::Client::Response
    if transcript = Wiretap.active_transcript
      Wiretap::Interceptor.handle(transcript, self, request) { previous_def }
    else
      previous_def
    end
  end

  # Streaming — buffers body_io for recording, replays via IO::Memory.
  # The caller's block receives a response and reads body_io from it,
  # exactly as it would from a live connection.
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
