module Wiretap
  module Interceptor
    # Entry point called from the HTTP::Client reopen below.
    # Dispatches based on transcript mode: replay, record, or pass-through.
    def self.handle(
      transcript : Transcript,
      client : HTTP::Client,
      request : HTTP::Request,
      &real_request : -> HTTP::Client::Response
    ) : HTTP::Client::Response
      url = build_url(client, request)

      case transcript.mode
      when :none
        # Strict replay. Raise immediately on any unrecognised request.
        replay_or_raise(transcript, request.method, url)
      when :always
        # Always re-record, even if the transcript already holds interactions.
        record_and_return(transcript, request, url, real_request)
      when :once
        if transcript.loaded?
          # Transcript file existed on disk — treat it as frozen.
          # Any request not in the transcript is an error, the same as :none.
          replay_or_raise(transcript, request.method, url)
        else
          # First recording run — make the real request and capture it.
          record_and_return(transcript, request, url, real_request)
        end
      else
        real_request.call
      end
    end

    # --- private helpers ----------------------------------------------------

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
      # Read the request body before the real call so we can store it, then
      # reset it on the request so the actual HTTP send is unaffected.
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

      # Return a fresh response; the original `raw` body has been consumed.
      build_response(raw.status.code, raw.headers, body)
    end

    # Builds a response from live HTTP::Headers (used after a real request).
    private def self.build_response(status : Int32, headers : HTTP::Headers, body : String) : HTTP::Client::Response
      HTTP::Client::Response.new(status, body: body, headers: headers)
    end

    # Builds a response from a stored Hash (used during replay).
    private def self.build_response(status : Int32, headers : Hash(String, String), body : String) : HTTP::Client::Response
      h = HTTP::Headers.new
      headers.each { |k, v| h[k] = v }
      HTTP::Client::Response.new(status, body: body, headers: h)
    end

    # Constructs the full URL from the HTTP::Client instance and request.
    # Omits the port when it matches the scheme default (80/443).
    private def self.build_url(client : HTTP::Client, request : HTTP::Request) : String
      scheme = client.tls? ? "https" : "http"
      host = client.host
      port = client.port
      default_port = scheme == "https" ? 443 : 80
      port_suffix = port == default_port ? "" : ":#{port}"
      "#{scheme}://#{host}#{port_suffix}#{request.resource}"
    end

    # Reads the request body IO to a String for recording, then replaces the
    # body with a fresh IO::Memory so the actual HTTP send is unaffected.
    # Returns nil for requests with no body or an empty body.
    private def self.read_and_reset_body(request : HTTP::Request) : String?
      body_io = request.body
      return nil unless body_io

      content = body_io.gets_to_end
      return nil if content.empty?

      # body=(String) creates a new IO::Memory and updates Content-Length.
      request.body = content
      content
    end

    # Converts HTTP::Headers to a plain Hash, replacing filtered header
    # values with "[FILTERED]". Multi-value headers are joined with ", ".
    private def self.filter_headers(headers : HTTP::Headers) : Hash(String, String)
      filter_list = Wiretap.config.filter_headers.map(&.downcase)
      result = {} of String => String
      headers.each do |name, values|
        result[name] = filter_list.includes?(name.downcase) ? "[FILTERED]" : values.join(", ")
      end
      result
    end

    # Converts HTTP::Headers to a plain Hash for storage.
    private def self.normalize_headers(headers : HTTP::Headers) : Hash(String, String)
      result = {} of String => String
      headers.each { |name, values| result[name] = values.join(", ") }
      result
    end
  end
end

# ---------------------------------------------------------------------------
# HTTP::Client reopen — the interception wedge point.
#
# All convenience class methods (HTTP::Client.get, .post, etc.) and all
# instance exec overloads taking (method, path, ...) ultimately call one
# of these two exec(request) forms. Intercepting here covers the full
# surface area without patching every overload.
#
# `previous_def` calls the original method as it existed before this reopen.
# ---------------------------------------------------------------------------
class HTTP::Client
  # Non-streaming form — fully buffers response body into a String.
  # This is the form used by most LLM client wrappers.
  def exec(request : HTTP::Request) : HTTP::Client::Response
    if transcript = Wiretap.active_transcript
      Wiretap::Interceptor.handle(transcript, self, request) { previous_def }
    else
      previous_def
    end
  end

  # Streaming form — yields a Response whose body_io must be read within
  # the block. Wiretap passes this through unrecorded in v0.1.
  # Streaming transcript support is planned for v0.2.
  def exec(request : HTTP::Request, &block : HTTP::Client::Response ->)
    previous_def { |response| block.call(response) }
  end
end
