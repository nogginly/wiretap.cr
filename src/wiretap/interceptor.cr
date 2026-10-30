module Wiretap
  # :nodoc:
  module Interceptor
    # What to do with an intercepted request, given the transcript's mode
    # and contents.
    enum Action
      Replay
      Record
      PassThrough
    end

    # One intercepted request: its normalized identity, the action the
    # transcript's mode calls for, and how to replay or record it.
    struct Call
      getter action : Action

      def initialize(@transcript : Transcript, client : HTTP::Client, @request : HTTP::Request)
        @url = Wiretap.config.apply_url_normalization(Interceptor.build_url(client, request))
        @raw_body = Interceptor.buffer_body(request)
        normalized_body = @raw_body.try { |body| Wiretap.config.apply_body_normalization(body) }
        @body_digest = Interceptor.compute_body_digest(normalized_body)
        @action = case @transcript.mode
                  when :none   then Action::Replay
                  when :always then Action::Record
                  when :once   then @transcript.loaded? ? Action::Replay : Action::Record
                  else              Action::PassThrough
                  end
      end

      # Returns the recorded response with its body as a `String`, or raises
      # `Wiretap::Error` on a miss.
      def replay : HTTP::Client::Response
        recorded = find_or_raise.response
        Interceptor.build_response(recorded.status, recorded.headers, recorded.body)
      end

      # Returns the recorded response with its body readable through
      # `body_io`, or raises `Wiretap::Error` on a miss. Reading past the end
      # of a truncated recording raises `Wiretap::Error`.
      def replay_streamed : HTTP::Client::Response
        recorded = find_or_raise.response
        body_io = if recorded.truncated?
                    TruncatedBodyIO.new(recorded.body, "#{@request.method} #{@url}")
                  else
                    IO::Memory.new(recorded.body)
                  end
        response = Interceptor.build_response(recorded.status, recorded.headers, "")
        HTTP::Client::Response.new(response.status, body_io: body_io, headers: response.headers)
      end

      # Saves the request together with the given response to the transcript.
      def record(status : Int32, headers : HTTP::Headers, body : String, truncated : Bool = false) : Nil
        req_data = RequestData.new(
          method: @request.method,
          url: @url,
          headers: Interceptor.filter_headers(@request.headers),
          body: @raw_body,
          body_digest: @body_digest
        )
        resp_data = ResponseData.new(status: status, headers: Interceptor.normalize_headers(headers), body: body, truncated: truncated)
        @transcript.record(Interaction.new(req_data, resp_data))
      end

      private def find_or_raise : Interaction
        interaction = @transcript.find_interaction(@request.method, @url, @body_digest)
        raise Wiretap::Error.new(Interceptor.miss_message(@transcript, @request.method, @url, @body_digest)) unless interaction
        interaction
      end
    end

    def self.handle(
      transcript : Transcript,
      client : HTTP::Client,
      request : HTTP::Request,
      &real_request : -> HTTP::Client::Response
    ) : HTTP::Client::Response
      call = Call.new(transcript, client, request)
      case call.action
      in .replay?
        call.replay
      in .record?
        raw = real_request.call
        call.record(raw.status.code, raw.headers, raw.body)
        build_response(raw.status.code, raw.headers, raw.body)
      in .pass_through?
        real_request.call
      end
    end

    # Returns a copy of the live *response* whose `body_io` is a `TeeIO`
    # over the original, so the caller still reads it as it arrives.
    def self.tee(response : HTTP::Client::Response) : {HTTP::Client::Response, TeeIO}
      tee = TeeIO.new(response.body_io? || IO::Memory.new)
      {HTTP::Client::Response.new(response.status, body_io: tee, headers: response.headers), tee}
    end

    # Builds a diagnostic message for a replay miss.
    #
    # Distinguishes "nothing shares this method and URL" from "something
    # does, but the request body digest differs" — the latter is the far
    # more common and more confusing case in practice.
    protected def self.miss_message(transcript : Transcript, method : String, url : String, body_digest : String?) : String
      base = "No recorded interaction for #{method} #{url}"
      return base if body_digest.nil?

      candidates = transcript.matching_method_and_url(method, url)
      return base if candidates.empty?

      noun = candidates.size == 1 ? "interaction" : "interactions"
      "#{base} — #{candidates.size} #{noun} matched method and URL but the request body digest differed"
    end

    protected def self.build_response(status : Int32, headers : HTTP::Headers, body : String) : HTTP::Client::Response
      HTTP::Client::Response.new(status, body: body, headers: headers)
    end

    protected def self.build_response(status : Int32, headers : Hash(String, String), body : String) : HTTP::Client::Response
      h = HTTP::Headers.new
      headers.each { |k, v| h[k] = v }
      HTTP::Client::Response.new(status, body: body, headers: h)
    end

    protected def self.build_url(client : HTTP::Client, request : HTTP::Request) : String
      scheme = client.tls? ? "https" : "http"
      host = client.host
      port = client.port
      default_port = scheme == "https" ? 443 : 80
      port_suffix = port == default_port ? "" : ":#{port}"
      "#{scheme}://#{host}#{port_suffix}#{request.resource}"
    end

    # Reads the request body into a string and replaces it with a rewindable
    # copy so the real request can still send it. Returns nil when there is
    # no body or it is empty.
    protected def self.buffer_body(request : HTTP::Request) : String?
      body_io = request.body
      return unless body_io
      content = body_io.gets_to_end
      return if content.empty?
      request.body = content
      content
    end

    protected def self.compute_body_digest(body : String?) : String?
      return if body.nil? || body.empty?
      Digest::SHA256.hexdigest(body)
    end

    protected def self.filter_headers(headers : HTTP::Headers) : Hash(String, String)
      filter_list = Wiretap.config.filter_headers.map(&.downcase)
      ignore_list = Wiretap.config.ignore_suspected_secrets.map(&.downcase)
      result = {} of String => String
      headers.each do |name, values|
        if filter_list.includes?(name.downcase)
          result[name] = "[FILTERED]"
          next
        end

        value = values.join(", ")
        if !ignore_list.includes?(name.downcase) && SecretHeuristic.suspicious?(name, value)
          Wiretap.config.on_suspected_secret.call(name, value)
        end
        result[name] = value
      end
      result
    end

    protected def self.normalize_headers(headers : HTTP::Headers) : Hash(String, String)
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

  def exec(request : HTTP::Request, &)
    transcript = Wiretap.active_transcript
    return previous_def { |response| yield response } unless transcript

    call = Wiretap::Interceptor::Call.new(transcript, self, request)
    case call.action
    in .replay?
      yield call.replay_streamed
    in .pass_through?
      previous_def { |response| yield response }
    in .record?
      # Hand the caller a teed body, then record whatever it read, also when
      # it leaves early with break or next, but not when it raises. The
      # recording is truncated unless the caller read to the end of stream.
      previous_def do |raw|
        response, tee = Wiretap::Interceptor.tee(raw)
        failed = false
        begin
          yield response
        rescue ex
          failed = true
          raise ex
        ensure
          call.record(raw.status.code, raw.headers, tee.captured, truncated: !tee.reached_end?) unless failed
        end
      end
    end
  end
end
