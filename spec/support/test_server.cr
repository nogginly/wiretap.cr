# ---------------------------------------------------------------------------
# Integration specs — real HTTP::Server, real sockets, real IO.
#
# A single TestServer instance is started once for the suite and shared
# across all examples. Each endpoint tracks how many times it was called
# so specs can assert whether a request hit the real server or was replayed
# from a transcript without touching the network.
# ---------------------------------------------------------------------------

class TestServer
  getter request_counts : Hash(String, Int32)

  @server : HTTP::Server
  @base_url : String

  def initialize
    @request_counts = Hash(String, Int32).new(0)
    @base_url = ""
    @server = HTTP::Server.new { |ctx| handle(ctx) }
  end

  # Binds to an OS-assigned free port and starts listening in a fiber.
  # Returns the base URL callers should use, e.g. "http://localhost:54321".
  def start : String
    address = @server.bind_unused_port
    spawn { @server.listen }
    @base_url = "http://#{address}"
  end

  def close : Nil
    @server.close
  end

  def base_url : String
    @base_url
  end

  # Resets all counters between examples.
  def reset_counts : Nil
    @request_counts.transform_values! { 0 }
  end

  private def handle(ctx : HTTP::Server::Context) : Nil
    path = ctx.request.path
    @request_counts[path] = @request_counts.fetch(path, 0) + 1

    ctx.response.content_type = "application/json"

    case path
    when "/status"
      ctx.response.print %({"status":"ok"})
    when "/chat"
      ctx.response.status = HTTP::Status::CREATED
      ctx.response.print %({"id":"msg_001","content":"Hello!"})
    when "/error"
      ctx.response.status = HTTP::Status::INTERNAL_SERVER_ERROR
      ctx.response.print %({"error":"something went wrong"})
    when "/stream"
      ctx.response.headers["Content-Type"] = "text/event-stream"
      ctx.response.headers["Cache-Control"] = "no-cache"
      [
        %(data: {"delta":{"content":"Hello"}}),
        %(data: {"delta":{"content":" world"}}),
        "data: [DONE]",
      ].each do |chunk|
        ctx.response.print "#{chunk}\n\n"
        ctx.response.flush
      end
    when "/stream_endless"
      stream_endless(ctx)
    else
      ctx.response.status = HTTP::Status::NOT_FOUND
      ctx.response.print %({"error":"not found"})
    end
  end

  # Sends a numbered SSE event every few milliseconds until the client
  # disconnects, like a long-lived MCP channel. Capped so a broken client
  # cannot keep the suite alive forever.
  private def stream_endless(ctx : HTTP::Server::Context) : Nil
    ctx.response.headers["Content-Type"] = "text/event-stream"
    ctx.response.headers["Cache-Control"] = "no-cache"
    1.upto(2000) do |n|
      ctx.response.print "data: event #{n}\n\n"
      ctx.response.flush
      sleep 5.milliseconds
    end
  rescue IO::Error
  end
end
