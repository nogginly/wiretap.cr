require "./spec_helper"

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
    else
      ctx.response.status = HTTP::Status::NOT_FOUND
      ctx.response.print %({"error":"not found"})
    end
  end
end

# ---------------------------------------------------------------------------
# Suite setup — server starts once for the whole file.
# Per-example transcript dir is handled inside the describe block.
# ---------------------------------------------------------------------------

test_server = TestServer.new
current_dir = [""]

Spec.before_suite { test_server.start }
Spec.after_suite { test_server.close }

# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------

describe "Wiretap integration" do
  before_each do
    current_dir[0] = tmp_transcript_dir
    Wiretap.configure { |c| c.transcript_dir = current_dir[0] }
    test_server.reset_counts
  end

  after_each do
    FileUtils.rm_rf(current_dir[0]) unless current_dir[0].empty?
  end

  describe ":once mode — first run records, second run replays" do
    it "makes a real request and saves a transcript on first run" do
      Wiretap.intercept("get_status", mode: :once) do
        HTTP::Client.get("#{test_server.base_url}/status")
      end

      # Server was actually called.
      test_server.request_counts["/status"].should eq(1)

      # Transcript was written to disk.
      path = File.join(current_dir[0], "get_status.json")
      File.exists?(path).should be_true

      # Transcript contains the interaction.
      t = Wiretap::Transcript.load_or_create("get_status", :once)
      t.interactions.size.should eq(1)
      t.interactions.first.response.body.should eq(%({"status":"ok"}))
    end

    it "replays from transcript on second run without hitting the server" do
      # First run — record.
      Wiretap.intercept("get_status_replay", mode: :once) do
        HTTP::Client.get("#{test_server.base_url}/status")
      end

      test_server.reset_counts

      # Second run — replay.
      response = uninitialized HTTP::Client::Response
      Wiretap.intercept("get_status_replay", mode: :once) do
        response = HTTP::Client.get("#{test_server.base_url}/status")
      end

      # Server was NOT called during replay.
      test_server.request_counts.fetch("/status", 0).should eq(0)

      response.status.code.should eq(200)
      response.body.should eq(%({"status":"ok"}))
    end

    it "records a POST with body and replays it correctly" do
      Wiretap.intercept("post_chat", mode: :once) do
        HTTP::Client.post(
          "#{test_server.base_url}/chat",
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: %({"model":"test","messages":[]})
        )
      end

      test_server.reset_counts

      response = uninitialized HTTP::Client::Response
      Wiretap.intercept("post_chat", mode: :once) do
        response = HTTP::Client.post(
          "#{test_server.base_url}/chat",
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: %({"model":"test","messages":[]})
        )
      end

      test_server.request_counts.fetch("/chat", 0).should eq(0)
      response.status.code.should eq(201)
      response.body.should eq(%({"id":"msg_001","content":"Hello!"}))
    end

    it "records non-200 status codes faithfully" do
      Wiretap.intercept("server_error", mode: :once) do
        HTTP::Client.get("#{test_server.base_url}/error")
      end

      response = uninitialized HTTP::Client::Response
      Wiretap.intercept("server_error", mode: :once) do
        response = HTTP::Client.get("#{test_server.base_url}/error")
      end

      response.status.code.should eq(500)
      response.body.should eq(%({"error":"something went wrong"}))
    end
  end

  describe ":always mode — re-records on every run" do
    it "overwrites an existing transcript and hits the server again" do
      # First run — record.
      Wiretap.intercept("always_test", mode: :always) do
        HTTP::Client.get("#{test_server.base_url}/status")
      end

      test_server.reset_counts

      # Second run — should hit server again, not replay.
      Wiretap.intercept("always_test", mode: :always) do
        HTTP::Client.get("#{test_server.base_url}/status")
      end

      test_server.request_counts["/status"].should eq(1)
    end
  end

  describe ":none mode — strict replay only" do
    it "raises Wiretap::Error when no transcript exists" do
      expect_raises(Wiretap::Error, /No recorded interaction/) do
        Wiretap.intercept("no_such_transcript", mode: :none) do
          HTTP::Client.get("#{test_server.base_url}/status")
        end
      end
    end

    it "does not hit the server when replaying" do
      # Seed a transcript by recording first.
      Wiretap.intercept("none_test", mode: :once) do
        HTTP::Client.get("#{test_server.base_url}/status")
      end

      test_server.reset_counts

      Wiretap.intercept("none_test", mode: :none) do
        HTTP::Client.get("#{test_server.base_url}/status")
      end

      test_server.request_counts.fetch("/status", 0).should eq(0)
    end
  end

  describe "header filtering" do
    it "does not write Authorization values to the transcript" do
      Wiretap.intercept("auth_header_test", mode: :once) do
        HTTP::Client.get(
          "#{test_server.base_url}/status",
          HTTP::Headers{"Authorization" => "Bearer super_secret"}
        )
      end

      t = Wiretap::Transcript.load_or_create("auth_header_test", :once)
      stored = t.interactions.first.request.headers["Authorization"]?
      stored.should eq("[FILTERED]")
    end
  end

  describe "streaming (SSE) — record and replay" do
    it "records a streaming response and saves the body to the transcript" do
      Wiretap.intercept("stream_record", mode: :once) do
        client = HTTP::Client.new(URI.parse(test_server.base_url))
        client.exec(HTTP::Request.new("GET", "/stream")) do |response|
          response.body_io.gets_to_end
        end
      end

      test_server.request_counts["/stream"].should eq(1)

      t = Wiretap::Transcript.load_or_create("stream_record", :once)
      t.interactions.size.should eq(1)
      t.interactions.first.response.body.should contain("Hello")
      t.interactions.first.response.body.should contain("[DONE]")
    end

    it "replays a streaming response via body_io without hitting the server" do
      # First run — record.
      Wiretap.intercept("stream_replay", mode: :once) do
        client = HTTP::Client.new(URI.parse(test_server.base_url))
        client.exec(HTTP::Request.new("GET", "/stream")) do |response|
          response.body_io.gets_to_end
        end
      end

      test_server.reset_counts

      # Second run — replay.
      replayed_body = ""
      Wiretap.intercept("stream_replay", mode: :once) do
        client = HTTP::Client.new(URI.parse(test_server.base_url))
        client.exec(HTTP::Request.new("GET", "/stream")) do |response|
          replayed_body = response.body_io.gets_to_end
        end
      end

      test_server.request_counts.fetch("/stream", 0).should eq(0)
      replayed_body.should contain("Hello")
      replayed_body.should contain(" world")
      replayed_body.should contain("[DONE]")
    end

    it "raises Wiretap::Error in :none mode when no streaming transcript exists" do
      expect_raises(Wiretap::Error, /No recorded interaction/) do
        Wiretap.intercept("stream_missing", mode: :none) do
          client = HTTP::Client.new(URI.parse(test_server.base_url))
          client.exec(HTTP::Request.new("GET", "/stream")) do |response|
            response.body_io.gets_to_end
          end
        end
      end
    end
  end
  describe "request normalization" do
    it "stores the raw body as sent, even when normalize_body is configured" do
      Wiretap.configure do |c|
        c.normalize_body = ->(body : String) {
          parsed = JSON.parse(body).as_h
          parsed.delete("user")
          parsed.to_json
        }
      end

      raw_body = %({"model":"test","user":"user_abc123_20250510T120000Z"})

      Wiretap.intercept("body_norm_record", mode: :once) do
        HTTP::Client.post(
          "#{test_server.base_url}/chat",
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: raw_body
        )
      end

      t = Wiretap::Transcript.load_or_create("body_norm_record", :once)
      stored_body = t.interactions.first.request.body
      stored_body.should_not be_nil
      stored_body.not_nil!.should eq(raw_body)
    end

    it "digests the normalized body while storing the raw one, so replay still matches" do
      Wiretap.configure do |c|
        c.normalize_body = ->(body : String) {
          parsed = JSON.parse(body).as_h
          parsed.delete("user")
          parsed.to_json
        }
      end

      Wiretap.intercept("body_norm_replay", mode: :once) do
        HTTP::Client.post(
          "#{test_server.base_url}/chat",
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: %({"model":"test","user":"user_abc123_20250510T120000Z"})
        )
      end

      # A second call with a different volatile "user" field, but the same
      # normalized shape, should still replay the same recorded interaction
      # rather than hitting the real server and recording a second one.
      response = uninitialized HTTP::Client::Response
      Wiretap.intercept("body_norm_replay", mode: :once) do
        response = HTTP::Client.post(
          "#{test_server.base_url}/chat",
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: %({"model":"test","user":"user_zzz999_20990101T000000Z"})
        )
      end

      t = Wiretap::Transcript.load_or_create("body_norm_replay", :once)
      t.interactions.size.should eq(1)
      response.status.code.should eq(201)
    end

    it "normalizes the URL before saving to the transcript" do
      Wiretap.configure do |c|
        c.normalize_url = ->(url : String) { url.gsub(/token=[^&]+/, "token=[FILTERED]") }
      end

      Wiretap.intercept("url_norm_record", mode: :once) do
        HTTP::Client.get("#{test_server.base_url}/status?token=secret123")
      end

      t = Wiretap::Transcript.load_or_create("url_norm_record", :once)
      stored_url = t.interactions.first.request.url
      stored_url.should contain("[FILTERED]")
      stored_url.should_not contain("secret123")
    end
  end

  describe "same-name transcript with different bodies" do
    it "records and replays two distinct interactions by body digest" do
      # Both requests POST to the same endpoint under the same transcript name.
      # Without digest matching they would collide; with it each gets its own
      # recorded interaction.
      Wiretap.intercept("shared_chat", mode: :once) do
        HTTP::Client.post(
          "#{test_server.base_url}/chat",
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: %({"model":"fast","messages":[]})
        )
        HTTP::Client.post(
          "#{test_server.base_url}/chat",
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: %({"model":"slow","messages":[]})
        )
      end

      # Transcript holds two distinct interactions.
      t = Wiretap::Transcript.load_or_create("shared_chat", :once)
      t.interactions.size.should eq(2)

      test_server.reset_counts

      # Replay — each request finds its own interaction by digest.
      responses = [] of HTTP::Client::Response
      Wiretap.intercept("shared_chat", mode: :once) do
        responses << HTTP::Client.post(
          "#{test_server.base_url}/chat",
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: %({"model":"fast","messages":[]})
        )
        responses << HTTP::Client.post(
          "#{test_server.base_url}/chat",
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: %({"model":"slow","messages":[]})
        )
      end

      # Server was not called during replay.
      test_server.request_counts.fetch("/chat", 0).should eq(0)

      # Both responses replayed correctly.
      responses.size.should eq(2)
      responses.all? { |r| r.status.code == 201 }.should be_true
    end
  end
end
