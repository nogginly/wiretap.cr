require "./spec_helper"

# ---------------------------------------------------------------------------
# These specs do NOT make real network calls.
#
# They exercise the intercept/replay logic by:
#   1. Pre-seeding transcript JSON files on disk, or
#   2. Verifying that :none mode raises on an unrecognised request.
#
# Real-network "record" behaviour is validated in the transcript_spec via
# Transcript#save round-trips. Full integration tests (which *do* spin up a
# local HTTP server) are left for a future spec file.
# ---------------------------------------------------------------------------

# Top-level helper — seeds a transcript JSON file and returns its path.
# Must live outside describe blocks; Crystal forbids dynamic def declarations.
def seed_transcript(name : String, method : String, url : String, status : Int32, body : String) : String
  dir = Wiretap.config.transcript_dir
  Dir.mkdir_p(dir)

  interaction = Wiretap::Interaction.new(
    Wiretap::RequestData.new(method, url, {} of String => String),
    Wiretap::ResponseData.new(status, {"Content-Type" => "application/json"}, body)
  )
  envelope = {name: name, recorded_with: "wiretap/test", interactions: [interaction]}
  path = File.join(dir, "#{name}.json")
  File.write(path, envelope.to_pretty_json)
  path
end

describe "Wiretap.intercept" do
  current_dir = [""]

  before_each do
    current_dir[0] = tmp_transcript_dir
    Wiretap.configure { |c| c.transcript_dir = current_dir[0] }
  end

  after_each do
    FileUtils.rm_rf(current_dir[0]) unless current_dir[0].empty?
  end

  describe "active_transcript scoping" do
    it "is nil outside an intercept block" do
      Wiretap.active_transcript.should be_nil
    end

    it "is set inside an intercept block" do
      seed_transcript("scope_test", "GET", "https://example.com/", 200, "{}")

      Wiretap.intercept("scope_test", mode: :none) do
        Wiretap.active_transcript.should_not be_nil
        Wiretap.active_transcript.not_nil!.name.should eq("scope_test")
      end
    end

    it "is nil again after the intercept block exits" do
      seed_transcript("scope_after", "GET", "https://example.com/", 200, "{}")
      Wiretap.intercept("scope_after", mode: :none) { }
      Wiretap.active_transcript.should be_nil
    end

    it "clears the transcript even when the block raises" do
      seed_transcript("scope_raise", "GET", "https://example.com/", 200, "{}")
      expect_raises(Exception) do
        Wiretap.intercept("scope_raise", mode: :none) { raise "boom" }
      end
      Wiretap.active_transcript.should be_nil
    end
  end

  describe ":none mode" do
    it "raises Wiretap::Error for an unrecognised request" do
      seed_transcript("strict", "GET", "https://example.com/known", 200, "{}")

      expect_raises(Wiretap::Error, /No recorded interaction/) do
        Wiretap.intercept("strict", mode: :none) do
          HTTP::Client.get("https://example.com/unknown")
        end
      end
    end
  end

  describe ":once mode — replay from existing transcript" do
    it "replays the recorded response without a real network call" do
      seed_transcript("replay_once", "GET", "https://api.example.com/status", 200, %({"ok":true}))

      response = uninitialized HTTP::Client::Response

      Wiretap.intercept("replay_once", mode: :once) do
        response = HTTP::Client.get("https://api.example.com/status")
      end

      response.status.code.should eq(200)
      response.body.should eq(%({"ok":true}))
    end

    it "replays a POST response with the correct status" do
      seed_transcript(
        "replay_post",
        "POST",
        "https://api.example.com/v1/chat",
        201,
        %({"id":"msg_001"})
      )

      response = uninitialized HTTP::Client::Response

      Wiretap.intercept("replay_post", mode: :once) do
        response = HTTP::Client.post(
          "https://api.example.com/v1/chat",
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: %({"model":"test","messages":[]})
        )
      end

      response.status.code.should eq(201)
      response.body.should eq(%({"id":"msg_001"}))
    end

    it "raises Wiretap::Error for a request not in the loaded transcript" do
      seed_transcript("once_strict", "GET", "https://example.com/known", 200, "{}")

      expect_raises(Wiretap::Error, /No recorded interaction/) do
        Wiretap.intercept("once_strict", mode: :once) do
          HTTP::Client.get("https://example.com/unknown")
        end
      end
    end
  end

  describe "header filtering" do
    it "records [FILTERED] in place of Authorization values" do
      t = Wiretap::Transcript.load_or_create("header_filter_test", :once)

      req = Wiretap::RequestData.new(
        "POST",
        "https://api.example.com/v1/chat",
        {"Authorization" => "[FILTERED]", "Content-Type" => "application/json"}
      )
      resp = Wiretap::ResponseData.new(200, {} of String => String, "{}")
      t.record(Wiretap::Interaction.new(req, resp))
      t.save

      reloaded = Wiretap::Transcript.load_or_create("header_filter_test", :once)
      stored_headers = reloaded.interactions.first.request.headers

      stored_headers["Authorization"].should eq("[FILTERED]")
      stored_headers["Content-Type"].should eq("application/json")
    end
  end
end
