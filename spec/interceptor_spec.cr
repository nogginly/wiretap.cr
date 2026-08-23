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
def seed_transcript(
  name : String,
  method : String,
  url : String,
  status : Int32,
  response_body : String,
  request_body : String? = nil,
) : String
  dir = Wiretap.config.transcript_dir
  Dir.mkdir_p(dir)

  body_digest = request_body ? Digest::SHA256.hexdigest(request_body) : nil

  interaction = Wiretap::Interaction.new(
    Wiretap::RequestData.new(method, url, {} of String => String, request_body, body_digest),
    Wiretap::ResponseData.new(status, {"Content-Type" => "application/json"}, response_body)
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

    it "does not mention body digest when nothing shares the method and URL" do
      seed_transcript("strict_no_match", "GET", "https://example.com/known", 200, "{}")

      expect_raises(Wiretap::Error, /^No recorded interaction for GET https:\/\/example\.com\/unknown$/) do
        Wiretap.intercept("strict_no_match", mode: :none) do
          HTTP::Client.get("https://example.com/unknown")
        end
      end
    end

    it "names the digest mismatch when method and URL match but the body differs" do
      seed_transcript(
        "strict_digest_mismatch", "POST", "https://api.example.com/v1/messages",
        200, %({"ok":true}), request_body: %({"id":"mc_1787427226104_0"})
      )

      expect_raises(Wiretap::Error, /1 interaction matched method and URL but the request body digest differed/) do
        Wiretap.intercept("strict_digest_mismatch", mode: :none) do
          HTTP::Client.post(
            "https://api.example.com/v1/messages",
            body: %({"id":"mc_1787427999999_0"})
          )
        end
      end
    end

    it "pluralizes the count when multiple interactions match method and URL" do
      dir = current_dir[0]
      Dir.mkdir_p(dir)
      path = File.join(dir, "strict_digest_mismatch_multi.json")
      interactions = ["aaa", "bbb"].map do |body|
        Wiretap::Interaction.new(
          Wiretap::RequestData.new("POST", "https://api.example.com/v1/messages", {} of String => String, body, Digest::SHA256.hexdigest(body)),
          Wiretap::ResponseData.new(200, {} of String => String, %({"ok":true}))
        )
      end
      File.write(path, {name: "strict_digest_mismatch_multi", recorded_with: "wiretap/test", interactions: interactions}.to_pretty_json)

      expect_raises(Wiretap::Error, /2 interactions matched method and URL but the request body digest differed/) do
        Wiretap.intercept("strict_digest_mismatch_multi", mode: :none) do
          HTTP::Client.post("https://api.example.com/v1/messages", body: "ccc")
        end
      end
    end

    it "does not mention digest for a bodyless request even if the URL is recorded with a body" do
      seed_transcript(
        "strict_bodyless_miss", "POST", "https://api.example.com/v1/messages",
        200, %({"ok":true}), request_body: %({"id":"1"})
      )

      expect_raises(Wiretap::Error, /^No recorded interaction for GET https:\/\/api\.example\.com\/v1\/messages$/) do
        Wiretap.intercept("strict_bodyless_miss", mode: :none) do
          HTTP::Client.get("https://api.example.com/v1/messages")
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
        %({"id":"msg_001"}),
        %({"model":"test","messages":[]})
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
