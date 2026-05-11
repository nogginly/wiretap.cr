require "./spec_helper"

# ---------------------------------------------------------------------------
# Normalization specs — exercises Config#normalize_url and #normalize_body
# in isolation, then verifies they are applied correctly during intercept
# via pre-seeded transcripts (no real network calls).
# ---------------------------------------------------------------------------

describe "Wiretap request normalization" do
  current_dir = [""]

  before_each do
    current_dir[0] = tmp_transcript_dir
    Wiretap.configure { |c| c.transcript_dir = current_dir[0] }
  end

  after_each do
    FileUtils.rm_rf(current_dir[0]) unless current_dir[0].empty?
  end

  describe "Config#apply_url_normalization" do
    it "returns the url unchanged when no proc is configured" do
      url = "https://api.example.com/v1/sessions/sk-abc123/messages"
      Wiretap.config.apply_url_normalization(url).should eq(url)
    end

    it "applies the proc when configured" do
      Wiretap.configure do |c|
        c.normalize_url = ->(url : String) { url.gsub(/sk-[a-z0-9]+/, "[FILTERED]") }
      end
      url = "https://api.example.com/v1/sessions/sk-abc123/messages"
      Wiretap.config.apply_url_normalization(url).should eq(
        "https://api.example.com/v1/sessions/[FILTERED]/messages"
      )
    end
  end

  describe "Config#apply_body_normalization" do
    it "returns the body unchanged when no proc is configured" do
      body = %({"model":"test","user":"user_abc123"})
      Wiretap.config.apply_body_normalization(body).should eq(body)
    end

    it "applies the proc when configured" do
      Wiretap.configure do |c|
        c.normalize_body = ->(body : String) {
          parsed = JSON.parse(body).as_h
          parsed.delete("user")
          parsed.to_json
        }
      end
      body = %({"model":"test","user":"user_abc123"})
      Wiretap.config.apply_body_normalization(body).should eq(%({"model":"test"}))
    end
  end

  describe "URL normalization applied during intercept" do
    it "stores the normalized URL in the transcript" do
      Wiretap.configure do |c|
        c.normalize_url = ->(url : String) { url.gsub(/sk-[a-z0-9]+/, "[FILTERED]") }
      end

      # Seed a transcript whose URL is already normalized, so :none replay
      # works after we verify the recorded URL.
      interaction = Wiretap::Interaction.new(
        Wiretap::RequestData.new(
          "GET",
          "https://api.example.com/v1/sessions/[FILTERED]/messages",
          {} of String => String
        ),
        Wiretap::ResponseData.new(200, {} of String => String, %({"ok":true}))
      )
      envelope = {
        name:          "url_norm_test",
        recorded_with: "wiretap/test",
        interactions:  [interaction],
      }
      File.write(
        File.join(current_dir[0], "url_norm_test.json"),
        envelope.to_pretty_json
      )

      # Replay using the raw (un-normalized) URL — Wiretap must normalize
      # it before matching so the lookup succeeds.
      response = uninitialized HTTP::Client::Response
      Wiretap.intercept("url_norm_test", mode: :once) do
        response = HTTP::Client.get(
          "https://api.example.com/v1/sessions/sk-abc123/messages"
        )
      end

      response.status.code.should eq(200)
      response.body.should eq(%({"ok":true}))
    end
  end

  describe "body normalization applied during intercept" do
    # Body normalization affects storage only — find_interaction matches on
    # method + URL. The value is that volatile fields (timestamps, user IDs)
    # are stripped from the saved transcript, keeping it stable across runs.
    # The recording-side verification (confirming the stored body is clean)
    # lives in integration_spec.cr where a live server is available.
    it "applies the body proc when normalizing for storage" do
      Wiretap.configure do |c|
        c.normalize_body = ->(body : String) {
          parsed = JSON.parse(body).as_h
          parsed.delete("user")
          parsed.to_json
        }
      end

      body = %({"model":"test","user":"user_abc123"})
      Wiretap.config.apply_body_normalization(body).should eq(%({"model":"test"}))
    end
  end
end
