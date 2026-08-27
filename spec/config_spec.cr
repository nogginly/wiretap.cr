require "./spec_helper"

describe Wiretap::Config do
  describe "defaults" do
    it "sets transcript_dir to spec/transcripts" do
      Wiretap.config.transcript_dir.should eq("spec/transcripts")
    end

    it "sets record_mode to :once" do
      Wiretap.config.record_mode.should eq(:once)
    end

    it "filters Authorization and X-Api-Key by default" do
      Wiretap.config.filter_headers.should contain("Authorization")
      Wiretap.config.filter_headers.should contain("X-Api-Key")
    end

    it "filters well-known non-standard LLM/cloud API key headers by default" do
      Wiretap.config.filter_headers.should contain("X-Goog-Api-Key")
      Wiretap.config.filter_headers.should contain("Api-Key")
    end

    it "has no headers ignored for the suspected-secret warning by default" do
      Wiretap.config.ignore_suspected_secrets.should be_empty
    end

    it "sets a default on_suspected_secret proc" do
      Wiretap.config.on_suspected_secret.should_not be_nil
    end
  end

  describe "Wiretap.configure" do
    it "mutates the shared config" do
      Wiretap.configure do |c|
        c.transcript_dir = "tmp/transcripts"
        c.record_mode = :none
      end

      Wiretap.config.transcript_dir.should eq("tmp/transcripts")
      Wiretap.config.record_mode.should eq(:none)
    end

    it "allows additional filter headers to be appended" do
      Wiretap.configure do |c|
        c.filter_headers << "X-Custom-Secret"
      end

      Wiretap.config.filter_headers.should contain("X-Custom-Secret")
    end

    it "allows on_suspected_secret to be overridden" do
      called_with = [] of {String, String}
      Wiretap.configure do |c|
        c.on_suspected_secret = ->(name : String, value : String) {
          called_with << {name, value}
          nil
        }
      end

      Wiretap.config.on_suspected_secret.call("X-Secret", "value")
      called_with.should eq([{"X-Secret", "value"}])
    end

    it "allows headers to be exempted from the suspected-secret warning" do
      Wiretap.configure do |c|
        c.ignore_suspected_secrets << "X-Idempotency-Key"
      end

      Wiretap.config.ignore_suspected_secrets.should contain("X-Idempotency-Key")
    end
  end

  describe "Wiretap.reset_config" do
    it "restores defaults after mutation" do
      Wiretap.configure { |c| c.record_mode = :always }
      Wiretap.reset_config
      Wiretap.config.record_mode.should eq(:once)
    end
  end
end
