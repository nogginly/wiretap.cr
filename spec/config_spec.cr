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
  end

  describe "Wiretap.reset_config" do
    it "restores defaults after mutation" do
      Wiretap.configure { |c| c.record_mode = :always }
      Wiretap.reset_config
      Wiretap.config.record_mode.should eq(:once)
    end
  end
end
