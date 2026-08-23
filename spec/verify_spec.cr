require "./spec_helper"

# ---------------------------------------------------------------------------
# Wiretap.verify! catches the failure mode :once alone cannot: a suite that
# passes but did so by silently re-recording rather than replaying. These
# specs do NOT make real network calls; they exercise Transcript#record
# directly, which is where recorded_count is incremented.
# ---------------------------------------------------------------------------

describe "Wiretap recorded-interaction tracking" do
  current_dir = [""]

  before_each do
    current_dir[0] = tmp_transcript_dir
    Wiretap.configure { |c| c.transcript_dir = current_dir[0] }
  end

  after_each do
    FileUtils.rm_rf(current_dir[0]) unless current_dir[0].empty?
  end

  it "starts at zero" do
    Wiretap.recorded_count.should eq(0)
  end

  it "increments when an interaction is recorded" do
    t = Wiretap::Transcript.load_or_create("verify_count", :once)
    t.record(Wiretap::Interaction.new(
      Wiretap::RequestData.new("GET", "https://example.com/", {} of String => String),
      Wiretap::ResponseData.new(200, {} of String => String, "ok")
    ))

    Wiretap.recorded_count.should eq(1)
  end

  it "does not increment on replay" do
    seed_transcript("verify_replay", "GET", "https://example.com/known", 200, "{}")

    Wiretap.intercept("verify_replay", mode: :none) do
      HTTP::Client.get("https://example.com/known")
    end

    Wiretap.recorded_count.should eq(0)
  end

  it "increments once per recorded interaction across multiple intercept blocks" do
    t1 = Wiretap::Transcript.load_or_create("verify_multi_a", :always)
    t1.record(Wiretap::Interaction.new(
      Wiretap::RequestData.new("GET", "https://a.example.com/", {} of String => String),
      Wiretap::ResponseData.new(200, {} of String => String, "ok")
    ))
    t2 = Wiretap::Transcript.load_or_create("verify_multi_b", :always)
    t2.record(Wiretap::Interaction.new(
      Wiretap::RequestData.new("GET", "https://b.example.com/", {} of String => String),
      Wiretap::ResponseData.new(200, {} of String => String, "ok")
    ))

    Wiretap.recorded_count.should eq(2)
  end

  describe "#reset_recording_count!" do
    it "resets the count to zero" do
      t = Wiretap::Transcript.load_or_create("verify_reset", :once)
      t.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("GET", "https://example.com/", {} of String => String),
        Wiretap::ResponseData.new(200, {} of String => String, "ok")
      ))
      Wiretap.recorded_count.should eq(1)

      Wiretap.reset_recording_count!

      Wiretap.recorded_count.should eq(0)
    end
  end

  describe "#verify!" do
    it "does not raise when nothing was recorded" do
      seed_transcript("verify_ok", "GET", "https://example.com/known", 200, "{}")

      Wiretap.intercept("verify_ok", mode: :none) do
        HTTP::Client.get("https://example.com/known")
      end

      Wiretap.verify!
    end

    it "raises Wiretap::Error naming the count when one interaction was recorded" do
      t = Wiretap::Transcript.load_or_create("verify_fail_one", :once)
      t.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("GET", "https://example.com/", {} of String => String),
        Wiretap::ResponseData.new(200, {} of String => String, "ok")
      ))

      expect_raises(Wiretap::Error, /1 interaction was recorded rather than replayed/) do
        Wiretap.verify!
      end
    end

    it "pluralizes and raises Wiretap::Error naming the count when several interactions were recorded" do
      t = Wiretap::Transcript.load_or_create("verify_fail_many", :once)
      2.times do |i|
        t.record(Wiretap::Interaction.new(
          Wiretap::RequestData.new("GET", "https://example.com/#{i}", {} of String => String),
          Wiretap::ResponseData.new(200, {} of String => String, "ok")
        ))
      end

      expect_raises(Wiretap::Error, /2 interactions were recorded rather than replayed/) do
        Wiretap.verify!
      end
    end
  end
end
