require "./spec_helper"

describe Wiretap::Transcript do
  # Each example gets its own temp directory so there is no cross-test
  # file system pollution. We store it in a variable shared between
  # before_each and after_each via a closure over a local array (the
  # idiomatic pattern in Crystal's baseline spec).
  current_dir = [""]

  before_each do
    current_dir[0] = tmp_transcript_dir
    Wiretap.configure { |c| c.transcript_dir = current_dir[0] }
  end

  after_each do
    FileUtils.rm_rf(current_dir[0]) unless current_dir[0].empty?
  end

  describe ".load_or_create" do
    it "returns a fresh transcript when no file exists" do
      t = Wiretap::Transcript.load_or_create("new_transcript", :once)
      t.interactions.should be_empty
      t.loaded?.should be_false
    end

    it "loads interactions from an existing file" do
      # --- seed the file manually ---
      dir = Wiretap.config.transcript_dir
      seed_interaction = Wiretap::Interaction.new(
        Wiretap::RequestData.new("GET", "https://example.com/", {} of String => String),
        Wiretap::ResponseData.new(200, {} of String => String, "hello")
      )
      seed = {
        name:          "existing",
        recorded_with: "wiretap/test",
        interactions:  [seed_interaction],
      }
      File.write(File.join(dir, "existing.json"), seed.to_pretty_json)

      t = Wiretap::Transcript.load_or_create("existing", :once)
      t.loaded?.should be_true
      t.interactions.size.should eq(1)
      t.interactions.first.request.url.should eq("https://example.com/")
    end

    it "ignores an existing file when mode is :always" do
      dir = Wiretap.config.transcript_dir
      File.write(File.join(dir, "redo.json"), %q({"name":"redo","recorded_with":"x","interactions":[]}))

      t = Wiretap::Transcript.load_or_create("redo", :always)
      t.loaded?.should be_false
    end
  end

  describe "#find_interaction" do
    it "returns the matching interaction by method and url" do
      t = Wiretap::Transcript.load_or_create("find_test", :once)
      interaction = Wiretap::Interaction.new(
        Wiretap::RequestData.new("POST", "https://api.example.com/v1/chat", {} of String => String),
        Wiretap::ResponseData.new(200, {} of String => String, "ok")
      )
      t.record(interaction)

      found = t.find_interaction("POST", "https://api.example.com/v1/chat")
      found.should_not be_nil
      found.not_nil!.response.body.should eq("ok")
    end

    it "returns nil when no match exists" do
      t = Wiretap::Transcript.load_or_create("find_test_miss", :once)
      t.find_interaction("GET", "https://missing.example.com/").should be_nil
    end
  end

  describe "#matching_method_and_url" do
    it "returns interactions that share method and url regardless of body digest" do
      t = Wiretap::Transcript.load_or_create("near_miss_test", :once)
      t.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("POST", "https://api.example.com/v1/chat", {} of String => String, "a", "digest-a"),
        Wiretap::ResponseData.new(200, {} of String => String, "ok")
      ))
      t.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("POST", "https://api.example.com/v1/chat", {} of String => String, "b", "digest-b"),
        Wiretap::ResponseData.new(200, {} of String => String, "ok")
      ))

      matches = t.matching_method_and_url("POST", "https://api.example.com/v1/chat")
      matches.size.should eq(2)
    end

    it "is empty when method and url do not match anything" do
      t = Wiretap::Transcript.load_or_create("near_miss_empty", :once)
      t.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("GET", "https://api.example.com/v1/chat", {} of String => String),
        Wiretap::ResponseData.new(200, {} of String => String, "ok")
      ))

      t.matching_method_and_url("POST", "https://other.example.com/").should be_empty
    end
  end

  describe "#save" do
    it "writes a parseable JSON file to transcript_dir" do
      t = Wiretap::Transcript.load_or_create("save_test", :once)
      t.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("GET", "https://example.com/save", {} of String => String),
        Wiretap::ResponseData.new(200, {} of String => String, "saved!")
      ))
      t.save

      path = File.join(Wiretap.config.transcript_dir, "save_test.json")
      File.exists?(path).should be_true

      reloaded = Wiretap::Transcript.load_or_create("save_test", :once)
      reloaded.loaded?.should be_true
      reloaded.interactions.first.response.body.should eq("saved!")
    end

    it "creates intermediate directories that do not yet exist" do
      Wiretap.configure { |c| c.transcript_dir = File.join(c.transcript_dir, "nested/deep") }
      t = Wiretap::Transcript.load_or_create("deep_save", :once)
      t.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("GET", "https://example.com/deep", {} of String => String),
        Wiretap::ResponseData.new(200, {} of String => String, "deep!")
      ))
      t.save

      path = File.join(Wiretap.config.transcript_dir, "deep_save.json")
      File.exists?(path).should be_true
    end

    it "merges new interactions into an existing transcript on save" do
      t1 = Wiretap::Transcript.load_or_create("merge_test", :once)
      t1.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("POST", "https://api.example.com/chat",
          {} of String => String, %({"model":"fast"}), Digest::SHA256.hexdigest(%({"model":"fast"}))),
        Wiretap::ResponseData.new(200, {} of String => String, %({"reply":"fast"}))
      ))
      t1.save

      # Second save — different body, should append not overwrite.
      t2 = Wiretap::Transcript.load_or_create("merge_test", :once)
      t2.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("POST", "https://api.example.com/chat",
          {} of String => String, %({"model":"slow"}), Digest::SHA256.hexdigest(%({"model":"slow"}))),
        Wiretap::ResponseData.new(200, {} of String => String, %({"reply":"slow"}))
      ))
      t2.save

      reloaded = Wiretap::Transcript.load_or_create("merge_test", :once)
      reloaded.interactions.size.should eq(2)
      reloaded.interactions.map(&.response.body).should contain(%({"reply":"fast"}))
      reloaded.interactions.map(&.response.body).should contain(%({"reply":"slow"}))
    end

    it "does not duplicate an interaction already present in the transcript" do
      t1 = Wiretap::Transcript.load_or_create("dedup_test", :once)
      t1.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("GET", "https://api.example.com/status",
          {} of String => String, nil, nil),
        Wiretap::ResponseData.new(200, {} of String => String, %({"ok":true}))
      ))
      t1.save

      # Save the same interaction again.
      t2 = Wiretap::Transcript.load_or_create("dedup_test", :once)
      t2.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("GET", "https://api.example.com/status",
          {} of String => String, nil, nil),
        Wiretap::ResponseData.new(200, {} of String => String, %({"ok":true}))
      ))
      t2.save

      reloaded = Wiretap::Transcript.load_or_create("dedup_test", :once)
      reloaded.interactions.size.should eq(1)
    end
  end

  describe "#dirty?" do
    it "is false before any interactions are recorded" do
      t = Wiretap::Transcript.load_or_create("dirty_check", :once)
      t.dirty?.should be_false
    end

    it "is true after recording an interaction" do
      t = Wiretap::Transcript.load_or_create("dirty_check2", :once)
      t.record(Wiretap::Interaction.new(
        Wiretap::RequestData.new("GET", "https://example.com/", {} of String => String),
        Wiretap::ResponseData.new(200, {} of String => String, "")
      ))
      t.dirty?.should be_true
    end
  end
end
