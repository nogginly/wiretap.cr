module Wiretap
  class Transcript
    # Serializable envelope — the only thing written to/read from disk.
    # Kept private so callers interact with Transcript directly.
    private struct Body
      include JSON::Serializable

      property name : String
      property recorded_with : String
      property interactions : Array(Interaction)

      def initialize(@name : String, @recorded_with : String, @interactions : Array(Interaction))
      end
    end

    getter name : String
    getter mode : Symbol
    getter interactions : Array(Interaction)

    @dirty : Bool
    @loaded : Bool # true if the transcript file existed on disk at load time
    @path : String
    @recorded_with : String

    # Private — callers use .load_or_create.
    private def initialize(
      @name : String,
      @mode : Symbol,
      @path : String,
      @interactions : Array(Interaction) = [] of Interaction,
      @loaded : Bool = false,
      @recorded_with : String = "wiretap/#{Wiretap::VERSION}",
    )
      @dirty = false
    end

    # Loads an existing transcript from disk, or creates a fresh one.
    # When mode is :always the existing file is ignored and a fresh
    # transcript is returned — this is the "re-record everything" semantic.
    def self.load_or_create(name : String, mode : Symbol) : Transcript
      path = File.join(Wiretap.config.transcript_dir, "#{name}.json")

      if File.exists?(path) && mode != :always
        body = Body.from_json(File.read(path))
        new(name, mode, path,
          interactions: body.interactions,
          loaded: true,
          recorded_with: body.recorded_with)
      else
        new(name, mode, path)
      end
    end

    # Finds the first interaction matching method + url, or nil.
    def find_interaction(method : String, url : String) : Interaction?
      @interactions.find { |i| i.request.method == method && i.request.url == url }
    end

    # Appends an interaction and marks the transcript as needing a save.
    def record(interaction : Interaction) : Nil
      @interactions << interaction
      @dirty = true
    end

    # True when at least one interaction has been recorded since load.
    def dirty? : Bool
      @dirty
    end

    # True when this transcript was loaded from an existing file on disk.
    # Used by the interceptor to distinguish a first recording run from
    # subsequent replay-only runs under :once mode.
    def loaded? : Bool
      @loaded
    end

    # Persists the transcript to disk as pretty-printed JSON.
    # Creates intermediate directories if they do not exist.
    def save : Nil
      Dir.mkdir_p(File.dirname(@path))
      body = Body.new(@name, @recorded_with, @interactions)
      File.write(@path, body.to_pretty_json)
    end
  end
end
