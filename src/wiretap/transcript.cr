module Wiretap
  # :nodoc:
  class Transcript
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
    @loaded : Bool
    @path : String
    @recorded_with : String

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

    def find_interaction(method : String, url : String, body_digest : String? = nil) : Interaction?
      @interactions.find do |i|
        next false unless i.request.method == method && i.request.url == url
        body_digest.nil? ? true : i.request.body_digest == body_digest
      end
    end

    def record(interaction : Interaction) : Nil
      @interactions << interaction
      @dirty = true
    end

    def dirty? : Bool
      @dirty
    end

    def loaded? : Bool
      @loaded
    end

    def save : Nil
      Dir.mkdir_p(File.dirname(@path))
      body = Body.new(@name, @recorded_with, @interactions)
      File.write(@path, body.to_pretty_json)
    end
  end
end
