require "json"
require "http/client"

require "./wiretap/error"
require "./wiretap/config"
require "./wiretap/interaction"
require "./wiretap/transcript"
require "./wiretap/interceptor"

module Wiretap
  # :nodoc:
  VERSION = {{ `shards version #{__DIR__}`.chomp.stringify }}

  # ---------------------------------------------------------------------------
  # Configuration
  # ---------------------------------------------------------------------------

  @@config : Config = Config.new

  def self.config : Config
    @@config
  end

  # Yields the config object for mutation inside a block.
  #
  #   Wiretap.configure do |c|
  #     c.transcript_dir = "spec/fixtures/transcripts"
  #     c.record_mode    = :none
  #     c.filter_headers << "X-Custom-Key"
  #   end
  def self.configure(&) : Nil
    yield @@config
  end

  # Resets config to defaults. Useful in spec helpers between suites.
  def self.reset_config : Nil
    @@config = Config.new
  end

  # ---------------------------------------------------------------------------
  # Active transcript — the interception seam
  #
  # A Fiber-local value so nested intercept blocks work without leaking state
  # across fibers (relevant when running specs concurrently with Spectator).
  # ---------------------------------------------------------------------------

  def self.active_transcript : Transcript?
    Fiber.current.wiretap_transcript
  end

  def self.active_transcript=(t : Transcript?) : Nil
    Fiber.current.wiretap_transcript = t
  end

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  # Runs *block* with all HTTP::Client traffic intercepted according to the
  # named transcript and the active (or overridden) record mode.
  #
  # Usage:
  #   Wiretap.intercept("chat_completion") do
  #     HTTP::Client.post("https://api.example.com/v1/chat", ...)
  #   end
  #
  # Options:
  #   mode: overrides Wiretap.config.record_mode for this block only.
  def self.intercept(name : String, mode : Symbol = config.record_mode, &) : Nil
    transcript = Transcript.load_or_create(name, mode)
    self.active_transcript = transcript

    begin
      yield
    ensure
      self.active_transcript = nil
      transcript.save if transcript.dirty?
    end
  end
end

# ---------------------------------------------------------------------------
# Fiber extension — per-fiber transcript slot
# ---------------------------------------------------------------------------

class Fiber
  property wiretap_transcript : Wiretap::Transcript? = nil
end
