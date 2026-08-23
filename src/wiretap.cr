require "json"
require "digest/sha256"
require "http/client"

require "./wiretap/error"
require "./wiretap/config"
require "./wiretap/interaction"
require "./wiretap/transcript"
require "./wiretap/interceptor"

# Wiretap records and replays HTTP interactions for deterministic testing.
#
# All HTTP traffic made via `HTTP::Client` inside a `Wiretap.intercept` block
# is intercepted. On the first run, requests pass through to the real server
# and the interaction is saved to a JSON transcript file. On subsequent runs,
# matching requests are replayed from the transcript without touching the
# network.
#
# ### Quick start
#
# ```
# # spec/spec_helper.cr
# require "wiretap"
#
# Wiretap.configure do |c|
#   c.record_mode = ENV["CI"]? ? :none : :once
# end
#
# # Fails the run if any transcript was recorded rather than replayed —
# # catches a missing or newly-required transcript silently re-recording
# # under :once instead of failing loudly the way :none would.
# Spec.after_suite { Wiretap.verify! }
# ```
#
# ```
# it "returns a completion" do
#   Wiretap.intercept("chat_completion") do
#     response = HTTP::Client.post(
#       "https://api.example.com/v1/chat/completions",
#       headers: HTTP::Headers{"Authorization" => "Bearer #{ENV["API_KEY"]}"},
#       body: {model: "my-model", messages: []}.to_json
#     )
#     response.status.code.should eq(200)
#   end
# end
# ```
module Wiretap
  # :nodoc:
  VERSION = {{ `shards version #{__DIR__}`.chomp.stringify }}

  # ---------------------------------------------------------------------------
  # Configuration
  # ---------------------------------------------------------------------------

  @@config : Config = Config.new

  # :nodoc:
  def self.config : Config
    @@config
  end

  # Configures Wiretap by yielding the shared `Config` instance.
  #
  # Place this in `spec/spec_helper.cr`. Settings apply to all subsequent
  # `intercept` calls unless overridden per block.
  #
  # ```
  # Wiretap.configure do |c|
  #   c.transcript_dir = "spec/fixtures/transcripts"
  #   c.record_mode = :none
  #   c.filter_headers << "X-Custom-Key"
  # end
  # ```
  def self.configure(&) : Nil
    yield @@config
  end

  # Resets all configuration to defaults.
  #
  # Useful in `Spec.before_each` when tests mutate config and need a clean
  # slate between examples.
  def self.reset_config : Nil
    @@config = Config.new
  end

  # ---------------------------------------------------------------------------
  # Recorded-interaction tracking
  # ---------------------------------------------------------------------------

  @@recorded_count = Atomic(Int32).new(0)

  # :nodoc:
  def self.note_recorded_interaction : Nil
    @@recorded_count.add(1)
  end

  # The number of interactions recorded (not replayed) since the last
  # `reset_recording_count!`.
  #
  # Under `:once`, a missing or newly-required transcript is recorded rather
  # than failed, so a passing suite does not by itself mean anything
  # replayed. This is the count `verify!` checks.
  def self.recorded_count : Int32
    @@recorded_count.get
  end

  # Resets `recorded_count` to zero.
  #
  # Call this at the start of a run (e.g. `Spec.before_suite`) if a previous
  # run in the same process may have recorded interactions and you want
  # `verify!` to judge only what happened since.
  def self.reset_recording_count! : Nil
    @@recorded_count.set(0)
  end

  # Raises `Wiretap::Error` if any interaction was recorded, rather than
  # replayed, since the last `reset_recording_count!`.
  #
  # A suite running under `:once` passes whether it replayed from disk or
  # quietly re-recorded against the real network — the assertions can't
  # tell the difference, because a re-recorded transcript is by
  # construction consistent with the response it just captured. `verify!`
  # makes that distinction visible:
  #
  # ```
  # Spec.after_suite { Wiretap.verify! }
  # ```
  #
  # Placed in CI, this fails the build the moment a transcript goes missing
  # or a new interaction is required, instead of leaving a suite that has
  # silently stopped testing anything against a recorded baseline.
  def self.verify! : Nil
    count = recorded_count
    return if count.zero?

    noun = count == 1 ? "interaction was" : "interactions were"
    raise Wiretap::Error.new(
      "#{count} #{noun} recorded rather than replayed during this run"
    )
  end

  # ---------------------------------------------------------------------------
  # Active transcript — internal interception seam
  # ---------------------------------------------------------------------------

  # :nodoc:
  def self.active_transcript : Transcript?
    Fiber.current.wiretap_transcript
  end

  # :nodoc:
  def self.active_transcript=(t : Transcript?) : Nil
    Fiber.current.wiretap_transcript = t
  end

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  # Intercepts all `HTTP::Client` traffic within the block, recording or
  # replaying interactions according to the named transcript and record mode.
  #
  # On the first run (no transcript file on disk), requests pass through to
  # the real server and the interaction is saved to
  # `<transcript_dir>/<name>.json`. On subsequent runs, matching requests are
  # replayed from the transcript without opening a socket.
  #
  # Multiple calls to the same endpoint with different request bodies can share
  # a transcript name — each interaction is keyed by a SHA256 digest of the
  # normalized body and coexists in the same file without collision.
  #
  # The `mode` keyword overrides `Wiretap.config.record_mode` for this block
  # only. See `Config#record_mode` for the available modes.
  #
  # ```
  # Wiretap.intercept("list_models") do
  #   response = HTTP::Client.get("https://api.example.com/v1/models")
  #   response.status.code.should eq(200)
  # end
  # ```
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

# :nodoc:
class Fiber
  property wiretap_transcript : Wiretap::Transcript? = nil
end
