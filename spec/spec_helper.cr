require "spec"
require "file_utils"
require "http/server"
require "../src/wiretap"
require "./support/*"

# Reset Wiretap config and recording state before every example so tests
# are independent — other spec files record interactions too, and
# recorded_count is process-global.
Spec.before_each do
  Wiretap.reset_config
  Wiretap.reset_recording_count!
end

# Wipe any active transcript that a failed test may have left behind.
Spec.after_each do
  Wiretap.active_transcript = nil
end

# ---------------------------------------------------------------------------
# Helpers available in all specs
# ---------------------------------------------------------------------------

# Builds a minimal HTTP::Client::Response — used in interceptor specs to
# represent what the "real" network would have returned.
def fake_response(status : Int32 = 200, body : String = "", headers : HTTP::Headers = HTTP::Headers.new) : HTTP::Client::Response
  HTTP::Client::Response.new(status, body: body, headers: headers)
end

# Returns a temp directory scoped to the current process, cleared on exit.
def tmp_transcript_dir : String
  dir = File.join(Dir.tempdir, "wiretap_specs_#{Process.pid}")
  Dir.mkdir_p(dir)
  dir
end

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

# Runs the block in a fiber and fails the example if it has not finished
# within *limit*; re-raises anything the block raised. Guards specs whose
# failure mode would otherwise be hanging forever.
def within(limit : Time::Span, &block : ->) : Nil
  done = Channel(Exception?).new
  spawn do
    block.call
    done.send(nil)
  rescue ex
    done.send(ex)
  end
  select
  when result = done.receive
    raise result if result
  when timeout(limit)
    fail "did not finish within #{limit}"
  end
end
