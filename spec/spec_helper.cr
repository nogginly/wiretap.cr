require "spec"
require "file_utils"
require "../src/wiretap"

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
