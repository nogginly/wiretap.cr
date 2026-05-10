require "spec"
require "file_utils"
require "../src/wiretap"

# Reset Wiretap config before every example so tests are independent.
Spec.before_each do
  Wiretap.reset_config
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
