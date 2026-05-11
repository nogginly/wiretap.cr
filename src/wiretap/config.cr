module Wiretap
  class Config
    # Directory where transcript JSON files are stored.
    property transcript_dir : String = "spec/transcripts"

    # Default record mode for Wiretap.intercept calls.
    # :once    — record if transcript absent; strict replay if present
    # :always  — always re-record, discarding any existing transcript
    # :none    — strict replay only; raise on any unmatched request
    property record_mode : Symbol = :once

    # Header names whose values are replaced with "[FILTERED]" before saving.
    property filter_headers : Array(String) = ["Authorization", "X-Api-Key"]

    # Optional proc applied to the request URL before matching and saving.
    # Use to scrub keys or session tokens embedded in the path.
    # The real outbound request is unaffected.
    #
    #   c.normalize_url = ->(url : String) { url.gsub(/sk-[a-z0-9]+/, "[FILTERED]") }
    property normalize_url : Proc(String, String)? = nil

    # Optional proc applied to the request body before matching and saving.
    # Use to strip non-deterministic fields (timestamps, user IDs, etc.)
    # so transcripts remain stable across runs.
    # The real outbound request body is unaffected.
    #
    #   c.normalize_body = ->(body : String) {
    #     json = JSON.parse(body).as_h
    #     json.delete("user")
    #     json.to_json
    #   }
    property normalize_body : Proc(String, String)? = nil

    # Applies URL normalization if configured, otherwise returns url as-is.
    def apply_url_normalization(url : String) : String
      normalize_url.try(&.call(url)) || url
    end

    # Applies body normalization if configured, otherwise returns body as-is.
    def apply_body_normalization(body : String) : String
      normalize_body.try(&.call(body)) || body
    end
  end
end
