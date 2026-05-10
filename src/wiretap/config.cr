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
  end
end
