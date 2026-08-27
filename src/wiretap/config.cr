module Wiretap
  # Holds all runtime configuration for Wiretap.
  #
  # Do not instantiate this class directly. Access it through
  # `Wiretap.configure` to mutate settings, or `Wiretap.reset_config` to
  # restore defaults.
  #
  # ```
  # Wiretap.configure do |c|
  #   c.transcript_dir = "spec/fixtures/transcripts"
  #   c.record_mode = :none
  #   c.filter_headers << "X-Session-Token"
  #   c.normalize_url = ->(url : String) { url.gsub(/sk-[a-z0-9]+/, "[FILTERED]") }
  # end
  # ```
  class Config
    # Directory where transcript JSON files are stored.
    #
    # Defaults to `"spec/transcripts"`. The directory and any intermediate
    # parents are created automatically on first save.
    property transcript_dir : String = "spec/transcripts"

    # Default record mode applied to all `Wiretap.intercept` calls.
    #
    # | Mode | Behaviour |
    # |---|---|
    # | `:once` | Record if no transcript exists; strict replay if one does. |
    # | `:always` | Always re-record, discarding any existing transcript. |
    # | `:none` | Strict replay only. Raise `Error` on any unmatched request. |
    #
    # Defaults to `:once`. Override per block via the `mode:` keyword on
    # `Wiretap.intercept`.
    property record_mode : Symbol = :once

    # Header names whose values are replaced with `"[FILTERED]"` before the
    # interaction is saved to disk.
    #
    # Matching is case-insensitive. Defaults to `["Authorization", "X-Api-Key",
    # "X-Goog-Api-Key", "Api-Key"]` - covering the common `Authorization:
    # Bearer` pattern plus the non-standard auth headers used by Anthropic /
    # most LLM APIs (`X-Api-Key`), Google Gemini (`X-Goog-Api-Key`), and Azure
    # OpenAI (`Api-Key`). Append additional names as needed:
    #
    # ```
    # c.filter_headers << "X-Session-Token"
    # ```
    #
    # To replace the list entirely use `filter_headers.replace(...)`, though
    # this discards the defaults and should be done deliberately.
    getter filter_headers : Array(String) = ["Authorization", "X-Api-Key", "X-Goog-Api-Key", "Api-Key"]

    # Optional proc applied to the request URL before matching and saving.
    #
    # Use this to scrub API keys or session tokens embedded in the URL path
    # or query string. The real outbound request is unaffected.
    #
    # ```
    # c.normalize_url = ->(url : String) { url.gsub(/sk-[a-z0-9]+/, "[FILTERED]") }
    # ```
    property normalize_url : Proc(String, String)? = nil

    # Optional proc applied to the request body before it is hashed for
    # matching.
    #
    # Use this to strip non-deterministic fields (timestamps, user IDs, UUIDs)
    # so requests still match across machines and CI runs despite those
    # fields changing on every call. This affects matching only: the real
    # outbound request body is unaffected, and the body saved to the
    # transcript is the raw, un-normalized body actually sent. If you need to
    # redact sensitive fields from the saved transcript itself, that is a
    # separate concern from matching (see `filter_headers` for the header
    # equivalent).
    #
    # ```
    # c.normalize_body = ->(body : String) {
    #   parsed = JSON.parse(body).as_h
    #   parsed.delete("user")
    #   parsed.to_json
    # }
    # ```
    property normalize_body : Proc(String, String)? = nil

    # :nodoc:
    def apply_url_normalization(url : String) : String
      normalize_url.try(&.call(url)) || url
    end

    # :nodoc:
    def apply_body_normalization(body : String) : String
      normalize_body.try(&.call(body)) || body
    end
  end
end
