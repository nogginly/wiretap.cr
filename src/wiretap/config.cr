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

    # Header names to exempt from the suspected-secret warning (see
    # `on_suspected_secret`), even though their value looks like it could be
    # a credential.
    #
    # Use this for headers you've verified are safe - a randomly-generated
    # idempotency key or trace ID, for example - rather than silencing the
    # warning globally.
    #
    # ```
    # c.ignore_suspected_secrets << "X-Idempotency-Key"
    # ```
    property ignore_suspected_secrets : Array(String) = [] of String

    # Called when a header that is not in `filter_headers` has a value that
    # looks like it could be a credential (a known API key format, or a
    # long, high-entropy value on a header named like "key", "token",
    # "secret" or "auth"). Receives the header name and its unfiltered
    # value.
    #
    # This is a warning, not a filter - the header is still saved as-is.
    # Defaults to printing a warning to `STDERR`. Two ways to act on it:
    #
    # - If it's a real credential, add the header name to `filter_headers`
    #   so it's redacted (this also stops the warning, since filtered
    #   headers are never checked).
    # - If it's a false positive, add the header name to
    #   `ignore_suspected_secrets` to silence just that header.
    #
    # Override the proc itself to change how the warning is delivered, e.g.
    # to raise instead of printing:
    #
    # ```
    # c.on_suspected_secret = ->(name : String, value : String) {
    #   raise "Unfiltered header '#{name}' looks like a secret" if ENV["CI"]?
    # }
    # ```
    property on_suspected_secret : Proc(String, String, Nil) = ->(name : String, value : String) {
      STDERR.puts(
        "[wiretap] Warning: header '#{name}' looks like it may contain a " \
        "secret but is not in filter_headers, so it will be saved as-is. " \
        "Add it to filter_headers to redact it, or to " \
        "ignore_suspected_secrets to silence this warning."
      )
      nil
    }

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
