module Wiretap
  # :nodoc:
  #
  # Best-effort detection of header values that look like credentials but
  # are not covered by `Config#filter_headers`. Used to warn, not to filter -
  # `filter_headers` remains the only thing that redacts anything.
  #
  # Two independent signals, either of which is enough to flag a header:
  #
  # 1. The value matches a known API key format (OpenAI, Anthropic, Google,
  #    GitHub, AWS, Slack, ...) - high confidence, regardless of header name.
  # 2. The header name suggests a credential (contains "key", "token",
  #    "secret", "auth", ...) AND the value looks random (long, high
  #    Shannon entropy) - moderate confidence, catches providers not on the
  #    known-format list.
  #
  # Name alone or entropy alone both produce too many false positives to be
  # useful (`X-Idempotency-Key`, `X-Request-Id`); requiring both narrows
  # that considerably, though a randomly-generated idempotency key can still
  # trip it - see `Config#ignore_suspected_secrets` for how to silence a
  # specific known-safe header.
  module SecretHeuristic
    # Value formats specific enough to be recognized on their own.
    KNOWN_VALUE_PATTERNS = [
      /^sk-ant-[a-zA-Z0-9\-_]{10,}$/, # Anthropic
      /^sk-[a-zA-Z0-9]{20,}$/,        # OpenAI-style (also used by several other providers)
      /^AIza[0-9A-Za-z\-_]{35}$/,     # Google API key
      /^gh[pousr]_[a-zA-Z0-9]{36,}$/, # GitHub personal/app/oauth/user/refresh tokens
      /^AKIA[0-9A-Z]{16}$/,           # AWS access key ID
      /^xox[baprs]-[a-zA-Z0-9\-]+$/,  # Slack tokens
    ]

    # Substrings in a header name that suggest it may hold a credential.
    # Matched case-insensitively against the whole header name.
    NAME_KEYWORDS = ["key", "token", "secret", "auth", "credential"]

    # Minimum length and Shannon entropy (bits/char) for the name+entropy
    # heuristic. Chosen to pass typical hex/base64 API keys (usually well
    # above 3.5 bits/char at 20+ chars) while giving short or low-variety
    # strings ("Bearer test", "enabled") the benefit of the doubt.
    MIN_VALUE_LENGTH =  16
    MIN_ENTROPY      = 3.0

    # :nodoc:
    def self.suspicious?(name : String, value : String) : Bool
      stripped = strip_scheme(value)
      return true if KNOWN_VALUE_PATTERNS.any?(&.matches?(stripped))

      return false unless name_suggests_credential?(name)
      return false if stripped.size < MIN_VALUE_LENGTH

      shannon_entropy(stripped) >= MIN_ENTROPY
    end

    private def self.name_suggests_credential?(name : String) : Bool
      lname = name.downcase
      NAME_KEYWORDS.any? { |keyword| lname.includes?(keyword) }
    end

    # Strips a leading auth scheme ("Bearer ", "Basic ", "Token ") so the
    # remaining token is what gets pattern-matched and entropy-scored.
    private def self.strip_scheme(value : String) : String
      value.sub(/^(Bearer|Basic|Token)\s+/i, "")
    end

    private def self.shannon_entropy(str : String) : Float64
      return 0.0 if str.empty?

      counts = Hash(Char, Int32).new(0)
      str.each_char { |char| counts[char] += 1 }

      length = str.size.to_f
      counts.values.sum do |count|
        probability = count / length
        -probability * Math.log2(probability)
      end
    end
  end
end
