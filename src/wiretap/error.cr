module Wiretap
  # Raised when a request cannot be matched to a recorded interaction.
  #
  # This occurs in `:none` mode (strict replay) or in `:once` mode when a
  # transcript file exists but does not contain an interaction matching the
  # incoming request's method, URL, and body digest.
  #
  # ```
  # begin
  #   Wiretap.intercept("my_test", mode: :none) do
  #     HTTP::Client.get("https://api.example.com/unknown")
  #   end
  # rescue Wiretap::Error => e
  #   puts e.message  # => "No recorded interaction for GET https://..."
  # end
  # ```
  class Error < Exception
  end
end
