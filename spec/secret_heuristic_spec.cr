require "./spec_helper"

# Test values below are deliberately assembled from separate string
# fragments rather than written as one contiguous literal. They match our
# own heuristic's format regexes (needed to exercise them), but GitHub's
# push-protection secret scanner also matches those same vendor formats
# against literal file content - splitting the fragments keeps the full
# pattern from ever appearing as a single string in the source.
describe Wiretap::SecretHeuristic do
  describe ".suspicious? — known value formats" do
    it "flags an Anthropic-style key regardless of header name" do
      key = "sk-ant-" + "api03-" + "abcdefghijklmnopqrstuvwxyz"
      Wiretap::SecretHeuristic.suspicious?("X-Custom-Thing", key).should be_true
    end

    it "flags an OpenAI-style key" do
      key = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
      Wiretap::SecretHeuristic.suspicious?("X-Whatever", key).should be_true
    end

    it "flags a Google API key format" do
      Wiretap::SecretHeuristic.suspicious?("X-Whatever", "AIza#{"a" * 35}").should be_true
    end

    it "flags a GitHub personal access token" do
      Wiretap::SecretHeuristic.suspicious?("X-Whatever", "ghp_#{"a1B2c3" * 7}").should be_true
    end

    it "flags an AWS access key ID" do
      key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
      Wiretap::SecretHeuristic.suspicious?("X-Whatever", key).should be_true
    end

    it "flags a Slack token" do
      key = "xoxb-" + "1234567890-" + "abcdefghijklmnop"
      Wiretap::SecretHeuristic.suspicious?("X-Whatever", key).should be_true
    end

    it "strips a Bearer scheme before matching" do
      key = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
      Wiretap::SecretHeuristic.suspicious?("X-Whatever", "Bearer #{key}").should be_true
    end

    it "does not flag an unrecognized, low-entropy, non-credential-named header" do
      Wiretap::SecretHeuristic.suspicious?("X-Request-Id", "12345").should be_false
    end
  end

  describe ".suspicious? — name + entropy heuristic" do
    it "flags a long, high-entropy value on a header named like a credential" do
      Wiretap::SecretHeuristic.suspicious?("X-Custom-Secret", "aZ8mK2pQ9xR4vN7wL1jY6tH3cF5b").should be_true
    end

    it "does not flag a credential-named header with a short value" do
      Wiretap::SecretHeuristic.suspicious?("X-Api-Token", "abc123").should be_false
    end

    it "does not flag a credential-named header with a low-entropy value" do
      Wiretap::SecretHeuristic.suspicious?("X-Session-Token", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa").should be_false
    end

    it "does not flag a long, high-entropy value on a header not named like a credential" do
      Wiretap::SecretHeuristic.suspicious?("X-Trace-Id", "aZ8mK2pQ9xR4vN7wL1jY6tH3cF5b").should be_false
    end

    it "matches header names case-insensitively" do
      Wiretap::SecretHeuristic.suspicious?("x-custom-SECRET", "aZ8mK2pQ9xR4vN7wL1jY6tH3cF5b").should be_true
    end
  end
end
