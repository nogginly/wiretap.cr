# Wiretap.cr

A Crystal shard for testing by intercepting and replaying http requests with streaming support.

## AI Use

See [DISCLOSURE](DISCLOSURE.md) for how I used AI for this project.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   development_dependencies:
      wiretap:
        github: nogginly/wiretap.cr
   ```

2. Run `shards install`

## Usage

### How Wiretap works

Wiretap sits between your test code and `HTTP::Client`. On the first run it lets requests through to the real server and saves each request/response pair to a **transcript** - a JSON file on disk. On subsequent runs it intercepts matching requests and replays the saved response without touching the network.

**First run - record**

```mermaid
sequenceDiagram
    participant T as Test code
    participant W as Wiretap.intercept
    participant C as HTTP::Client
    participant S as Real server
    participant D as Transcript (disk)

    T->>W: intercept("name") do ... end
    W->>W: no transcript found
    W->>C: exec(request)
    C->>S: real HTTP request
    S-->>C: response
    C-->>W: response
    W->>D: save interaction
    W-->>T: response
```

**Subsequent runs - replay**

```mermaid
sequenceDiagram
    participant T as Test code
    participant W as Wiretap.intercept
    participant C as HTTP::Client
    participant D as Transcript (disk)

    T->>W: intercept("name") do ... end
    W->>W: transcript found
    W->>C: exec(request)
    C->>W: intercepted
    W->>D: find_interaction(method, url, digest)
    D-->>W: recorded response
    W-->>C: replayed response
    C-->>T: response (no network call)
```

Transcripts are stored as human-readable JSON under `spec/transcripts/` and should be committed to version control. Once recorded, your tests run offline, deterministically, and fast.


### Configuration

Place this in `spec/spec_helper.cr`:

```crystal
require "wiretap"

Wiretap.configure do |c|
  c.transcript_dir = "spec/transcripts"  # default
  c.record_mode    = :once               # default
  c.filter_headers << "X-Custom-Key"     # add to the default list
end
```

|Setting         |Default                         |Purpose                                               |
|----------------|--------------------------------|------------------------------------------------------|
|`transcript_dir`|`"spec/transcripts"`            |Where transcript JSON files are stored                |
|`record_mode`   |`:once`                         |Default record mode for all `intercept` blocks        |
|`filter_headers`|`["Authorization", "X-Api-Key"]`|Header values replaced with `[FILTERED]` before saving|
|`normalize_url` |`nil`                           |Proc applied to the URL before matching and saving    |
|`normalize_body`|`nil`                           |Proc applied to the request body before saving        |

Additional headers can be filtered by appending to the array:

```crystal
c.filter_headers << "X-Custom-Key"
```


### Record modes

|Mode     |Behaviour                                                      |
|---------|---------------------------------------------------------------|
|`:once`  |Record if no transcript exists; strict replay if one does.     |
|`:always`|Always re-record, discarding any existing transcript.          |
|`:none`  |Strict replay only. Raise on any request not in the transcript.|

The default is `:once`. Override per block when needed:

```crystal
Wiretap.intercept("my_test", mode: :none) do
  # ...
end
```


### Basic usage

#### GET request

```crystal
it "returns the model list" do
  Wiretap.intercept("list_models") do
    response = HTTP::Client.get(
      "https://api.example.com/v1/models",
      HTTP::Headers{"Authorization" => "Bearer #{ENV["API_KEY"]}"}
    )
    response.status.code.should eq(200)
  end
end
```

The first time this runs, the real request is made and saved to
`spec/transcripts/list_models.json`. Every run after replays it.

#### POST with JSON body

```crystal
it "returns a chat completion" do
  Wiretap.intercept("chat_completion") do
    response = HTTP::Client.post(
      "https://api.example.com/v1/chat/completions",
      headers: HTTP::Headers{
        "Authorization" => "Bearer #{ENV["API_KEY"]}",
        "Content-Type"  => "application/json",
      },
      body: {
        model:    "my-model",
        messages: [{ role: "user", content: "Hello" }],
      }.to_json
    )
    result = JSON.parse(response.body)
    result["choices"][0]["message"]["content"].as_s.should_not be_empty
  end
end
```

Multiple calls to the same endpoint with different bodies can share a
transcript name. Wiretap keys each interaction by a SHA256 digest of the
normalized body, so they coexist without collision.

#### Testing error responses

```crystal
it "raises on a 429 rate limit response" do
  Wiretap.intercept("rate_limit_error") do
    response = HTTP::Client.post("https://api.example.com/v1/chat/completions", ...)
    response.status.code.should eq(429)
  end
end
```

Record this once against a real rate-limited request, or create the
transcript by hand - any valid JSON file in `spec/transcripts/` works.


### Streaming responses (SSE)

LLM APIs that stream tokens use Server-Sent Events over a chunked HTTP
response. Wiretap handles these through the block form of `HTTP::Client#exec`.
On record it buffers the full stream and saves it to the transcript. On replay
it wraps the stored body in `IO::Memory`, satisfying the `body_io` contract so
your parsing code runs identically against live and replayed responses.

```crystal
it "streams a completion" do
  Wiretap.intercept("streaming_chat") do
    client = HTTP::Client.new(URI.parse("https://api.example.com"))
    client.exec(HTTP::Request.new("POST", "/v1/chat/completions",
      headers: HTTP::Headers{
        "Authorization" => "Bearer #{ENV["API_KEY"]}",
        "Content-Type"  => "application/json",
      },
      body: {model: "my-model", stream: true, messages: [{role: "user", content: "Hello"}]}.to_json
    )) do |response|
      response.body_io.each_line do |line|
        next unless line.starts_with?("data: ")
        data = line.lchop("data: ")
        break if data == "[DONE]"
        chunk = JSON.parse(data)
        print chunk["delta"]["content"].as_s
      end
    end
  end
end
```

The transcript stores the full SSE body as a single string - chunk boundaries
are preserved in the content, so `each_line` iteration works identically during
replay.

```mermaid
sequenceDiagram
    participant T as Test code
    participant W as Wiretap
    participant C as HTTP::Client
    participant S as Real server
    participant D as Transcript (disk)

    Note over W,D: First run - record
    T->>W: intercept("name") do ... end
    W->>C: exec(request) { |r| ... }
    C->>S: real HTTP request
    S-->>C: chunked SSE stream
    C-->>W: body_io (buffered)
    W->>D: save full body as string
    W-->>T: replayed IO::Memory

    Note over W,D: Subsequent runs - replay
    T->>W: intercept("name") do ... end
    W->>D: find_interaction(method, url, digest)
    D-->>W: stored body string
    W-->>T: IO::Memory (no network call)
```


### Request normalization

LLM requests often contain volatile fields that change between runs: user IDs,
session tokens embedded in URLs, timestamps in request bodies. These prevent
transcripts from matching reliably across machines and CI runs. Normalization
lets you strip or transform those values before matching and saving, without
affecting the real outbound request.

#### URL normalization

Use this to scrub API keys or session tokens embedded in the URL path or query
string:

```crystal
Wiretap.configure do |c|
  # Redact API keys in the path
  c.normalize_url = ->(url : String) { url.gsub(/sk-[a-z0-9]+/, "[FILTERED]") }

  # Redact tokens in query strings
  c.normalize_url = ->(url : String) { url.gsub(/token=[^&]+/, "token=[FILTERED]") }
end
```

#### Body normalization

Use this to strip non-deterministic fields from JSON request bodies before
they are saved and hashed for matching:

```crystal
Wiretap.configure do |c|
  c.normalize_body = ->(body : String) {
    parsed = JSON.parse(body).as_h
    parsed.delete("user")       # remove volatile user ID
    parsed.delete("request_id") # remove per-call UUID
    parsed.to_json
  }
end
```

The normalization proc receives the raw body string and must return a string.
The real outbound request body is unaffected - only the stored and matched
value is transformed.

```mermaid
flowchart LR
    A[Incoming request] --> B[normalize_url]
    A --> C[normalize_body]
    B --> D[SHA256 digest]
    C --> D
    D --> E[Transcript matching]
    B --> F[Transcript storage]
    C --> F
    A -->|unchanged| G[Real outbound request]
```


### Using with Spectator

Wiretap has no dependency on any test framework. The `intercept` block works
identically inside Spectator examples:

```crystal
describe MyLLMClient do
  it "parses the completion response" do
    Wiretap.intercept("completion") do
      client = MyLLMClient.new
      result = client.complete("Say hello")
      result.should eq("Hello!")
    end
  end
end
```

For suite-wide setup with Spectator, use its `before_suite` hook:

```crystal
Spectator.before_suite do
  Wiretap.configure do |c|
    c.record_mode = :none  # no live calls in CI
  end
end
```


### Transcript files

A transcript is a plain JSON file you can read, edit, and commit:

```json
{
  "name": "chat_completion",
  "recorded_with": "wiretap/0.2.0",
  "interactions": [
    {
      "request": {
        "method": "POST",
        "url": "https://api.example.com/v1/chat/completions",
        "headers": {
          "Authorization": "[FILTERED]",
          "Content-Type": "application/json"
        },
        "body": "{\"model\":\"my-model\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}",
        "body_digest": "a1b2c3d4e5f6..."
      },
      "response": {
        "status": 200,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"Hello!\"}}]}"
      },
      "recorded_at": "2025-05-10T12:00:00Z"
    }
  ]
}
```

To update a transcript, delete the file and run the test once with network
access, or set `mode: :always` for that block temporarily.

### Recommended CI setup

In CI you want strict replay - no live calls, no network dependency:

```crystal
# spec/spec_helper.cr
Wiretap.configure do |c|
  c.record_mode = ENV["CI"]? ? :none : :once
end
```

This uses `:once` locally (recording new transcripts as you write tests)
and `:none` in CI (failing loudly if a transcript is missing, which means
a test was added without a recorded transcript).

## Development

See [DEVELOPMENT](./DEVELOPMENT.md)

## Contributions, by invitation!

*With apologies*, at this time contributions are *by invitation only* and limited to people I know and see often.

These are early days for _Wiretap_ and I am busy with family and work.

At this time I want to work on this at a manageable pace.
