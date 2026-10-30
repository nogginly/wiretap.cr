module Wiretap
  # :nodoc:
  class RequestData
    include JSON::Serializable

    property method : String
    property url : String
    property headers : Hash(String, String)
    property body : String?
    property body_digest : String?

    def initialize(
      @method : String,
      @url : String,
      @headers : Hash(String, String),
      @body : String? = nil,
      @body_digest : String? = nil,
    )
    end
  end

  # :nodoc:
  class ResponseData
    include JSON::Serializable

    property status : Int32
    property headers : Hash(String, String)
    property body : String

    # True when the caller stopped reading a streamed body before the server
    # ended it, so *body* holds only part of the stream. Omitted from JSON
    # when false; transcripts without it are read as complete.
    @[JSON::Field(emit_null: false)]
    property truncated : Bool?

    def initialize(
      @status : Int32,
      @headers : Hash(String, String),
      @body : String,
      truncated : Bool = false,
    )
      @truncated = truncated || nil
    end

    def truncated? : Bool
      @truncated == true
    end
  end

  # :nodoc:
  class Interaction
    include JSON::Serializable

    property request : RequestData
    property response : ResponseData
    property recorded_at : String

    def initialize(
      @request : RequestData,
      @response : ResponseData,
      @recorded_at : String = Time.utc.to_rfc3339,
    )
    end
  end
end
