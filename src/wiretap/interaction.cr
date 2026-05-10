module Wiretap
  # The recorded outgoing request.
  class RequestData
    include JSON::Serializable

    property method : String
    property url : String
    property headers : Hash(String, String)
    property body : String?

    def initialize(
      @method : String,
      @url : String,
      @headers : Hash(String, String),
      @body : String? = nil,
    )
    end
  end

  # The recorded incoming response.
  class ResponseData
    include JSON::Serializable

    property status : Int32
    property headers : Hash(String, String)
    property body : String

    def initialize(
      @status : Int32,
      @headers : Hash(String, String),
      @body : String,
    )
    end
  end

  # A matched request/response pair — one entry in a transcript.
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
