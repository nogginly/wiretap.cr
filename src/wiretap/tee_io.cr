module Wiretap
  # :nodoc:
  #
  # Read-only `IO` that passes every byte read from *source* through to the
  # caller and keeps a copy, so a streamed body can be recorded as it is
  # consumed rather than buffered up front.
  class TeeIO < IO
    @copy = IO::Memory.new
    @reached_end = false

    def initialize(@source : IO)
    end

    # The bytes read through this IO so far.
    def captured : String
      @copy.to_s
    end

    # True once a read from *source* has returned end of stream. Never reads
    # ahead to find out, as that could block on a stream that is still open.
    def reached_end? : Bool
      @reached_end
    end

    def read(slice : Bytes) : Int32
      count = @source.read(slice)
      @reached_end = true if count == 0 && !slice.empty?
      @copy.write(slice[0, count])
      count
    end

    def write(slice : Bytes) : Nil
      raise IO::Error.new("TeeIO is read-only")
    end
  end

  # :nodoc:
  #
  # Read-only `IO` over the body of a truncated recording. Serves the
  # recorded bytes, then raises `Wiretap::Error` instead of signalling end of
  # stream, because the real server had not ended it.
  class TruncatedBodyIO < IO
    def initialize(body : String, @request_label : String)
      @memory = IO::Memory.new(body)
    end

    def read(slice : Bytes) : Int32
      count = @memory.read(slice)
      if count == 0 && !slice.empty?
        raise Wiretap::Error.new(
          "Read past the end of a truncated recording for #{@request_label}; " \
          "the recording stopped where the caller stopped reading. Re-record to capture more.")
      end
      count
    end

    def write(slice : Bytes) : Nil
      raise IO::Error.new("TruncatedBodyIO is read-only")
    end
  end
end
