module Wiretap
  # :nodoc:
  #
  # Read-only `IO` that passes every byte read from *source* through to the
  # caller and keeps a copy, so a streamed body can be recorded as it is
  # consumed rather than buffered up front.
  class TeeIO < IO
    @copy = IO::Memory.new

    def initialize(@source : IO)
    end

    # The bytes read through this IO so far.
    def captured : String
      @copy.to_s
    end

    def read(slice : Bytes) : Int32
      count = @source.read(slice)
      @copy.write(slice[0, count])
      count
    end

    def write(slice : Bytes) : Nil
      raise IO::Error.new("TeeIO is read-only")
    end
  end
end
