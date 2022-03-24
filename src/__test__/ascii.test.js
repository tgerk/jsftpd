/* eslint-disable @typescript-eslint/no-var-requires */
const { streamToAscii, streamFromAscii } = require("../ascii.ts")
const { Readable, Writable } = require("stream")

function getSink() {
  return new Writable({
    write(chunk, encoding, next) {
      chunk = chunk.toString()
      this.result = this.result?.concat(chunk) ?? chunk
      next()
    },
  })
}

test("test conversion *into* NVT-ASCII transport format", (done) => {
  const input = Readable.from("line1\nline2\r\nline3\r"),
    sink = getSink()

  sink.on("close", function () {
    expect(this.result).toBe("line1\r\nline2\r\nline3\r\n")
    done()
  })

  streamToAscii(input).pipe(sink)
})

test("test conversion *from* NVT-ASCII transport format", (done) => {
  const input = Readable.from("line1\nline2\r\nline3\r"),
    sink = getSink()

  sink.on("close", function () {
    expect(this.result).toBe("line1\nline2\nline3\r")
    done()
  })

  streamFromAscii(input).pipe(sink)
})
