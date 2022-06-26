import { Readable, Writable } from "stream"

import { asciify, deasciify } from "../util/ascii"

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

  input.pipe(asciify()).pipe(sink)
})

test("test conversion *from* NVT-ASCII transport format", (done) => {
  const input = Readable.from("line1\nline2\r\nline3\r"),
    sink = getSink()

  sink.on("close", function () {
    expect(this.result).toBe("line1\nline2\nline3\r")
    done()
  })

  input.pipe(deasciify()).pipe(sink)
})
