import { Transform, Readable } from "stream"
import { EOL } from "os"

/*
 * implement ASCII mode in FTP
 * put simply:
 *  on STOR, convert from \r\n in-flight encoding to host-native line-endings at rest
 *  on RETR, convert any on-disk line-ending (\r, \n, or \r\n) to \r\n in-flight
 */

export function asciify(stream: Readable): Readable {
  return stream.pipe(
    new Transform({
      transform(chunk, encoding, next) {
        next(null, chunk.toString().replace(/(\r\n?|\n)/g, "\r\n"))
      },
    })
  )
}

export function deasciify(stream: Readable): Readable {
  return stream.pipe(
    new Transform({
      transform(chunk, encoding, next) {
        next(null, chunk.toString().replace(/\r\n/g, EOL))
      },
    })
  )
}
