import { Transform } from "stream"
import { EOL } from "os"

/*
 * implement ASCII mode in FTP
 * put simply:
 *  on STOR, convert from \r\n in-flight encoding to host-native line-endings at rest
 *  on RETR, convert any on-disk line-ending (\r, \n, or \r\n) to \r\n in-flight
 */

export function asciify(): Transform {
  return new Transform({
    transform(chunk, encoding, next) {
      next(null, chunk.toString().replace(/(\r\n?|\n)/g, "\r\n"))
    },
  })
}

export function deasciify(): Transform {
  return new Transform({
    transform(chunk, encoding, next) {
      next(null, chunk.toString().replace(/\r\n/g, EOL))
    },
  })
}

export function tee(tee: (chunk: Buffer) => void): Transform {
  return new Transform({
    transform(chunk, encoding, next) {
      tee(chunk)
      next(null, chunk)
    },
  })
}
