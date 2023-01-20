import { format } from "node:util"

import {
  rfc3659_formatTime,
  common_formatTime,
  MSDOS_formatTime,
} from "./time.js"
import type { Stats } from "./store.js"

export function formatListing(cmd = "LIST") {
  switch (cmd) {
    case "NLST":
      return ({ name }: Stats) => name

    case "MLSD":
      return (fstat: Stats) =>
        fstat.isDirectory()
          ? format(
              "type=dir;modify=%s; %s",
              rfc3659_formatTime(fstat.mtime),
              fstat.name
            )
          : format(
              "type=file;modify=%s;size=%d; %s",
              rfc3659_formatTime(fstat.mtime),
              fstat.size,
              fstat.name
            )

    case "MSDOS":
      // let's make a MS-DOS listing (for Windows 11)
      return (fstat: Stats) =>
        fstat.isDirectory()
          ? format(
              "%s       <DIR>          %s",
              MSDOS_formatTime(fstat.mtime),
              fstat.name
            )
          : format(
              "%s %s %s",
              MSDOS_formatTime(fstat.mtime),
              String(fstat.size).padStart(20, " "),
              fstat.name
            )

    case "POSIX":
    case "LIST":
    default:
      return (fstat: Stats) =>
        fstat.isDirectory()
          ? format(
              "dr--r--r-- 1 ? ? %s %s %s", // #links, uid, gid unimportant
              "0".padStart(14, " "),
              common_formatTime(fstat.mtime),
              fstat.name
            )
          : format(
              "-r--r--r-- 1 ? ? %s %s %s", // #links, uid, gid unimportant
              String(fstat.size).padStart(14, " "),
              common_formatTime(fstat.mtime),
              fstat.name
            )
  }
}
