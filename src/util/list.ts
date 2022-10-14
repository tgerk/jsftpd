import { format } from "node:util"

import {
  format_rfc3659_time,
  formatDate_Mmm_DD_HH_mm,
  formatDate_MSDOS,
} from "./time.js"
import type { Stats } from "../store.js"

export function formatListing(cmd = "LIST") {
  switch (cmd) {
    case "NLST":
      return ({ name }: Stats) => name

    case "MLSD":
      return (fstat: Stats) =>
        fstat.isDirectory()
          ? format(
              "type=dir;modify=%s; %s",
              format_rfc3659_time(fstat.mtime),
              fstat.name
            )
          : format(
              "type=file;modify=%s;size=%d; %s",
              format_rfc3659_time(fstat.mtime),
              fstat.size,
              fstat.name
            )

    case "MSDOS":
      // let's make a MS-DOS listing (for Windows 11)
      return (fstat: Stats) =>
        fstat.isDirectory()
          ? format(
              "%s       <DIR>          %s",
              formatDate_MSDOS(fstat.mtime),
              fstat.name
            )
          : format(
              "%s %s %s",
              formatDate_MSDOS(fstat.mtime),
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
              formatDate_Mmm_DD_HH_mm(fstat.mtime),
              fstat.name
            )
          : format(
              "-r--r--r-- 1 ? ? %s %s %s", // #links, uid, gid unimportant
              String(fstat.size).padStart(14, " "),
              formatDate_Mmm_DD_HH_mm(fstat.mtime),
              fstat.name
            )
  }
}
