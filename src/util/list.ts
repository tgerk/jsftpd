import { format } from "node:util"

import { format_rfc3659_time, formatDate_Mmm_DD_HH_mm } from "./time.js"
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
    case "LIST":
    default:
      return (fstat: Stats) =>
        fstat.isDirectory()
          ? format(
              "dr--r--r-- 1 ? ? %s %s %s", // unknown uid, gid
              "0".padStart(14, " "),
              formatDate_Mmm_DD_HH_mm(fstat.mtime),
              fstat.name
            )
          : format(
              "-r--r--r-- 1 ? ? %s %s %s", // unknown uid, gid
              String(fstat.size).padStart(14, " "),
              formatDate_Mmm_DD_HH_mm(fstat.mtime),
              fstat.name
            )
  }
}
