import { format } from "node:util"

import { format_rfc3659_time, formatDate_Mmm_DD_HH_mm } from "./time.js"
import type { Stats } from "../store.js"

export function formatListing(cmd = "LIST") {
  switch (cmd) {
    case "NLST":
      return ({ name }: Stats) => name
    case "MLSD":
      return (fstat: Stats) =>
        format(
          "type=%s;modify=%s;%s %s",
          fstat.isDirectory() ? "dir" : "file",
          format_rfc3659_time(fstat.mtime),
          fstat.isDirectory() ? "" : "size=" + fstat.size.toString() + ";",
          fstat.name
        )
    case "LIST":
    default:
      return (fstat: Stats) =>
        format(
          "%s 1 ? ? %s %s %s", // showing link-count = 1, don't expose uid, gid
          fstat.isDirectory() ? "dr--r--r--" : "-r--r--r--",
          String(fstat.isDirectory() ? "0" : fstat.size).padStart(14, " "),
          formatDate_Mmm_DD_HH_mm(fstat.mtime),
          fstat.name
        )
  }
}
