export function formatDate_Mmm_DD_HH_mm(mtime: Date): string {
  mtime = new Date(mtime)
  return mtime.toLocaleString([], {
    month: "short",
    day: "numeric",
    hour12: false,
    hour: "numeric",
    minute: "2-digit",
  })
}

export function format_rfc3659_time(mtime: Date): string {
  mtime = new Date(mtime)
  const MM = (mtime.getMonth() + 1).toString().padStart(2, "0"),
    DD = mtime.getDate().toString().padStart(2, "0"),
    H = mtime.getHours().toString().padStart(2, "0"),
    M = mtime.getMinutes().toString().padStart(2, "0"),
    S = mtime.getSeconds().toString().padStart(2, "0"),
    s = mtime.getMilliseconds().toString().padStart(3, "0")
  return `${mtime.getFullYear()}${MM}${DD}${H}${M}${S}.${s}`
}

export function parse_rfc3659_time(rfc3659_time: string): Date {
  const Y = rfc3659_time.substring(0, 4),
    M = rfc3659_time.substring(4, 6),
    D = rfc3659_time.substring(6, 8),
    Hrs = rfc3659_time.substring(8, 10),
    Min = rfc3659_time.substring(10, 12),
    Sec = rfc3659_time.substring(12, 14)
  return new Date(`${Y}-${M}-${D}T${Hrs}:${Min}:${Sec}+00:00`)
}
