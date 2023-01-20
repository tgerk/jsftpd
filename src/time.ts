export function common_formatTime(mtime: Date): string {
  // unix ls -l shows "Mmm DD hh:mm" if within past 182 days, else "Mmm DD  YYYY"
  // unix ls -lT show "Mmm DD hh:mm:ss YYYY"
  const { year, month, day, hour, minute } = new Intl.DateTimeFormat("en-US", {
    hour12: false,
    timeZone: "America/Los_Angeles",
    timeZoneName: "short",
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "numeric",
  })
    .formatToParts(mtime)
    .filter(({ type }) => type !== "literal")
    .reduce((o, { type, value }) => {
      o[type] = value.toString()
      return o
    }, {} as Record<Intl.DateTimeFormatPartTypes, string>)

  if (mtime > new Date(Date.now() - 182 * 86400000)) {
    return `${month} ${day.padStart(2, " ")} ${hour.padStart(
      2,
      "0"
    )}:${minute.padStart(2, "0")}`
  }
  return `${month} ${day.padStart(2, " ")}  ${year}`
}

export function MSDOS_formatTime(mtime: Date): string {
  const { year, month, day, hour, minute, dayPeriod } = new Intl.DateTimeFormat(
    "en-US",
    {
      hour12: true,
      // dayPeriod: "short",
      timeZone: "UTC",
      timeZoneName: "short",
      year: "numeric",
      month: "numeric",
      day: "numeric",
      hour: "numeric",
      minute: "numeric",
    }
  )
    .formatToParts(mtime)
    .filter(({ type }) => type !== "literal")
    .reduce((o, { type, value }) => {
      o[type] = value.toString()
      return o
    }, {} as Record<Intl.DateTimeFormatPartTypes, string>)

  return `${month.padStart(2, "0")}-${day.padStart(
    2,
    "0"
  )}-${year} ${hour}:${minute}${dayPeriod}`
}

export function rfc3659_formatTime(mtime: Date): string {
  mtime = new Date(mtime)
  const MM = (mtime.getUTCMonth() + 1).toString().padStart(2, "0"),
    DD = mtime.getUTCDate().toString().padStart(2, "0"),
    H = mtime.getUTCHours().toString().padStart(2, "0"),
    M = mtime.getUTCMinutes().toString().padStart(2, "0"),
    S = mtime.getUTCSeconds().toString().padStart(2, "0"),
    s = mtime.getUTCMilliseconds().toString().padStart(3, "0")
  return `${mtime.getUTCFullYear()}${MM}${DD}${H}${M}${S}.${s}`
}

export function rfc3659_parseTime(rfc3659_time: string): Date {
  const Y = rfc3659_time.substring(0, 4),
    M = rfc3659_time.substring(4, 6),
    D = rfc3659_time.substring(6, 8),
    Hrs = rfc3659_time.substring(8, 10),
    Min = rfc3659_time.substring(10, 12),
    Sec = rfc3659_time.substring(12, 14)
  return new Date(`${Y}-${M}-${D}T${Hrs}:${Min}:${Sec}+00:00`)
}
