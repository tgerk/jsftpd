/**
 * -load certificate from a well-known location on local disk
 * -generate and store a self-signed cert & store when not found
 *
 * will be called when the FTP server is created without providing
 *  a key/cert/keyFile/certFile
 * will be imported dynamically, so sync or promise filesystem calls are ok (rather than top-level await)
 */

import { execFileSync } from "child_process"
import { existsSync, readFileSync } from "fs"

const crtFile = "server.crt",
  keyFile = "server.key"
if (!existsSync(crtFile) || !existsSync(keyFile)) {
  // one-shot self-signed cert:
  execFileSync(
    "openssl",
    `req -nodes -newkey rsa:2048 -keyout ${keyFile} -subj /CN=dncftpd -x509 -days 1825 -out ${crtFile}`.split(
      " "
    )
  )
}

export const key = readFileSync(keyFile)
export const cert = readFileSync(crtFile)
