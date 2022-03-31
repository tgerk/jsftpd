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

if (!existsSync("server.crt") || !existsSync("server.key")) {
  // one-shot self-signed cert:
  execFileSync("openssl", [
    "req",
    "-nodes",
    "-newkey",
    "rsa:2048",
    "-keyout",
    "server.key",
    "-subj",
    "/CN=dncftpd",
    "-x509",
    "-days",
    "1825",
    "-out",
    "server.crt",
  ])
}

export const key = readFileSync("server.key")
export const cert = readFileSync("server.crt")
