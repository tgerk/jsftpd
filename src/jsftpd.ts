/*
 * @package jsftpd
 * @author Sven <mailsvb@gmail.com>
 * @author Tim Gerk <tjgerk@gmail.com>
 * @license https://github.com/mailsvb/jsftpd/blob/main/LICENSE MIT License
 */

import net, { Socket, AddressInfo, createServer } from "net"
import tls, {
  TlsOptions,
  TLSSocket,
  createServer as createSecureServer,
  createSecureContext,
} from "tls"
import util from "util"
import path from "path"
import fs from "fs"
import { EventEmitter } from "events"

import Deferred from "./deferred"
import localFsBackend from "./backends/local"
import configAuthBackend from "./backends/auth"

export enum LoginType {
  None,
  Anonymous,
  Password,
  NoPassword,
}

export type anonPermissions =
  | "allowAnonymousFileCreate"
  | "allowAnonymousFileRetrieve"
  | "allowAnonymousFileOverwrite"
  | "allowAnonymousFileDelete"
  | "allowAnonymousFileRename"
  | "allowAnonymousFolderDelete"
  | "allowAnonymousFolderCreate"

export type AnonymousPermissions = {
  [key in anonPermissions]?: boolean
}

export type userPermissions =
  | "allowUserFolderCreate"
  | "allowUserFolderDelete"
  | "allowUserFileCreate"
  | "allowUserFileRetrieve"
  | "allowUserFileOverwrite"
  | "allowUserFileRename"
  | "allowUserFileDelete"

export type UserPermissions = {
  [key in userPermissions]?: boolean
}

export type FilenameTransformer = {
  in: (file: string) => string
  out: (file: string) => string
}

export type UserCredential = {
  password?: string
  basefolder?: string
  allowLoginWithoutPassword?: boolean
  filenameTransform?: FilenameTransformer
} & UserPermissions

export interface AuthHandlers {
  userLoginType(username: string): [LoginType, UserCredential?]
  userAuthenticate(
    username: string,
    password: string
  ): [LoginType, UserCredential?]
}

export type FolderListFormat = "NLST" | "MLSD" | "LIST"
export interface BackendHandlers {
  resolveFolder(folder: string): Promise<string>
  resolveFile(file: string): Promise<string>

  setFolder(folder: string): Promise<string>
  getFolder(): string

  folderExists: (folder: string) => Promise<boolean>
  folderCreate: (folder: string) => Promise<void>
  folderDelete: (folder: string) => Promise<void>
  folderList: (format: FolderListFormat, folder?: string) => Promise<string[]>

  fileExists: (file: string) => Promise<boolean>
  fileSize: (file: string) => Promise<number>
  fileDelete: (file: string) => Promise<void>
  fileRetrieve: (file: string, restOffset: number) => Promise<fs.ReadStream>
  fileStore: (
    file: string,
    restOffset: number,
    encoding: string
  ) => Promise<fs.WriteStream>
  fileRename: (fromFile: string, toFile: string) => Promise<void>
  fileSetTimes: (file: string, mtime: number) => Promise<void>
}

export type AuthOptions = {
  allowAnonymousLogin?: boolean
  username?: string
  user?: ({ username: string } & UserCredential)[] // seems goofy to iterate an array when could map {[username]: credential}
} & AnonymousPermissions &
  UserCredential

export type ConfigOptions = {
  port?: number
  securePort?: number
  maxConnections?: number
  minDataPort?: number
} & AuthOptions

const defaultCert = Buffer.from(
  "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdHpOM1dKdHE5MjAzYWQ0eFRxb2hHM3hLUVdvUnJFejArd3JTUnNhZitMQTQzSWQ4CjRWUUU0elpsaEhSRVJzSGJjQkdGd0dNTEwxaGJXTWc3eDErSFhKYXlxNXJwcldTZ1g4TVRwZllkN2RUNkxRT3oKdmdBTUx3WUJwM3VkYm5IM2tyUERQazBibWRDcTZ4RmxqaUR4bHB6dWxIN1Vqb2crRE1XYmdpVHFYU2YrUThZTwpXS2xVRXhMVzZ5L3hFNUNIVVN3ZGI3MWREc2pDSG90YWliTTNXdlpGdEc3MnAvUXBaWldtZmQreEQwL3VoVnhNCnBualR0S21xWlMwcnJZM3Y1SFR5dVpBMUJRMFBVWmV0NzdLdWZKUis2aVlzQjQ4Z3NSM0szNmd6WHoyMzRXUXUKbEppcWk0dXo4Wjk1LzQyZmJOUlR3eWxRZXBQY1Ruc0Rib0Y0Q1FJREFRQUJBb0lCQVFDanR1UmlWSkVraDM5TApwbm9kdUQ5WjFwcHRGcUt3ZlIwMzhwV3pGZkVEUmtlcUc1SG5zek9pOEl1TDhITExZSlgrOGttNmdVZ1BpVUFvCmVOZWk5YVY3Z2xnc3JvVkFwSG9FMmNtSE9BZks3OWFadjRNeXVjd3BnWTZjNHdUdkcvMklKZ2pHZGhYQ1FRMWMKZi9Gbkw5MTFJTXk3K3hOc1JDaGZOWUFncjJpWTBZOUpRQndncTlJM1BWZ1RGQUtkTTBKZ1hySzhXVCtsN3NDRQpWc0kyUkVnYUxzeUxud2VmYnRwbVV0ankrbWtLemIzcnNyY1JVVmJOZjB3aEFlTG9HS01wZjVPNVUzMVNjd2xwClB2RnpHWkUyM01HbHpheGpZVVJTVmV3TFlzR2dwNTg5SDF6WmZaQVhSRWRiOEx2MGYra0I5MSthUi9Hdy9IT3gKS3ZlVXEvTVpBb0dCQU9BQkhxWWdXNmFwM3BjMjZJNVdNNURrMnJ1TnArRENQbzJUV3RRTklwTlREMEorRWt6SgpMZ1ZEK0xGVWZmNDFTQlZEbWZXR2x3cnVtajdWWGtTbjZyWmZXQUVKYTBySkljdHV3TDcxQ1Y0Q280cnFsUGlpCnhEazdhUFpYSXJBcjdaOG5UOG1kVStmcENMS1FNVUhYY0wydDI0cE85NytFVGVycVVYcGtEQXVEQW9HQkFORmUKVitZYThuVGxjVVhkbktqQVU4czJNSlhUUFZkeDlIM3BzQjNOVjJtR2lmM1h2d2F6ei9mYTg5NG5Ha3FxS2N6cwppV1BLdlR0MytVdUwxSlhWSlcwMllycHpUMlpMd2lqY3pCQlc1OGtIeU9UUGZ4UENjemh1dGlQUHJoMnQwbGJtCkR6WFpuTzJPUlpJWlp3MFllVFlNVzFUcnZ3WnRpT0VxMFp4cVVkeURBb0dBYld0K21pMmlOMll3NmZLVFpMdnMKMG5GSCsyZTF3bzkvMk01TEJ0d25zSWxaSWVUTmNaNndFVGhqcWRPWSsrencraG9jZ1pldC9sUVJHbkpGYXdvUApGK2k0NTBDL25UZGtmNmZwRlI1QzVoNHAzdmk1cmo1cjFYMFV4NGhHMUlHUXdEYUd2ZmhRL1M2UzVnNlRVUk00CjZoNmI2QktzNkd0cldEMy9jT2FnRDVzQ2dZQXpwNHdXS0dYVE0xeHIrVTRTVUVrY0pNVjk0WDBMMndDUUpCeWcKYmEzNFNnbzNoNGdJdGtwRUExQVJhaUpSYzRRV20vRVZuc3BySnFGcDR4alMwcUNHUGxuRFdIbXBhbDEveVdITApValdqWW5sTkFtaCt6b1d3MFplOFpCdTRGTStGUXdOVHJObkx2a01wMVh5WVBZYUNNREJFVmxsdDA0NW14ektwCjNZMU8wd0tCZ0FHaVkyNVZLOGJyMVFydXlzM3Vhb21LQ3BYUmhjZU15eHdBazdxeUlpNnpHeEx3bnFaVldaQmQKbkcxbkFaT2JET1JSTGRBRktPZ2tncGtVbGgrTEE3dTRuUytGWEdteGtLZlF1cTNTcTNaWHhiTjMxcXBCcERHTQoxbE9QSlVWY2UxV3ZyeXcrWVI4M1VFQ0ZTOEZjeDdibEVEM3oyNnVOQnN0dlBwVTUrV3ZxCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDNGpDQ0FjcWdBd0lCQWdJSWJqQ2hhajZDT2Iwd0RRWUpLb1pJaHZjTkFRRUxCUUF3RVRFUE1BMEdBMVVFCkF4TUdhbk5tZEhCa01DQVhEVEl3TURFd01UQXdNREF3TUZvWUR6azVPVGt4TWpNeE1qTTFPVFU1V2pBUk1ROHcKRFFZRFZRUURFd1pxYzJaMGNHUXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDMwpNM2RZbTJyM2JUZHAzakZPcWlFYmZFcEJhaEdzVFBUN0N0Skd4cC80c0RqY2gzemhWQVRqTm1XRWRFUkd3ZHR3CkVZWEFZd3N2V0Z0WXlEdkhYNGRjbHJLcm11bXRaS0Jmd3hPbDloM3QxUG90QTdPK0FBd3ZCZ0duZTUxdWNmZVMKczhNK1RSdVowS3JyRVdXT0lQR1duTzZVZnRTT2lENE14WnVDSk9wZEovNUR4ZzVZcVZRVEV0YnJML0VUa0lkUgpMQjF2dlYwT3lNSWVpMXFKc3pkYTlrVzBidmFuOUNsbGxhWjkzN0VQVCs2RlhFeW1lTk8wcWFwbExTdXRqZS9rCmRQSzVrRFVGRFE5Umw2M3ZzcTU4bEg3cUppd0hqeUN4SGNyZnFETmZQYmZoWkM2VW1LcUxpN1B4bjNuL2paOXMKMUZQREtWQjZrOXhPZXdOdWdYZ0pBZ01CQUFHalBEQTZNQXdHQTFVZEV3RUIvd1FDTUFBd0hRWURWUjBPQkJZRQpGQkRRdzE4NC91Qk5zMHlxczVqaU92dnd4TFBTTUFzR0ExVWREd1FFQXdJRjREQU5CZ2txaGtpRzl3MEJBUXNGCkFBT0NBUUVBaWdSa0draEMxeTVMendOQ0N1T0I5eUsyS2NkUGJhcm9lZGlSWVVxZmpVU2JsT3NweWFTNjEvQjgKVk9UdHZSRjBxZkJFZTVxZVhVUTRIV1JGSnRVZmQ1eisvZTRZNkJHVmR3eFJ5aktIYkVGQ3NpOFlFZDNHOTdaZwpWM1RFV08xVVlCTlJhN2tZajE2QXFDOWtXaG5WRVU3bUdRWE5nR1NJaDNNTmx5RG1RblBIdHdzS2d3cUs5VWcvCk9QVUhUNGlTa2h2OEVoTjYyUFlRaHBEaU1udWFQbUZ1bGVKbmllQnNFMTlvSVBtbWsxblRIZXRPZDg4VU1PeUEKWDFKY0ZBZXI2dmVPQkxVMUhRSEdtd1Iyalgzai83YzI3SjJFdjRQWW1rU2R2N0FYcm5LaENDeGRSblA2WDlGaApTYlEwRHBhbW5zaWFEWld4QzNuUks2LzVndXdlOHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
  "base64"
)
const TlsDefaults: TlsOptions = {
  key: defaultCert,
  cert: defaultCert,
  honorCipherOrder: true,
  rejectUnauthorized: false,
}

const defaultBaseFolder = path.join(process.cwd(), "__ftproot__")
const ConfigDefaults: ConfigOptions = {
  port: 21,
  securePort: 990,
  maxConnections: 10,
  minDataPort: 1024,
  basefolder: defaultBaseFolder,
}

export function createFtpServer({
  tls: tlsConfig,
  auth: authBackend,
  store: storeBackend,
  ...options
}: ConfigOptions & {
  tls?: TlsOptions
  auth?: (options: AuthOptions) => AuthHandlers
  store?: (options: UserCredential & { username: string }) => BackendHandlers
} = {}): EventEmitter & { start(): void; stop(): void; cleanup(): void } {
  let lastSessionKey = 0
  const openSessions: Map<number, Socket> = new Map()

  const config = {
      ...ConfigDefaults,
      ...options,
      tls: {
        ...TlsDefaults,
        ...tlsConfig,
      },
    },
    usingTLS = !!tlsConfig

  // the following methods may be overridden by dependency injection, not externalized due to close dependence on config options
  const { userLoginType, userAuthenticate }: AuthHandlers = Object.assign(
    configAuthBackend(config),
    authBackend?.(config)
  )

  // checks
  if (!storeBackend && !fs.existsSync(config.basefolder)) {
    if (config.basefolder === defaultBaseFolder) {
      fs.mkdirSync(defaultBaseFolder)
    } else {
      throw new Error("Basefolder must exist")
    }
  }

  // setup FTP on TCP
  const tcpServer = createServer()
  tcpServer.on("error", ServerErrorHandler)
  tcpServer.on("listening", () => {
    ListenHandler("tcp", tcpServer.address())
  })
  tcpServer.on("connection", SessionHandler)
  tcpServer.maxConnections = config.maxConnections

  // setup FTP on TLS
  let tlsServer: tls.Server
  if (usingTLS) {
    tlsServer = createSecureServer(config.tls)
    tlsServer.on("error", ServerErrorHandler)
    tlsServer.on("listening", function () {
      ListenHandler("tls", tlsServer.address())
    })
    tlsServer.on("secureConnection", SessionHandler)
    tlsServer.maxConnections = config.maxConnections
  }

  const emitter = new EventEmitter()
  return Object.assign(emitter, {
    start() {
      tcpServer.listen(config.port)
      usingTLS && tlsServer.listen(config.securePort)
    },

    stop() {
      for (const [key, session] of openSessions.entries()) {
        session.destroy()
        openSessions.delete(key)
      }
      tcpServer.close()
      usingTLS && tlsServer.close()
    },

    cleanup() {
      if (!storeBackend && config.basefolder === defaultBaseFolder) {
        fs.rmSync(defaultBaseFolder, { force: true, recursive: true })
      }
    },
  })

  function SessionHandler(cmdSocket: Socket | TLSSocket) {
    const socketKey = ++lastSessionKey
    openSessions.set(socketKey, cmdSocket)

    let username = "nobody"
    let authenticated = false
    let allowUserFileCreate: boolean,
      allowUserFileRetrieve: boolean,
      allowUserFileOverwrite: boolean,
      allowUserFileDelete: boolean,
      allowUserFileRename: boolean,
      allowUserFolderDelete: boolean,
      allowUserFolderCreate: boolean

    let resolveFolder: BackendHandlers["resolveFolder"],
      resolveFile: BackendHandlers["resolveFile"],
      setFolder: BackendHandlers["setFolder"],
      getFolder: BackendHandlers["getFolder"],
      folderExists: BackendHandlers["folderExists"],
      folderDelete: BackendHandlers["folderDelete"],
      folderCreate: BackendHandlers["folderCreate"],
      folderList: BackendHandlers["folderList"],
      fileExists: BackendHandlers["fileExists"],
      fileSize: BackendHandlers["fileSize"],
      fileDelete: BackendHandlers["fileDelete"],
      fileRetrieve: BackendHandlers["fileRetrieve"],
      fileStore: BackendHandlers["fileStore"],
      fileRename: BackendHandlers["fileRename"],
      fileSetTimes: BackendHandlers["fileSetTimes"]

    let isEncrypted = "encrypted" in cmdSocket
    let pbszReceived = false
    let shouldProtect = false

    let asciiOn = false
    let renameFileFrom = ""
    let dataOffset = 0

    let dataAddr: string
    let dataPort: number
    let passivePort: net.Server
    let pasvSocket = new Deferred<Socket | TLSSocket>()

    cmdSocket.on("error", SessionErrorHandler)
    cmdSocket.on("data", CmdHandler)
    cmdSocket.on("close", () => {
      openSessions.delete(socketKey)
      DebugHandler(`${remoteInfo} FTP connection closed`)
      if (passivePort) {
        passivePort.close()
      }
    })

    const localAddr =
      cmdSocket.localAddress?.replace(/::ffff:/g, "") ?? "unknown"
    const remoteAddr =
      cmdSocket.remoteAddress?.replace(/::ffff:/g, "") ?? "unknown"
    const remoteInfo = `[(${socketKey}) ${remoteAddr}:${cmdSocket.remotePort}]`
    DebugHandler(`${remoteInfo} new FTP connection established`)

    function respond(
      this: Socket & {
        respond: (code: string, message: string, delimiter?: string) => void
      },
      code: string,
      message: string,
      delimiter = " "
    ) {
      LogHandler(`${remoteInfo} <<< ${code} ${message}`)
      this.writable &&
        this.write(Buffer.from(`${code}${delimiter}${message}\r\n`))
    }
    let client = Object.assign(cmdSocket, { respond })
    client.respond("220", "Welcome")

    function CmdHandler(data: string) {
      interface FTPCommandTable {
        [fn: string]: (cmd: string, arg: string) => void
      }
      const preAuthMethods: FTPCommandTable = { USER, PASS, AUTH }
      const authenticatedMethods: FTPCommandTable = {
        QUIT,
        PWD,
        CLNT,
        PBSZ,
        OPTS,
        PROT,
        FEAT,
        CWD,
        SIZE,
        DELE,
        RMD,
        RMDA: RMD,
        MKD,
        LIST,
        MLSD: LIST,
        NLST: LIST,
        PORT,
        PASV,
        EPRT,
        EPSV,
        RETR,
        REST,
        STOR,
        SYST,
        TYPE,
        RNFR,
        RNTO,
        MFMT,
        MDTM: MFMT,
      }

      try {
        data = data.toString()
        const [cmd, ...args] = data.trim().split(/\s+/),
          arg = args.join(" ")
        LogHandler(
          `${remoteInfo} >>> cmd[${cmd}] arg[${cmd === "PASS" ? "***" : arg}]`
        )
        if (authenticated) {
          if (cmd in authenticatedMethods) {
            authenticatedMethods[cmd as keyof FTPCommandTable](cmd, arg)
          } else {
            client.respond("500", "Command not implemented")
          }
        } else if (cmd in preAuthMethods) {
          preAuthMethods[cmd as keyof FTPCommandTable](cmd, arg)
        } else {
          client.respond("530", "Not logged in")
          cmdSocket.end()
        }
      } catch (err) {
        DebugHandler(err)
        client.respond("550", "Unexpected server error")
        cmdSocket.end()
      }

      /*
       *  USER
       */
      function USER(cmd: string, user: string) {
        username = user
        authenticated = false
        const [loginType, userCredential] = userLoginType(username)
        switch (loginType) {
          case LoginType.NoPassword:
            DebugHandler(`${remoteInfo} username[${username}] no password`)
            setUserRights(userCredential).then(() => {
              LoginHandler()
              client.respond("232", "User logged in")
            })
            break
          case LoginType.None:
            client.respond("530", "Not logged in")
            break
          default:
            client.respond("331", `Password required for ${username}`)
        }
      }

      /*
       *  PASS
       */
      function PASS(cmd: string, password: string) {
        const [loginType, userCredential] = userAuthenticate(username, password)
        switch (loginType) {
          case LoginType.Anonymous:
            username = `anon(${password})`
          case LoginType.NoPassword: // eslint-disable-line no-fallthrough
          case LoginType.Password:
            DebugHandler(`${remoteInfo} username[${username}] authenticated`)
            setUserRights(userCredential).then(() => {
              LoginHandler()
              client.respond("230", "Logged on")
            })
            break
          default:
            client.respond("530", "Username or password incorrect")
            cmdSocket.end()
        }
      }

      /*
       *  AUTH (switch protocol)
       */
      function AUTH(cmd: string, auth: string) {
        if (auth === "TLS" || auth === "SSL") {
          client.respond("234", `Using authentication type ${auth}`)
          cmdSocket = new TLSSocket(cmdSocket, {
            secureContext: createSecureContext(config.tls),
            isServer: true,
          })
          cmdSocket.on("secure", () => {
            DebugHandler(`${remoteInfo} secure connection established`)
            client = Object.assign(cmdSocket, { respond })
            isEncrypted = "encrypted" in cmdSocket
          })
          cmdSocket.on("data", CmdHandler)
        } else {
          client.respond("504", `Unsupported auth type ${auth}`)
        }
      }

      /*
       *  QUIT
       */
      function QUIT() {
        client.respond("221", "Goodbye")
        cmdSocket.end()
        authenticated && LogoffHandler()
      }

      /*
       *  CLNT
       */
      function CLNT() {
        client.respond("200", "Don't care")
      }

      /*
       *  PBSZ
       */
      function PBSZ(cmd: string, size: string) {
        pbszReceived = true
        client.respond("200", `PBSZ=${size}`)
      }

      /*
       *  OPTS
       */
      function OPTS(cmd: string, opt: string) {
        opt = opt.toLowerCase()
        if (opt === "utf8 on") {
          client.respond("200", "UTF8 ON")
        } else if (opt === "utf8 off") {
          client.respond("200", "UTF8 OFF")
        } else {
          client.respond("451", "Not supported")
        }
      }

      /*
       *  PROT
       */
      function PROT(cmd: string, protection: string) {
        if (pbszReceived === true) {
          if (protection === "C" || protection === "P") {
            shouldProtect = protection === "P"
            client.respond("200", `Protection level is ${protection}`)
          } else {
            client.respond("534", "Protection level must be C or P")
          }
        } else {
          client.respond("503", "PBSZ missing")
        }
      }

      /*
       *  FEAT
       */
      function FEAT() {
        const features = Object.keys(preAuthMethods)
          .concat(Object.keys(authenticatedMethods))
          .join("\r\n ")
          .replace("AUTH", "AUTH TLS\r\n AUTH SSL")
        client.respond("211", `Features:\r\n ${features}\r\n211 End`, "-")
      }

      /*
       *  PORT
       */
      function PORT(cmd: string, arg: string) {
        passivePort = undefined
        const spec = arg.split(",")
        if (spec.length === 6) {
          dataAddr = spec[0] + "." + spec[1] + "." + spec[2] + "." + spec[3]
          dataPort = parseInt(spec[4], 10) * 256 + parseInt(spec[5])
          client.respond("200", "Port command successful")
        } else {
          dataAddr = dataPort = undefined
          client.respond("501", "Port command failed")
        }
      }

      /*
       *  PASV
       */
      function PASV() {
        dataAddr = dataPort = undefined
        initPasvSocket().then(
          (port) => {
            DebugHandler(
              `${remoteInfo} listening on ${port} for data connection`
            )
            client.respond(
              "227",
              util.format(
                "Entering passive mode (%s,%d,%d)",
                localAddr.split(".").join(","),
                (port / 256) | 0,
                port % 256
              )
            )
          },
          (error) => {
            DebugHandler(error)
            passivePort = undefined
            client.respond("501", "Passive command failed")
          }
        )
      }

      /*
       *  EPRT
       */
      function EPRT(cmd: string, arg: string) {
        passivePort = undefined
        const spec = arg.split("|")
        if (spec.length === 5) {
          dataAddr = spec[2]
          dataPort = parseInt(spec[3], 10)
          client.respond("200", "Extended Port command successful")
        } else {
          dataAddr = dataPort = undefined
          client.respond("501", "Extended port command failed")
        }
      }

      /*
       *  EPSV
       */
      function EPSV() {
        dataAddr = dataPort = undefined
        initPasvSocket().then(
          (port) => {
            DebugHandler(
              `${remoteInfo} listening on ${port} for data connection`
            )
            client.respond(
              "229",
              util.format("Entering extended passive mode (|||%d|)", port)
            )
          },
          (error) => {
            DebugHandler(error)
            passivePort = undefined
            client.respond("501", "Extended passive command failed")
          }
        )
      }

      /*
       *  SYST
       */
      function SYST() {
        client.respond("215", "UNIX")
      }

      /*
       *  TYPE
       */
      function TYPE(cmd: string, tfrType: string) {
        if (tfrType === "A") {
          asciiOn = true
          client.respond("200", "Type set to ASCII")
        } else {
          asciiOn = false
          client.respond("200", "Type set to BINARY")
        }
      }

      /*
       *  REST
       */
      function REST(cmd: string, arg: string) {
        const offset = parseInt(arg, 10)
        if (offset > -1) {
          dataOffset = offset
          client.respond("350", `Restarting at ${dataOffset}`)
        } else {
          dataOffset = 0
          client.respond("550", "Wrong restart offset")
        }
      }

      /*
       *  PWD
       */
      function PWD() {
        client.respond("257", `"${getFolder()}" is current directory`)
      }

      /*
       *  CWD
       */
      function CWD(cmd: string, folder: string) {
        resolveFolder(folder).then(
          (folder) =>
            folderExists(folder).then((isFolder) => {
              if (isFolder) {
                setFolder(folder).then(
                  (folder) =>
                    client.respond(
                      "250",
                      `CWD successful. "${folder}" is current directory`
                    ),
                  (error) => {
                    DebugHandler(error)
                    client.respond("530", "CWD not successful")
                  }
                )
              } else {
                client.respond("550", "Folder not found")
              }
            }),
          (error) => {
            DebugHandler(error)
            client.respond("550", `Command failed "${folder}`)
          }
        )
      }

      /*
       *  RMD
       *  RMDA
       */
      function RMD(cmd: string, folder: string) {
        resolveFolder(folder).then(
          (folder) => {
            if (!allowUserFolderDelete || folder === "/") {
              client.respond("550", "Permission denied")
            } else {
              folderExists(folder).then((isFolder) => {
                if (isFolder) {
                  folderDelete(folder).then(
                    () => {
                      client.respond("250", "Folder deleted successfully")
                    },
                    (error) => {
                      DebugHandler(error)
                      client.respond("501", "Command failed")
                    }
                  )
                } else {
                  client.respond("550", "Folder not found")
                }
              })
            }
          },
          (error) => {
            DebugHandler(error)
            client.respond("550", `Command failed "${folder}`)
          }
        )
      }

      /*
       *  MKD
       */
      function MKD(cmd: string, folder: string) {
        if (!allowUserFolderCreate) {
          client.respond("550", "Permission denied")
        } else {
          resolveFolder(folder).then(
            (folder) =>
              folderExists(folder).then((isFolder) => {
                if (isFolder) {
                  client.respond("550", "Folder exists")
                } else {
                  folderCreate(folder).then(
                    () => {
                      client.respond("250", "Folder created successfully")
                    },
                    (error) => {
                      DebugHandler(error)
                      client.respond("501", "Command failed")
                    }
                  )
                }
              }),
            (error) => {
              DebugHandler(error)
              client.respond("550", `Command failed "${folder}`)
            }
          )
        }
      }

      /*
       *  LIST
       *  MLSD
       *  NLST
       */
      function LIST(cmd: FolderListFormat, folder: string) {
        openDataSocket()
          .then((socket) => {
            folderList(cmd, folder)
              .then((listing) => listing.join("\r\n"))
              .then((listing) => {
                DebugHandler(
                  `${remoteInfo} LIST response on data channel\r\n${listing}`
                )
                socket.end(Buffer.from(listing + "\r\n"))
                client.respond(
                  "226",
                  `Successfully transferred "${getFolder()}"`
                )
              })
          })
          .catch(() => {
            client.respond("501", "Command failed")
          })
      }

      /*
       *  SIZE
       */
      function SIZE(cmd: string, file: string) {
        resolveFile(file).then(
          (file) =>
            fileSize(file).then(
              (size) => {
                client.respond("213", size.toString())
              },
              (error) => {
                DebugHandler(error)
                switch (error.code) {
                  case "ENOENT":
                    client.respond("550", "File not found")
                    break
                  default:
                    client.respond("501", "Command failed")
                    break
                }
              }
            ),
          (error) => {
            DebugHandler(error)
            client.respond("501", "Command failed")
          }
        )
      }

      /*
       *  DELE
       */
      function DELE(cmd: string, file: string) {
        if (!allowUserFileDelete) {
          client.respond("550", "Permission denied")
        } else {
          resolveFile(file).then(
            (file) =>
              fileDelete(file).then(
                () => {
                  client.respond("250", "File deleted successfully")
                },
                (error) => {
                  DebugHandler(error)
                  switch (error.code) {
                    case "ENOENT":
                      client.respond("550", "File not found")
                      break
                    default:
                      client.respond("501", "Command failed")
                      break
                  }
                }
              ),
            (error) => {
              DebugHandler(error)
              client.respond("501", "Command failed")
            }
          )
        }
      }

      /*
       *  RETR
       */
      function RETR(cmd: string, param: string) {
        resolveFile(param).then(
          (file) => {
            if (!allowUserFileRetrieve) {
              client.respond("550", `Transfer failed "${file}"`)
            } else {
              fileExists(file).then((isFile) => {
                if (!isFile) {
                  client.respond("550", "File not found")
                } else {
                  openDataSocket()
                    .then((writeSocket) =>
                      fileRetrieve(file, dataOffset)
                        .then((readStream) => {
                          asciiOn && writeSocket.setEncoding("ascii")
                          readStream.on("error", (error) => {
                            // incomplete write
                            DebugHandler(error)
                            writeSocket.destroy()
                            client.respond("550", `Transfer failed "${file}"`)
                          })
                          writeSocket.on("error", () => {
                            // incomplete write
                            readStream.destroy()
                            client.respond(
                              "426",
                              `Connection closed. Aborted transfer of "${file}"`
                            )
                          })
                          readStream.on("close", () => {
                            // end of file
                            writeSocket.end()
                            client.respond(
                              "226",
                              `Successfully transferred "${file}"`
                            )
                          })
                          readStream.pipe(writeSocket)
                        })
                        .finally(() => {
                          dataOffset = 0
                        })
                    )
                    .catch((error) => {
                      DebugHandler(error)
                      client.respond("501", "Command failed")
                    })
                }
              })
            }
          },
          (error) => {
            DebugHandler(error)
            client.respond("550", `Transfer failed "${param}`)
          }
        )
      }

      /*
       *  STOR
       */
      function STOR(cmd: string, param: string) {
        resolveFile(param).then(
          (file) =>
            fileExists(file).then((isFile) => {
              if (isFile ? !allowUserFileOverwrite : !allowUserFileCreate) {
                client.respond(
                  "550",
                  isFile ? "File already exists" : `Transfer failed "${file}"`
                )
              } else {
                openDataSocket()
                  .then((readSocket) => {
                    fileStore(file, dataOffset, asciiOn ? "ascii" : "binary")
                      .then((writeStream) => {
                        writeStream.on("error", (error) => {
                          // incomplete write
                          DebugHandler(error)
                          readSocket.destroy()
                          client.respond("550", `Transfer failed "${file}"`)
                        })
                        readSocket.on("error", (error) => {
                          // incomplete upload
                          DebugHandler(error)
                          writeStream.destroy()
                          client.respond("550", `Transfer failed "${file}"`)
                        })
                        readSocket.on("end", () => {
                          // end of file
                          writeStream.end()
                          client.respond(
                            "226",
                            `Successfully transferred "${file}"`
                          )
                        })
                        readSocket.pipe(writeStream)
                      })
                      .finally(() => {
                        dataOffset = 0
                      })
                  })
                  .catch((error) => {
                    DebugHandler(error)
                    client.respond("501", "Command failed")
                  })
              }
            }),
          (error) => {
            DebugHandler(error)
            client.respond("550", `Transfer failed "${param}"`)
          }
        )
      }

      /*
       *  RNFR
       */
      function RNFR(cmd: string, file: string) {
        resolveFile(file).then(
          (file) =>
            fileExists(file).then((isFile) => {
              if (!isFile) {
                client.respond("550", "File does not exist")
              } else if (!allowUserFileRename) {
                client.respond("550", "Permission denied")
              } else {
                renameFileFrom = file
                client.respond("350", "File exists")
              }
            }),
          (error) => {
            DebugHandler(error)
            client.respond("501", "Command failed")
          }
        )
      }

      /*
       *  RNTO
       */
      function RNTO(cmd: string, file: string) {
        if (!allowUserFileRename) {
          client.respond("550", "Permission denied")
        } else {
          resolveFile(file).then(
            (file) =>
              fileExists(file).then((isFile) => {
                if (isFile) {
                  client.respond("550", "File already exists")
                } else {
                  fileRename(renameFileFrom, file)
                    .then(
                      () => {
                        client.respond("250", "File renamed successfully")
                      },
                      (error) => {
                        DebugHandler(error)
                        client.respond("550", "File rename failed")
                      }
                    )
                    .finally(() => {
                      renameFileFrom = ""
                    })
                }
              }),
            (error) => {
              DebugHandler(error)
              client.respond("501", "Command failed")
            }
          )
        }
      }

      /*
       *  MFMT
       */
      function MFMT(cmd: string, arg: string) {
        const [time, ...rest] = arg.split(/\s+/),
          mtime = getDateForMFMT(time)
        resolveFile(rest.join(" ")).then(
          (file) =>
            fileSetTimes(file, mtime).then(
              () => {
                client.respond("253", "Date/time changed okay")
              },
              (error) => {
                DebugHandler(error)
                switch (error.code) {
                  case "ENOENT":
                    client.respond("550", "File does not exist")
                    break
                  default:
                    client.respond("501", "Command failed")
                    break
                }
              }
            ),
          (error) => {
            DebugHandler(error)
            client.respond("501", "Command failed")
          }
        )
      }
    }

    function setUserRights(credential: UserCredential) {
      const { basefolder } = credential
      if (basefolder && !storeBackend && !fs.existsSync(basefolder)) {
        throw Object.assign(
          Error(`user basefolder [${basefolder}] does not exist`),
          {
            code: "ENOTDIR",
          }
        )
      }

      ;({
        allowUserFileCreate = false,
        allowUserFileRetrieve = false,
        allowUserFileOverwrite = false,
        allowUserFileDelete = false,
        allowUserFileRename = false,
        allowUserFolderDelete = false,
        allowUserFolderCreate = false,
      } = credential)
      ;({
        resolveFolder,
        resolveFile,

        setFolder,
        getFolder,

        folderExists,
        folderDelete,
        folderCreate,
        folderList,

        fileExists,
        fileSize,
        fileDelete,
        fileRetrieve,
        fileStore,
        fileRename,
        fileSetTimes,
      } = Object.assign(
        localFsBackend({
          basefolder: config.basefolder,
          ...credential,
          username,
        }),
        storeBackend?.({
          basefolder: config.basefolder,
          ...credential,
          username,
        })
      ))

      renameFileFrom = ""
      dataOffset = 0
      authenticated = true
      return Promise.resolve()
    }

    function initPasvSocket() {
      if (passivePort) {
        passivePort.close()
        pasvSocket = new Deferred<Socket | TLSSocket>()
      }

      if (isEncrypted && shouldProtect) {
        passivePort = createSecureServer(config.tls)
        passivePort.on("secureConnection", (socket) => {
          DebugHandler(`${remoteInfo} secure data connection established`)
          setupSocket(socket)
        })
      } else {
        passivePort = createServer()
        passivePort.on("connection", (socket) => {
          if (isEncrypted && shouldProtect) {
            socket = new TLSSocket(socket, {
              isServer: true,
              secureContext: createSecureContext(config.tls),
            })
            socket.on("secure", () => {
              DebugHandler(`${remoteInfo} data connection is secure`)
              setupSocket(socket)
            })
          } else {
            DebugHandler(`${remoteInfo} data connection established`)
            setupSocket(socket)
          }
        })
      }

      passivePort.maxConnections = 1
      passivePort.on("error", ServerErrorHandler)
      return findAvailablePort().then(
        (port) =>
          new Promise<AddressInfo["port"]>((resolve, reject) => {
            passivePort.once("error", reject)
            passivePort.listen(port, () => {
              resolve((passivePort?.address() as AddressInfo).port)
            })
          })
      )

      function setupSocket(socket: Socket | TLSSocket) {
        socket.on("error", SessionErrorHandler)
        socket.on("close", () => {
          pasvSocket = new Deferred<Socket | TLSSocket>()
        })

        // socket.on("data", (buf) => DebugHandler(buf.toString()))
        pasvSocket.resolve(socket)
      }

      function findAvailablePort() {
        return new Promise<number>((resolve, reject) => {
          const { minDataPort, maxConnections } = config
          function checkListenPort(port: number) {
            const server = createServer()
            server.once("error", function () {
              if (port >= minDataPort + maxConnections) {
                reject(Error("exceeded maxConnections"))
              } else {
                checkListenPort(++port)
              }
            })
            server.once("close", function () {
              resolve(port)
            })

            server.listen(port, function () {
              server.close()
            })
          }

          if (minDataPort > 0 && minDataPort < 65535) {
            checkListenPort(minDataPort)
          } else {
            reject(Error("minDataPort out-of-range 1-65535"))
          }
        })
      }
    }

    function openDataSocket(): Promise<net.Socket> {
      if (passivePort) {
        client.respond("150", "Awaiting passive connection")
        return pasvSocket
      }

      return new Promise<Socket>((resolve, reject) => {
        if (dataAddr && dataPort) {
          client.respond("150", "Opening data connection")
          DebugHandler(
            `${remoteInfo} connect to client data socket isSecure[${isEncrypted}] protection[${shouldProtect}] addr[${dataAddr}] port[${dataPort}]`
          )
          let socket = net.connect(dataPort, dataAddr, () => {
            if (isEncrypted && shouldProtect) {
              socket = new TLSSocket(socket, {
                isServer: true,
                secureContext: createSecureContext(config.tls),
              })
              socket.on("secure", () => {
                DebugHandler(`${remoteInfo} data connection is secure`)
                resolve(socket) // data connection resolved
              })
            } else {
              resolve(socket) // data connection resolved
            }
          })
          socket.on("error", DebugHandler)
        } else {
          reject(Error("active or passive mode not selected"))
        }
      })
    }

    function LoginHandler() {
      emitter.emit("login", {
        remoteInfo,
        username,
        openSessions: Array.from(openSessions.keys()).length,
      })
    }

    function LogoffHandler() {
      emitter.emit("logoff", {
        remoteInfo,
        username,
        openSessions: Array.from(openSessions.keys()).length - 1,
      })
    }

    function SessionErrorHandler(err: NodeJS.ErrnoException) {
      if ("code" in err && err.code === "ECONNRESET") {
        DebugHandler(err)
        return
      }
      console.error(
        `session error ${remoteInfo}`,
        `${getDateForLogs()} ${util.inspect(err, {
          showHidden: false,
          depth: null,
          breakLength: Infinity,
        })}`
      )
    }
  }

  function ListenHandler(protocol: string, address: string | AddressInfo) {
    emitter.emit("listen", {
      protocol,
      address: (address as AddressInfo).address,
      port: (address as AddressInfo).port,
      basefolder: config.basefolder,
    })
  }

  function LogHandler(msg: string | { toString: () => string }) {
    emitter.emit("log", `${getDateForLogs()} ${msg}`)
  }

  function DebugHandler(msg: string | { toString: () => string }) {
    emitter.emit("debug", `${getDateForLogs()} ${msg}`)
  }

  function ServerErrorHandler(err: NodeJS.ErrnoException) {
    if ("code" in err && err.code === "ECONNRESET") {
      DebugHandler(err)
      return
    }
    console.error(
      "server error",
      `${getDateForLogs()} ${util.inspect(err, {
        showHidden: false,
        depth: null,
        breakLength: Infinity,
      })}`
    )
  }
}

// time/date formatter utilities
export function getDateForLIST(mtime: Date): string {
  const now = new Date(mtime)
  const MM = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
  ][now.getMonth()]
  const DD = now.getDate().toString().padStart(2, "0")
  const H = now.getHours().toString().padStart(2, "0")
  const M = now.getMinutes().toString().padStart(2, "0")
  return `${MM} ${DD} ${H}:${M}`
}

export function getDateForMLSD(mtime: Date): string {
  const now = new Date(mtime)
  const MM = (now.getMonth() + 1).toString().padStart(2, "0")
  const DD = now.getDate().toString().padStart(2, "0")
  const H = now.getHours().toString().padStart(2, "0")
  const M = now.getMinutes().toString().padStart(2, "0")
  const S = now.getSeconds().toString().padStart(2, "0")
  return `${now.getFullYear()}${MM}${DD}${H}${M}${S}`
}

function getDateForMFMT(time: string): number {
  // expect format YYYYMMDDhhmmss
  const Y = time.substring(0, 4),
    M = time.substring(4, 6),
    D = time.substring(6, 8),
    Hrs = time.substring(8, 10),
    Min = time.substring(10, 12),
    Sec = time.substring(12, 14)
  return Date.parse(`${Y}-${M}-${D}T${Hrs}:${Min}:${Sec}+00:00`) / 1000
}

function getDateForLogs(date?: Date): string {
  date = date || new Date()
  return date.toISOString()
}

export default createFtpServer
