/*
 * @package jsftpd
 * @author Sven <mailsvb@gmail.com>
 * @author Tim Gerk <tjgerk@gmail.com>
 * @license https://github.com/mailsvb/jsftpd/blob/main/LICENSE MIT License
 */

import { EventEmitter } from "node:events"
import { createHash } from "node:crypto"
import { Stats as FsStats } from "node:fs"
import { connect, createServer, Server } from "node:net"
import {
  Socket,
  AddressInfo,
  ListenOptions,
  TcpSocketConnectOpts,
} from "node:net"
import { resolve as resolvePath } from "node:path"
import type { Readable, Writable } from "node:stream"
import {
  TLSSocket,
  createServer as createSecureServer,
  createSecureContext,
} from "node:tls"
import { SecureContextOptions, Server as TLSServer } from "node:tls"
import { format } from "node:util"

import internalAuthFactory, {
  AuthFactory,
  AuthOptions,
  LoginError,
  Credential,
} from "./auth.js"

import localStoreFactory, {
  Store,
  StoreFactory,
  Errors as StoreErrors,
  RelativePath,
  Stats,
  validateBaseFolder,
} from "./store.js"
import type { AbsolutePath } from "./store.js"

import { asciify, deasciify, tee } from "./ascii.js"
import { addDeferredIteratorOnEvent } from "./deferred.js"
import { formatListing } from "./list.js"
import { rfc3659_formatTime, rfc3659_parseTime } from "./time.js"

export type ComposableAuthFactory = (factory: AuthFactory) => AuthFactory
export type ComposableStoreFactory = (factory: StoreFactory) => StoreFactory

export type ServerOptions = {
  server?: Server | TLSServer
  port?: number | ListenOptions
  securePort?: number | ListenOptions
  minDataPort?: number
  maxConnections?: number
  timeout?: number
  dataTimeout?: number
  tls?: SecureContextOptions
  basefolder?: AbsolutePath | RelativePath
  auth?: ComposableAuthFactory | ComposableAuthFactory[] // most-significant first
  store?: ComposableStoreFactory | ComposableStoreFactory[] // most-significant first
} & AuthOptions

interface FtpServerControls {
  basefolder: string

  emit(event: "reload-auth", options: AuthOptions): void
}

interface FtpServerEvents {
  on(
    event: "listening",
    listener: (data: {
      server: Server | TLSServer
      basefolder: AbsolutePath
    }) => void
  ): this

  on(
    event: "session",
    listener: (socket: Socket | (TLSSocket & FtpSessionEvents)) => void
  ): this

  on(
    event: "login" | "logoff",
    listener: (data: {
      client: string
      username: string
      sessions: number
    }) => void
  ): this

  // command channel in/out plus folder listing
  on(
    event: "trace",
    listener: (data: { msg: string; client: FtpSession }) => void
  ): this

  // networking
  on(
    event: "debug",
    listener: (
      msg: string,
      data: {
        client: FtpSession
        dataServer?: Server
        socket?: Socket
      }
    ) => void
  ): this

  on(
    event: "create-directory" | "read-directory" | "remove-directory",
    listener: (data: {
      client: string
      username: string
      folder: string
    }) => void
  ): this
  on(
    event: "upload",
    listener: (data: {
      client: string
      username: string
      file: string
      sha256: string
      overwrite: boolean
      offset: number
      size: number
    }) => void
  ): this
  on(
    event: "download",
    listener: (data: {
      client: string
      username: string
      file: string
      sha256: string
      offset: number
      size: number
    }) => void
  ): this
  on(
    event: "rename",
    listener: (data: {
      client: string
      username: string
      fileFrom: string
      fileTo: string
    }) => void
  ): this
  on(
    event: "delete",
    listener: (data: { client: string; username: string; file: string }) => void
  ): this
  on(
    event: "modify",
    listener: (data: {
      client: string
      username: string
      file: string
      fstatOriginal: FsStats
      fstatNew: FsStats
    }) => void
  ): this
  on(
    event: "inspect",
    listener: (data: {
      client: string
      username: string
      file: string
      fstat: Stats
    }) => void
  ): this
}

interface FtpSessionEvents {
  on(
    event: "command-error",
    listener: (this: FtpSession, data: { cmd: string; error: unknown }) => void
  ): this
  on(
    event: "port-error",
    listener: (
      this: FtpSession,
      msg: string,
      data: {
        error: unknown
        client: FtpSession
        dataServer?: Server
        socket?: Socket
      }
    ) => void
  ): this
}

type FtpSession = (Socket | TLSSocket) & FtpSessionEvents

export type FtpServer = EventEmitter & {
  server?: Server
  secureServer?: TLSServer

  on(
    event: "listening",
    listener: (server: Server | TLSServer, basefolder: string) => void
  ): FtpServer

  close: (callback?: (err?: Error) => void) => FtpServer
}

export default function createFtpServer({
  server, // caller handles binding to path or address/port
  port,
  securePort,
  minDataPort = 1024,
  maxConnections = 10,
  timeout, // max session duration (not an idle-timeout)
  dataTimeout, // max data transfer time (not a connection-delay timeout)
  tls: tlsOptions, // TODO: compatible or extractible from caller-provided server?
  auth,
  store,
  ...options
}: ServerOptions = {}): (Server | TLSServer | FtpServer) &
  FtpServerControls &
  FtpServerEvents {
  if (!port && !securePort && !server) port = { port: 21 }
  dataTimeout = dataTimeout ?? timeout

  // always prepare TLS certs and secure context for TLS escalation
  tlsOptions = {
    // rejectUnauthorized: false, // enforce CA trust
    honorCipherOrder: true,
    ...tlsOptions,
  }
  const secureOptions = (() => {
      if (
        ("key" in tlsOptions && "cert" in tlsOptions) ||
        "pfx" in tlsOptions
      ) {
        return Promise.resolve(tlsOptions)
      }

      // load key & cert from well-known location, else generate self-signed certificate
      return import("./tls.js").then((keys) => ({
        ...tlsOptions,
        ...keys,
      }))
    })(),
    secureContext = secureOptions.then(createSecureContext) // can use with tls.Socket constructor option, not tls.Server

  const authFactory = ((authFactory) => {
    if (auth instanceof Array) {
      return auth.reduceRight((y, f) => f(y), authFactory)
    }

    if (auth instanceof Function) {
      return auth(authFactory)
    }

    return authFactory
  })(internalAuthFactory)

  const basefolder = validateBaseFolder(options.basefolder),
    storeFactory = ((storeFactory) => {
      if (store instanceof Array) {
        return store.reduceRight((y, f) => f(y), storeFactory)
      }

      if (store instanceof Function) {
        return store(storeFactory)
      }

      return storeFactory
    })(localStoreFactory({ basefolder }))

  // track active and cumulative client sessions
  let clientCounter = 0
  const clientSessions: Set<Socket> = new Set()

  const emitter = server ?? new EventEmitter()

  let authenticate = authFactory(options)
  emitter.on("reload-auth", (options: AuthOptions) => {
    authenticate = authFactory(options)
  })

  if (server) {
    if (server instanceof TLSServer) {
      server.on("secureConnection", FtpSessionHandler)
    } else {
      server.on("connection", FtpSessionHandler)
    }

    if (basefolder.cleanup) {
      server.on("close", basefolder.cleanup)
    }

    return Object.assign(server, { basefolder })
  }

  // setup FTP, FTPS servers
  let tcpServer: Server
  if (port) {
    tcpServer = createServer(FtpSessionHandler)
    // .on("connection", emitter.emit.bind(emitter, "connection"))
    // .on("drop", emitter.emit.bind(emitter, "drop"))
    // .on("error", emitter.emit.bind(emitter, "error"))
    // .on("close", emitter.emit.bind(emitter, "close"))

    tcpServer.maxConnections = maxConnections
    tcpServer.listen(port, function () {
      emitter.emit("listening", { server: this, basefolder })
    })

    if (basefolder.cleanup) {
      // idempotent
      tcpServer.on("close", basefolder.cleanup)
    }

    Object.assign(emitter, { server: tcpServer })
  }

  let tlsServer: Promise<TLSServer>
  if (securePort) {
    tlsServer = secureOptions.then((secureOptions) => {
      const tlsServer = createSecureServer(secureOptions, FtpSessionHandler)
      // .on("connection", emitter.emit.bind(emitter, "connection"))
      // .on("keylog", emitter.emit.bind(emitter, "keylog"))
      // .on("newSession", emitter.emit.bind(emitter, "newSession")) // if registered, need a response from handler to finish TLS handshake
      // .on("OCSPRequest", emitter.emit.bind(emitter, "OCSPRequest"))
      // .on("resumeSession", emitter.emit.bind(emitter, "resumeSession")) // if registered, need a response from handler to finish TLS handshake
      // .on("tlsClientError", emitter.emit.bind(emitter, "tlsClientError"))
      // .on("secureConnection", emitter.emit.bind(emitter, "secureConnection"))
      // .on("drop", emitter.emit.bind(emitter, "drop"))
      // .on("error", emitter.emit.bind(emitter, "error"))
      // .on("close", emitter.emit.bind(emitter, "close"))

      tlsServer.maxConnections = maxConnections
      tlsServer.listen(securePort, function () {
        emitter.emit("listening", { server: this, basefolder })
      })

      return tlsServer
    })

    if (basefolder.cleanup) {
      // idempotent
      tlsServer.then((server) => server.on("close", basefolder.cleanup))
    }

    Object.assign(emitter, { secureServer: tlsServer })
  }

  return Object.assign(emitter, {
    basefolder,
    close(callback?: (err?: Error) => void) {
      tcpServer?.close(callback)
      tlsServer?.then((server) => server.close(callback))
      return this
    },
  })

  function FtpSessionHandler(this: Server, socket: Socket | TLSSocket) {
    const clientInfo = `[(${++clientCounter}) ${
      socket.remoteAddress?.replace(/::ffff:/g, "") ?? "unknown"
    }:${socket.remotePort}]`
    let client = Object.assign(socket, {
      respond(this: Socket, code: string, message: string, delimiter = " ") {
        emitter.emit("trace", `<<< ${code} ${message}`, client)
        this.write(`${code}${delimiter}${message}\r\n`)
      },
    })

    emitter.emit("debug", `established FTP connection`, { client })
    clientSessions.add(client)

    client.on("data", CmdHandler).on("close", function () {
      if (dataServer) {
        emitter.emit("debug", `closing data server ${JSON.stringify(dataServer.address())}`, { client, dataServer }) // prettier-ignore
      }
      dataServer?.close()
      clientSessions.delete(this)
      emitter.emit("debug", `FTP connection closed`, { client })
    })

    client.respond("220", "Welcome")
    emitter.emit("session", client)

    // TODO: authentication by Kerberos single-signon (Windows Authentication)
    // TODO: authentication by client cert
    // TODO: push down allow* credential access to the Store

    // session state
    let authUser: (token: string) => Promise<Credential>,
      user: Credential,
      store: Store
    function setUser(credential: Credential) {
      authUser = null
      user = credential
      store = storeFactory(client, credential)

      emitter.emit("login", {
        client: clientInfo,
        username: user.username,
        sessions: clientSessions.size,
      })
    }

    let asciiTxfrMode = false,
      pbszReceived = false,
      protectedMode = false,
      dataOffset = 0,
      renameFile: Awaited<ReturnType<Store["fileRename"]>>

    let dataServer: Server & AsyncIterator<Socket>,
      dataPort: TcpSocketConnectOpts

    function startDataServer(): Promise<Server & AsyncIterator<Socket>> {
      const dataServer = addDeferredIteratorOnEvent<Server, Socket>(createServer(), "connection")
        .on("error", function (error) { this.throw(error) }) // prettier-ignore
        .on("close", function () { this.return() }) // prettier-ignore

      dataServer.maxConnections = 1

      return selectDataPort(minDataPort, maxConnections).then(
        (port) =>
          // promisify net.Server.listen()
          new Promise((resolve, reject) => {
            // TODO listen to same address as server or secureServer
            dataServer
              .on("error", reject)
              .listen(port, function onListening(this: typeof dataServer) {
                emitter.emit("debug", `data server listening ${JSON.stringify(this.address())}`, { client, dataServer: this }) // prettier-ignore

                resolve(
                  this.off("error", reject)
                    .on("error", function (error) {
                      client.emit("port-error", "data server", { error, client, dataServer: this }) // prettier-ignore
                    })
                    .on("close", function () {
                      // when closed, this.address() returns null
                      emitter.emit("debug", `closed data server port[${port}]`, { client, dataServer: this }) // prettier-ignore
                    })
                )
              })
          })
      )

      // TODO: avoid port scanning
      function selectDataPort(minDataPort: number, maxConnections: number) {
        return new Promise<number>((resolve, reject) => {
          // TODO: if minDataPort is not set, ignore maxConnections & just listen on a random port, stateful firewalls can cope
          // port-based firewalls want a block of ports from min to min+max
          if (minDataPort <= 0 || minDataPort > 65535) {
            reject(Error("minDataPort out-of-range 1-65535"))
            return
          }

          ;(function checkAvailablePort(port: number) {
            createServer()
              .once("error", function () {
                if (port >= minDataPort + maxConnections) {
                  reject(Error("exceeded maxConnections"))
                  return
                }

                checkAvailablePort(port + 1) // continue port scan
              })
              .once("close", function () {
                resolve(port)
              })
              .listen(port, function () {
                this.close()
              })
          })(minDataPort)
        })
      }
    }

    function getDataSocket() {
      // promisify incoming/outbound connection
      return new Promise<Socket>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(Error("connection timeout")),
          2000
        )

        if (dataServer) {
          client.respond("150", "Awaiting passive data connection")

          // eslint-disable-next-line no-inner-declarations
          function onClose(cause?: Error) {
            reject(new Error("server closed", { cause }))
          }

          // dataServer implements AsyncIterable<Socket>
          const server = dataServer
          server
            .on("error", reject)
            .on("close", onClose)
            .next()
            .then(({ done, value: socket }) => {
              clearTimeout(timer)
              server.off("error", reject).off("close", onClose)

              if (done) {
                reject(Error("data server has closed"))
                return
              }

              // TODO: assure remote address is same as command channel

              emitter.emit("debug", `passive data connection established`, { client, socket }) // prettier-ignore
              resolve(socket)
            })
        } else if (dataPort) {
          client.respond("150", "Opening active data connection")

          const { host, port } = dataPort
          emitter.emit("debug", `connecting to ${host} port ${port}`, { client }) // prettier-ignore
          connect(dataPort, async function onActiveDataConnect() {
            clearTimeout(timer)
            this.off("error", reject)
            emitter.emit("debug", `active data connection established`, { client, socket: this }) // prettier-ignore

            resolve(this)
          }).on("error", reject)
        } else {
          clearTimeout(timer)
          reject(Error("active or passive mode not selected"))
        }
      })
        .then<Socket>(async (socket) => {
          // secure the connection
          const secure = "encrypted" in client && protectedMode
          if (secure) {
            // promisify new tls.Socket()
            const ctx = await secureContext
            return new Promise<TLSSocket>((resolve, reject) => {
              new TLSSocket(socket, {
                isServer: true,
                secureContext: ctx,
              })
                .on("error", reject)
                .once("secure", function (this: TLSSocket) {
                  // TLS handshake is complete (tls.Socket emits "secure", tls.Server emits "secureConnection")
                  emitter.emit("debug", `data connection secured`, { client, socket: this }) // prettier-ignore
                  resolve(this.off("error", reject))
                })
            })
          }

          return socket
        })
        .then((socket) => {
          if (dataTimeout) {
            socket.setTimeout(dataTimeout, socket.destroy.bind(socket))
          }

          return socket
            .on("error", function (error) {
              client.emit("port-error", "data connection", { error, client, socket: this }) // prettier-ignore
            })
            .on("close", function () {
              emitter.emit("debug", `data connection closed`, { client, socket: this }) // prettier-ignore
            })
        })
    }

    function resetSession() {
      authUser = null
      user = null
      store = null

      asciiTxfrMode = false
      pbszReceived = false
      protectedMode = false
      dataOffset = 0
      renameFile = null

      dataServer?.close()
      dataServer = dataPort = null
    }

    const preAuthMethods = {
        QUIT() {
          client.respond("221", "Goodbye")
          client.end()

          if (user) {
            emitter.emit("logoff", {
              client: clientInfo,
              username: user.username,
              sessions: clientSessions.size - 1,
            })
          }
        },

        AUTH(_: string, auth: string) {
          switch (auth) {
            case "TLS":
            case "SSL":
              resetSession() // RFC-4217
              client.respond("234", `Using authentication type ${auth}`)

              secureContext.then((secureContext) => {
                client = Object.assign(
                  new TLSSocket(client, {
                    isServer: true,
                    secureContext,
                  })
                    .once("secure", () => {
                      emitter.emit("debug", `command connection secured`, { client }) // prettier-ignore
                    })
                    .on("data", CmdHandler),
                  { respond: client.respond }
                )
              })
              break
            default:
              client.respond("504", `Unsupported auth type ${auth}`)
          }
        },

        USER(cmd: string, user: string) {
          resetSession()
          authenticate(client, user)
            .then((credential) => {
              if (credential instanceof Function) {
                authUser = credential
                client.respond("331", `Password required for ${user}`)
                // LATER: extra data for OAUTH, ID provider link?
                return
              }

              setUser(credential)
              client.respond("232", "User logged in")
            })
            .catch((loginError) => {
              switch (loginError) {
                case LoginError.Secure:
                  client.respond("530", "Session not secure")
                  break

                case LoginError.None:
                default:
                  client.respond("530", "Not logged in")
                  break
              }
            })
        },

        // LATER: extra data for OAUTH, refresh token?
        // LATER: inject protocol extensions for KRB negotiation?
        PASS(_: string, token: string) {
          if (!authUser) {
            client.respond("503", "USER missing")
          } else
            authUser(token)
              .then(
                (credential: Credential) => {
                  setUser(credential)
                  client.respond("230", "Logged on")
                },
                (loginError) => {
                  switch (loginError) {
                    case LoginError.Password:
                      client.respond("530", "Username or password incorrect")
                      break

                    default:
                      throw loginError
                  }
                }
              )
              .finally(() => {
                authUser = null
              })
        },
      },
      authenticatedMethods = {
        CLNT() {
          client.respond("200", "Don't care")
        },

        PBSZ(_: string, size: string) {
          pbszReceived = true
          client.respond("200", `PBSZ=${size}`)
        },

        PROT(_: string, protection: string) {
          if (!pbszReceived) {
            client.respond("503", "PBSZ missing")
            return
          }

          switch (protection) {
            case "P": // private, i.e. SSL
            case "C": // clear
              protectedMode = protection === "P"
              client.respond("200", `Protection level is ${protection}`)
              break
            default:
              client.respond("534", "Protection level must be C or P")
          }
        },

        OPTS(_: string, opt: string, value: string) {
          switch (opt.toLowerCase()) {
            case "utf8":
              switch (value.toLowerCase()) {
                case "on":
                  client.respond("200", "UTF8 ON")
                  return
                case "off":
                  client.respond("200", "UTF8 OFF")
                  return
              }
          }

          client.respond("451", "Not supported")
        },

        FEAT() {
          const features = Object.keys(preAuthMethods)
            .concat(Object.keys(authenticatedMethods))
            .join("\r\n ")
            .replace("AUTH", "AUTH TLS\r\n AUTH SSL")
          client.respond("211", `Features:\r\n ${features}\r\n211 End`, "-")
        },

        PORT(_: string, spec: string) {
          const parts = spec.split(","),
            host = parts.slice(0, 4).join("."),
            port = (parseInt(parts[4], 10) << 8) | parseInt(parts[5])
          if (host.match(/\d{1,3}(\.\d{1,3}){3}/) && port) {
            dataServer?.close()
            dataServer = null
            dataPort = { host, port }

            client.respond("200", "Port command successful")
          } else {
            client.respond("501", "Port command failed")
          }
        },

        PASV(cmd: string) {
          dataServer?.close()
          dataServer = dataPort = null
          startDataServer().then(
            (server) => {
              dataServer = server

              const port = (server.address() as AddressInfo).port,
                host = client.localAddress
                  .replace(/::ffff:/g, "") // IPv4 in IPv6 prefix
                  .split(".")
                  .join(","),
                response = format(
                  "Entering passive mode (%s,%d,%d)",
                  host,
                  port >> 8,
                  port & 255
                )
              client.respond("227", response)
            },
            (error) => {
              client.emit("command-error", { cmd, error })
              client.respond("501", "Passive command failed")
            }
          )
        },

        EPRT(_: string, spec: string) {
          const parts = spec.split("|"),
            host = parts[2], // could be either IPv4 or IPv6
            port = parseInt(parts[3], 10)
          if (
            parts.length === 5 &&
            // addr.match(/\d{1,3}(\.\d{1,3}){3}/) && // skip this check to permit IPv6
            port > 0
          ) {
            dataServer?.close()
            dataServer = null
            dataPort = { host, port }

            client.respond("200", "Extended Port command successful")
          } else {
            client.respond("501", "Extended port command failed")
          }
        },

        EPSV(cmd: string) {
          dataServer?.close()
          dataServer = dataPort = null
          startDataServer().then(
            (server) => {
              dataServer = server

              const port = (server.address() as AddressInfo).port,
                response = format(
                  "Entering extended passive mode (|||%d|)",
                  port
                )
              client.respond("229", response)
            },
            (error) => {
              client.emit("command-error", { cmd, error })
              client.respond("501", "Extended passive command failed")
            }
          )
        },

        SYST() {
          client.respond("215", process.env["OS"] ?? "UNIX")
        },

        TYPE(_: string, tfrType: string) {
          if (tfrType === "A") {
            asciiTxfrMode = true
            client.respond("200", "Type set to ASCII")
          } else {
            asciiTxfrMode = false
            client.respond("200", "Type set to BINARY")
          }
        },

        REST(_: string, arg: string) {
          const offset = parseInt(arg, 10)
          if (offset >= 0) {
            dataOffset = offset
            client.respond("350", `Restarting at ${dataOffset}`)
          } else {
            dataOffset = 0
            client.respond("550", "Wrong restart offset")
          }
        },

        PWD() {
          client.respond("257", `"${store.folder}" is current directory`)
        },

        CWD(cmd: string, folder: string) {
          store.setFolder(folder).then(
            (folder) =>
              client.respond(
                "250",
                `CWD successful. "${folder}" is current directory`
              ),
            (error) => {
              client.emit("command-error", { cmd, error })
              if (error.code === StoreErrors.EPERM) {
                client.respond("550", "Permission denied")
                return
              }

              if (
                error.code === StoreErrors.ENOTDIR ||
                error.code === StoreErrors.ENOENT
              ) {
                client.respond("550", "Folder not found")
                return
              }

              client.respond("501", "Command failed")
            }
          )
        },

        RMD(cmd: string, folder: string) {
          store.folderDelete(folder).then(
            () => {
              client.respond("250", "Folder deleted successfully")

              emitter.emit("remove-directory", {
                client: clientInfo,
                username: user.username,
                folder: resolvePath(store.folder, folder),
              })
            },
            (error) => {
              client.emit("command-error", { cmd, error })
              if (error.code === StoreErrors.EPERM) {
                client.respond("550", "Permission denied")
                return
              }

              if (
                error.code === StoreErrors.ENOTDIR ||
                error.code === StoreErrors.ENOENT
              ) {
                client.respond("550", "Folder not found")
                return
              }

              client.respond("501", "Command failed")
            }
          )
        },

        MKD(cmd: string, folder: string) {
          store.folderCreate(folder).then(
            () => {
              client.respond("250", "Folder created successfully")

              emitter.emit("create-directory", {
                client: clientInfo,
                username: user.username,
                folder: resolvePath(store.folder, folder),
              })
            },
            (error) => {
              client.emit("command-error", { cmd, error })
              if (error.code === StoreErrors.EPERM) {
                client.respond("550", "Permission denied")
                return
              }

              if (error.code == StoreErrors.EEXIST) {
                client.respond("550", "Folder exists")
                return
              }

              client.respond("501", "Command failed")
            }
          )
        },

        LIST(cmd: string, folder?: string) {
          store
            .folderList(folder)
            .then((stats: Stats[]) =>
              getDataSocket().then((socket: Writable) => {
                folder = resolvePath(store.folder, folder ?? "")
                const listing = stats.map(formatListing(cmd)).join("\r\n")
                emitter.emit("trace", `>>> ${cmd} ${folder}\r\n${listing || "(empty)"}`, client) // prettier-ignore

                socket.end(listing + "\r\n") // FileZilla borks: "TLS connection was non-properly terminated" some half-open problem?
                client.respond("226", `Successfully transferred "${folder}"`)

                emitter.emit("read-directory", {
                  client: clientInfo,
                  username: user.username,
                  folder,
                })
              })
            )
            .catch((error) => {
              client.emit("command-error", { cmd, error })
              if (error.code === StoreErrors.EPERM) {
                client.respond("550", "Permission denied")
                return
              }

              if (
                error.code === StoreErrors.ENOTDIR ||
                error.code === StoreErrors.ENOENT
              ) {
                client.respond("550", "Folder not found")
                return
              }

              // TODO: likely socket connection errors

              client.respond("501", `Command failed`)
            })
        },

        DELE(cmd: string, file: string) {
          store.fileDelete(file).then(
            () => {
              client.respond("250", "File deleted successfully")

              emitter.emit("delete", {
                client: clientInfo,
                username: user.username,
                file: resolvePath(store.folder, file),
              })
            },
            (error) => {
              client.emit("command-error", { cmd, error })
              if (error.code === StoreErrors.EPERM) {
                client.respond("550", "Permission denied")
                return
              }

              if (
                error.code === StoreErrors.ENOTFILE ||
                error.code === StoreErrors.ENOENT
              ) {
                client.respond("550", "File not found")
                return
              }

              client.respond("501", "Command failed")
            }
          )
        },

        SIZE(cmd: string, file: string) {
          store.fileStats(file).then(
            (fstat) => {
              switch (cmd) {
                case "SIZE":
                  client.respond("213", fstat.size.toString())
                  break
                case "MDTM":
                  client.respond("213", rfc3659_formatTime(fstat.mtime))
                  break
                default:
                  return
              }

              emitter.emit("inspect", {
                client: clientInfo,
                username: user.username,
                file: resolvePath(store.folder, file),
                fstat,
              })
            },
            (error) => {
              client.emit("command-error", { cmd, error })
              if (error.code === StoreErrors.EPERM) {
                client.respond("550", "Permission denied")
                return
              }

              if (
                error.code === StoreErrors.ENOTFILE ||
                error.code === StoreErrors.ENOENT
              ) {
                client.respond("550", "File not found")
                return
              }

              client.respond("501", "Command failed")
            }
          )
        },

        RETR(cmd: string, file: string) {
          store
            .fileRetrieve(file, dataOffset)
            .then((readStream: Readable) =>
              getDataSocket().then((writeSocket: Writable) => {
                readStream.on("error", (error) => {
                  writeSocket.destroy()
                  client.emit("command-error", { cmd, error })
                  client.respond("550", `Transfer failed`)
                })

                writeSocket.on("error", (error) => {
                  readStream.destroy()
                  client.emit("command-error", { cmd, error })
                  client.respond("426", `Client connection error"`)
                })

                if (asciiTxfrMode) {
                  // convert from server native text encoding
                  writeSocket = asciify().pipe(writeSocket)
                }

                let octets = 0
                const hash = createHash("sha256")
                readStream
                  .pipe(
                    tee((_, chunk) => {
                      octets += chunk.length
                      hash.write(chunk)
                    })
                  )
                  .pipe(
                    writeSocket.on("finish", () => {
                      client.respond(
                        "226",
                        `Successfully transferred "${file}"`
                      )

                      emitter.emit("download", {
                        client: clientInfo,
                        username: user.username,
                        file: resolvePath(store.folder, file),
                        sha256: hash.digest("hex"), // if offset > 0, this is signature of only part of the file
                        offset: dataOffset,
                        size: octets,
                      })
                      dataOffset = 0
                    })
                  )
              })
            )
            .catch((error) => {
              client.emit("command-error", { cmd, error })
              if (error.code === StoreErrors.EPERM) {
                client.respond("550", "Permission denied")
                return
              }

              if (
                error.code === StoreErrors.ENOTFILE ||
                error.code === StoreErrors.ENOENT
              ) {
                client.respond("550", "File not found")
                return
              }

              // TODO: likely socket connection errors

              client.respond("501", "Command failed")
            })
        },

        STOR(cmd: string, file: string) {
          store
            .fileStore(file, dataOffset)
            .then((writeStream: Writable) =>
              getDataSocket().then(
                (readSocket: Readable) => {
                  readSocket.on("error", (error) => {
                    writeStream.destroy()
                    client.emit("command-error", { cmd, error })
                    client.respond("426", `Client connection error"`)
                  })

                  writeStream.on("error", (error) => {
                    readSocket.destroy()
                    client.emit("command-error", { cmd, error })
                    client.respond("550", `Transfer failed`)
                  })

                  if (asciiTxfrMode) {
                    // convert to server native text encoding
                    readSocket = readSocket.pipe(deasciify())
                  }

                  let octets = 0
                  const hash = createHash("sha256")
                  readSocket
                    .pipe(
                      tee((_, chunk) => {
                        octets += chunk.length
                        hash.write(chunk)
                      })
                    )
                    .pipe(
                      writeStream.on("finish", () => {
                        client.respond(
                          "226",
                          `Successfully transferred "${file}"`
                        )

                        emitter.emit("upload", {
                          client: clientInfo,
                          username: user.username,
                          file: resolvePath(store.folder, file),
                          sha256: hash.digest("hex"), // if offset > 0, this is signature of only part of the file
                          overwrite: "overwrite" in writeStream,
                          offset: dataOffset,
                          size: octets,
                        })
                        dataOffset = 0
                      })
                    )
                },
                (error) => {
                  writeStream.destroy()
                  return Promise.reject(error)
                }
              )
            )
            .catch((error) => {
              client.emit("command-error", { cmd, error })
              if (
                error.code === StoreErrors.EPERM ||
                error.code === StoreErrors.EEXIST
              ) {
                if (error.code === StoreErrors.EEXIST) {
                  // actually a permissions problem: overwrite not allowed
                  client.respond("550", "File already exists")
                  return
                }

                client.respond("550", "Permission denied")
                return
              }

              if (error.code === StoreErrors.ENOTDIR) {
                client.respond("550", "Folder not found")
                return
              }

              // TODO: likely socket connection errors

              client.respond("501", "Command failed")
            })
        },

        RNFR(cmd: string, file: string) {
          store.fileRename(file).then(
            (renamingFunction) => {
              renameFile = renamingFunction
              client.respond("350", "File exists")
            },
            (error) => {
              client.emit("command-error", { cmd, error })
              if (error.code === StoreErrors.EPERM) {
                client.respond("550", "Permission denied")
                return
              }

              if (
                error.code === StoreErrors.ENOTFILE ||
                error.code === StoreErrors.ENOENT
              ) {
                client.respond("550", "File not found")
                return
              }

              client.respond("501", "Command failed")
            }
          )
        },

        RNTO(cmd: string, file: string) {
          if (!renameFile) {
            client.respond("503", "RNFR missing")
            return
          }

          renameFile(file).then(
            () => {
              client.respond("250", "File renamed successfully")

              emitter.emit("rename", {
                client: clientInfo,
                username: user.username,
                fileFrom: renameFile.fromFile,
                fileTo: resolvePath(store.folder, file),
              })
              renameFile = undefined
            },
            (error) => {
              client.emit("command-error", { cmd, error })
              if (
                error.code === StoreErrors.EPERM ||
                error.code === StoreErrors.EEXIST
              ) {
                if (error.code === StoreErrors.EEXIST) {
                  // actually a permissions problem: overwrite not allowed
                  client.respond("550", "File already exists")
                  return
                }

                client.respond("550", "Permission denied")
                return
              }

              if (error.code === StoreErrors.ENOTDIR) {
                client.respond("550", "Folder not found")
                return
              }

              client.respond("501", "Command failed")
            }
          )
        },

        MFMT(cmd: string, time: string, file: string) {
          const mtime = rfc3659_parseTime(time)
          store.fileSetAttributes(file, { mtime }).then(
            ([fstatOriginal, fstatNew]) => {
              client.respond("253", "Modified date/time")

              emitter.emit("modify", {
                client: clientInfo,
                username: user.username,
                file: resolvePath(store.folder, file),
                fstatOriginal,
                fstatNew,
              })
            },
            (error) => {
              client.emit("command-error", { cmd, error })
              if (error.code === StoreErrors.EPERM) {
                client.respond("550", "Permission denied")
                return
              }

              if (
                error.code === StoreErrors.ENOTFILE ||
                error.code === StoreErrors.ENOENT
              ) {
                client.respond("550", "File not found")
                return
              }

              client.respond("501", "Command failed")
            }
          )
        },
      }

    // method aliases
    Object.assign(authenticatedMethods, {
      RMDA: authenticatedMethods.RMD,
      MLSD: authenticatedMethods.LIST,
      NLST: authenticatedMethods.LIST,
      MDTM: authenticatedMethods.SIZE,
    })

    // unimplemented methods:
    //  SPSV, LPSV, LPRT
    //  MLST (like MDTM and SIZE)
    //  MFCT, MFF (like MFMT)
    //  ABOR, ACCT, NOOP, REIN, STAT
    //  APPE, CDUP, SMNT, STOU

    if (timeout) {
      client.setTimeout(timeout, preAuthMethods.QUIT)
    }

    function CmdHandler(buf: Buffer) {
      const [cmd, ...args] = buf.toString().trim().split(/\s+/)
      emitter.emit("trace", `>>> cmd[${cmd}] arg[${cmd === "PASS" ? "***" : args.join(" ")}]`, client) // prettier-ignore

      try {
        if (cmd in preAuthMethods) {
          preAuthMethods[cmd as keyof typeof preAuthMethods].call(
            this,
            cmd,
            ...args
          )
        } else if (cmd in authenticatedMethods) {
          if (!user) {
            client.respond("530", "Not logged in")
            return
          }

          authenticatedMethods[cmd as keyof typeof authenticatedMethods].call(
            this,
            cmd,
            ...args
          )
        } else {
          client.respond("500", "Command not implemented")
        }
      } catch (error) {
        client.emit("command-error", { cmd: `${[cmd, ...args].join(" ")}`, error }) // prettier-ignore
        client.respond("550", "Unexpected server error")
      }
    }
  }
}
