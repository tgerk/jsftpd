/* eslint-disable @typescript-eslint/no-unused-vars */
/*
 * @package jsftpd
 * @author Sven <mailsvb@gmail.com>
 * @author Tim Gerk <tjgerk@gmail.com>
 * @license https://github.com/mailsvb/jsftpd/blob/main/LICENSE MIT License
 */

import { EventEmitter } from "node:events"
import path from "node:path"
import { connect, createServer, Server } from "node:net"
import type {
  Socket,
  AddressInfo,
  ListenOptions,
  TcpSocketConnectOpts,
} from "node:net"
import {
  TLSSocket,
  createServer as createSecureServer,
  createSecureContext,
} from "node:tls"
import type { SecureContextOptions } from "node:tls"
import { inspect, format } from "node:util"
import type { Readable, Writable } from "node:stream"

import internalAuth, {
  AuthFactory,
  AuthOptions,
  LoginType,
  Permissions,
  Credential,
} from "./auth.js"

import localBackend, {
  Store,
  StoreFactory,
  Errors as StoreErrors,
} from "./store.js"
import type { AbsolutePath } from "./store.js"

import { asciify, deasciify } from "./util/ascii.js"
import { formatListing } from "./util/list.js"
import { format_rfc3659_time, parse_rfc3659_time } from "./util/time.js"
import createConnectionSource from "./util/connection-source.js"
import type { ConnectionSource } from "./util/connection-source.js"

export type ComposableAuthFactory = (factory: AuthFactory) => AuthFactory
export type ComposableStoreFactory = (factory: StoreFactory) => StoreFactory

export type ServerOptions = {
  server?: Server
  port?: number | ListenOptions
  securePort?: number
  minDataPort?: number
  maxConnections?: number
  timeout?: number
  dataTimeout?: number
  tls?: SecureContextOptions
  basefolder?: AbsolutePath
  auth?: ComposableAuthFactory
  store?: ComposableStoreFactory | ComposableStoreFactory[]
} & AuthOptions

export type FtpServer = ReturnType<typeof createFtpServer>

export default function createFtpServer({
  server,
  port = 21,
  securePort,
  minDataPort = 1024,
  maxConnections = 10,
  timeout,
  dataTimeout,
  tls: tlsOptions,
  basefolder,
  auth,
  store,
  ...authOptions
}: ServerOptions = {}) {
  // track client sessions
  let clientCounter = 0
  const clientSessions: Set<Socket> = new Set()

  const emitter = new EventEmitter()

  // compose auth and storage backend handler factories
  const authFactory = auth?.(internalAuth) ?? internalAuth
  let authenticate = authFactory(authOptions)

  const localStoreFactory = localBackend(basefolder),
    storeFactory: StoreFactory = (() => {
      if (store) {
        if (store instanceof Array) {
          return store.reduce((y, f) => f(y), localStoreFactory)
        }
        return store(localStoreFactory)
      }
      return localStoreFactory
    })()

  tlsOptions = {
    // rejectUnauthorized: false, // enforce CA trust
    honorCipherOrder: true,
    ...tlsOptions,
  }

  // always prepare TLS certs and secure context for TLS escalation
  const secureOptions = (async () => {
      if (
        ("key" in tlsOptions && "cert" in tlsOptions) ||
        "pfx" in tlsOptions
      ) {
        return tlsOptions
      }

      // load key & cert from well-known location, else generate self-signed certificate
      return await import("./util/tls.js").then((keys) => ({
        ...tlsOptions,
        ...keys,
      }))
    })(),
    secureContext = secureOptions.then(createSecureContext)

  function FtpSessionHandler(
    client: Socket & {
      respond?: (code: string, message: string, delimiter?: string) => void
    }
  ) {
    const clientInfo = `[(${++clientCounter}) ${
      client.remoteAddress?.replace(/::ffff:/g, "") ?? "unknown"
    }:${client.remotePort}]`
    Object.assign(client, {
      respond: function respond(
        this: Socket,
        code: string,
        message: string,
        delimiter = " "
      ) {
        log(`<<< ${code} ${message}`)
        this.write(`${code}${delimiter}${message}\r\n`)
      },
    })

    client
      .on("error", SessionErrorHandler("command socket"))
      .on("close", function () {
        ;(dataPort as ConnectionSource)?.close?.()
        clientSessions.delete(this)
        debug(`FTP connection closed`)
      })
      .on("data", CmdHandler)

    if (timeout) {
      client.setTimeout(timeout, () => {
        client.respond("221", "Goodbye")
        client.end()

        // LATER: emit an Event object
        authenticated &&
          emitter.emit("logoff", {
            username,
            clientInfo,
            openSessions: clientSessions.size - 1,
          })
      })
    }

    clientSessions.add(client)
    client.respond("220", "Welcome")
    debug(`established FTP connection`)

    // setup session
    let authenticated = false,
      permissions: Permissions,
      username = "nobody"

    // implement passive data server as an async iterator for incoming connections (as by Deno)
    let dataPort: TcpSocketConnectOpts | ConnectionSource

    let setFolder: Store["setFolder"],
      getFolder: Store["getFolder"],
      folderDelete: Store["folderDelete"],
      folderCreate: Store["folderCreate"],
      folderList: Store["folderList"],
      fileStats: Store["fileStats"],
      fileDelete: Store["fileDelete"],
      fileRetrieve: Store["fileRetrieve"],
      fileStore: Store["fileStore"],
      fileRename: Store["fileRename"],
      fileSetAttributes: Store["fileSetAttributes"],
      renameFileToFn: Awaited<ReturnType<Store["fileRename"]>>

    let asciiTxfrMode = false,
      pbszReceived = false,
      protectedMode = false,
      dataOffset = 0

    function resetSession() {
      authenticated = false
      permissions = undefined
      username = "nobody"

      asciiTxfrMode = false
      pbszReceived = false
      protectedMode = false
      dataOffset = 0
      ;(dataPort as ConnectionSource)?.close?.()
      dataPort = renameFileToFn = undefined
    }

    function setUser(credential: Credential) {
      authenticated = true
      permissions = Object.fromEntries(
        Object.entries(credential).filter((entry) =>
          entry[0].startsWith("allow")
        )
      ) as Permissions
      ;({ username } = credential)
      ;({
        setFolder,
        getFolder,

        folderDelete,
        folderCreate,
        folderList,

        fileStats,
        fileDelete,
        fileRetrieve,
        fileStore,
        fileRename,
        fileSetAttributes,
      } = storeFactory(credential, client))

      emitter.emit("login", {
        username,
        clientInfo,
        openSessions: clientSessions.size,
      })
    }

    const preAuthMethods = {
        USER(_: string, user: string) {
          resetSession()
          authenticate(client, user)
            .then((user) => {
              setUser(user)
              client.respond("232", "User logged in")
            })
            .catch((loginType) => {
              // password required
              switch (loginType) {
                case LoginType.Anonymous:
                case LoginType.Password:
                default:
                  username = user
                  client.respond("331", `Password required for ${username}`)
                  break
                case LoginType.None:
                  client.respond("530", "Not logged in")
                  break
              }
            })
        },

        PASS(_: string, password: string) {
          authenticate(client, username, password)
            .then((user) => {
              setUser(user)
              client.respond("230", "Logged on")
            })
            .catch(() => {
              client.respond("530", "Username or password incorrect")
              client.end()
            })
        },

        AUTH(_: string, auth: string) {
          switch (auth) {
            case "TLS":
            case "SSL":
              client.respond("234", `Using authentication type ${auth}`)
              resetSession() // reset session variables (User, CWD, Mode, etc.  RFC-4217)

              secureContext.then((secureContext) => {
                client = Object.assign(
                  new TLSSocket(client, {
                    secureContext,
                    isServer: true,
                  }),
                  { respond: client.respond }
                )
                client.on("data", CmdHandler)
                debug(`command connection secured`)
              })
              break
            default:
              client.respond("504", `Unsupported auth type ${auth}`)
          }
        },
      },
      authenticatedMethods = {
        QUIT() {
          client.respond("221", "Goodbye")
          client.end()

          // LATER: emit an Event object
          emitter.emit("logoff", {
            username,
            clientInfo,
            openSessions: clientSessions.size - 1,
          })
        },

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
          } else
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
          opt = opt.toLowerCase()
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
          const [net0, net1, net2, net3, portHi, portLo] = spec.split(","),
            addr = [net0, net1, net2, net3].join("."),
            port = parseInt(portHi, 10) * 256 + parseInt(portLo)
          if (/* addr.match(/\d{1,3}(\.\d{1,3}){3}/) && */ port > 0) {
            if (dataPort instanceof Server) {
              dataPort.close()
            }

            dataPort = { host: addr, port }
            client.respond("200", "Port command successful")
          } else {
            client.respond("501", "Port command failed")
          }
        },

        PASV(cmd: string) {
          if (dataPort instanceof Server) {
            dataPort.close()
          }
          dataPort = undefined

          startPassiveDataServer().then(
            (server) => {
              dataPort = server
              const port = (server.address() as AddressInfo).port
              debug(`listening on ${port} for data connection`)
              client.respond(
                "227",
                format(
                  "Entering passive mode (%s,%d,%d)",
                  client.localAddress
                    .replace(/::ffff:/g, "")
                    .split(".")
                    .join(","),
                  (port / 256) | 0,
                  port % 256
                )
              )
            },
            (error) => {
              SessionErrorHandler(cmd)(error)
              client.respond("501", "Passive command failed")
            }
          )
        },

        EPRT(_: string, spec: string) {
          const addrSpec = spec.split("|"),
            addr = addrSpec[2],
            port = parseInt(addrSpec[3], 10)
          if (
            addrSpec.length === 5 &&
            // addr.match(/\d{1,3}(\.\d{1,3}){3}/) && // skip this check to permit IPv6
            port > 0
          ) {
            if (dataPort instanceof Server) {
              dataPort.close()
            }

            dataPort = { host: addr, port }
            client.respond("200", "Extended Port command successful")
          } else {
            client.respond("501", "Extended port command failed")
          }
        },

        EPSV(cmd: string) {
          if (dataPort instanceof Server) {
            dataPort.close()
          }
          dataPort = undefined

          startPassiveDataServer().then(
            (server) => {
              dataPort = server
              const port = (server.address() as AddressInfo).port
              debug(`listening on ${port} for data connection`)
              client.respond(
                "229",
                format("Entering extended passive mode (|||%d|)", port)
              )
            },
            (error) => {
              SessionErrorHandler(cmd)(error)
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
          client.respond("257", `"${getFolder()}" is current directory`)
        },

        CWD(cmd: string, folder: string) {
          setFolder(folder).then(
            (folder) =>
              client.respond(
                "250",
                `CWD successful. "${folder}" is current directory`
              ),
            (error) => {
              if (
                error.code === StoreErrors.ENOTDIR ||
                error.code === StoreErrors.ENOENT
              ) {
                client.respond("550", "Folder not found")
                return
              }

              SessionErrorHandler(cmd)(error)
              client.respond("530", "CWD not successful")
            }
          )
        },

        RMD(cmd: string, folder: string) {
          if (!permissions.allowFolderDelete || folder === "/") {
            client.respond("550", "Permission denied")
          } else {
            folderDelete(folder).then(
              () => {
                client.respond("250", "Folder deleted successfully")
              },
              (error) => {
                if (
                  error.code === StoreErrors.ENOTDIR ||
                  error.code === StoreErrors.ENOENT
                ) {
                  client.respond("550", "Folder not found")
                  return
                }

                SessionErrorHandler(cmd)(error)
                client.respond("501", "Command failed")
              }
            )
          }
        },

        MKD(cmd: string, folder: string) {
          if (!permissions.allowFolderCreate) {
            client.respond("550", "Permission denied")
          } else {
            folderCreate(folder).then(
              () => {
                client.respond("250", "Folder created successfully")
              },
              (error) => {
                if (error.code == StoreErrors.EEXIST) {
                  client.respond("550", "Folder exists")
                  return
                }

                SessionErrorHandler(cmd)(error)
                client.respond("501", "Command failed")
              }
            )
          }
        },

        LIST(cmd: string, folder: string) {
          Promise.all([getDataSocket(), folderList(folder)]).then(
            ([socket, stats]) => {
              const listing = stats.map(formatListing(cmd)).join("\r\n")
              debug(`LIST response on data channel\r\n${listing || "(empty)"}`)
              socket.end(listing + "\r\n") // FileZilla has a cow, "TLS connection was non-properly terminated" some half-open problem?
              client.respond(
                "226",
                `Successfully transferred "${path.resolve(
                  getFolder(),
                  folder ?? ""
                )}"`
              )
            },
            (error) => {
              SessionErrorHandler(cmd)(error)
              client.respond("501", `Command failed`)
            }
          )
        },

        DELE(cmd: string, file: string) {
          if (!permissions.allowFileDelete) {
            client.respond("550", "Permission denied")
          } else {
            fileDelete(file).then(
              () => {
                client.respond("250", "File deleted successfully")
              },
              (error) => {
                if (error.code === StoreErrors.ENOENT) {
                  client.respond("550", "File not found")
                  return
                }

                SessionErrorHandler(cmd)(error)
                client.respond("501", "Command failed")
              }
            )
          }
        },

        SIZE(cmd: string, file: string) {
          fileStats(file).then(
            (fstat) => {
              switch (cmd) {
                case "SIZE":
                  client.respond("213", fstat.size.toString())
                  return
                case "MDTM":
                  client.respond("213", format_rfc3659_time(fstat.mtime))
                  return
              }
            },
            (error) => {
              if (error.code === StoreErrors.ENOENT) {
                client.respond("550", "File not found")
                return
              }

              SessionErrorHandler(cmd)(error)
              client.respond("501", "Command failed")
            }
          )
        },

        RETR(cmd: string, file: string) {
          if (!permissions.allowFileRetrieve) {
            client.respond("550", `Transfer failed "${file}"`)
            // Could client connecton be waiting on passive port?
          } else {
            getDataSocket().then(
              (writeSocket: Writable) =>
                fileRetrieve(file, dataOffset)
                  .then(
                    (readStream) => {
                      readStream.on("error", (error: NodeJS.ErrnoException) => {
                        writeSocket.destroy()
                        SessionErrorHandler(cmd)(error)
                        if (error.code === StoreErrors.ENOENT) {
                          client.respond("550", "File not found")
                          return
                        }

                        client.respond("550", `Transfer failed "${file}"`)
                      })

                      writeSocket
                        .on("error", (error) => {
                          readStream.destroy()
                          SessionErrorHandler(cmd)(error)
                          client.respond(
                            "426",
                            `Connection closed. Aborted transfer of "${file}"`
                          )
                        })
                        .on("end", () => {
                          client.respond(
                            "226",
                            `Successfully transferred "${file}"`
                          )

                          // LATER: emit an Event object
                          emitter.emit("download", {
                            username,
                            clientInfo,
                            file: path.join(getFolder(), file),
                          })
                        })

                      readStream
                        // .pipe(tee(emitDebugMessage)) // log outbound stream
                        .pipe(
                          asciiTxfrMode
                            ? asciify().pipe(writeSocket)
                            : writeSocket
                        )
                    },
                    (error) => {
                      writeSocket.destroy()
                      SessionErrorHandler(cmd)(error)
                      client.respond("501", "Command failed")
                    }
                  )
                  .finally(() => {
                    dataOffset = 0
                  }),
              (error: NodeJS.ErrnoException) => {
                SessionErrorHandler(cmd)(error)
                client.respond("501", "Command failed")
              }
            )
          }
        },

        STOR(cmd: string, file: string) {
          if (!permissions.allowFileOverwrite && !permissions.allowFileCreate) {
            client.respond("550", `Transfer failed "${file}"`)
            // Could client connecton be waiting on passive port?
          } else {
            // but what if allowFileOverwrite, but not allowFileCreate?
            getDataSocket().then(
              (readSocket: Readable) =>
                fileStore(file, permissions.allowFileOverwrite, dataOffset)
                  .then(
                    (writeStream) => {
                      readSocket.on("error", (error: NodeJS.ErrnoException) => {
                        writeStream.destroy()
                        SessionErrorHandler(cmd)(error)
                        client.respond(
                          "426",
                          `Connection closed. Aborted transfer of "${file}"`
                        )
                      })

                      writeStream
                        .on("error", (error: NodeJS.ErrnoException) => {
                          readSocket.destroy()
                          SessionErrorHandler(cmd)(error)
                          if (error.code === StoreErrors.EEXIST) {
                            client.respond("550", "File already exists")
                            return
                          }

                          client.respond("550", `Transfer failed "${file}"`)
                        })
                        .on("finish", (error: NodeJS.ErrnoException) => {
                          client.respond(
                            "226",
                            `Successfully transferred "${file}"`
                          )

                          // LATER: emit an Event object
                          emitter.emit("upload", {
                            username,
                            clientInfo,
                            file: path.join(getFolder(), file),
                          })
                        })

                      readSocket
                        // .pipe(tee(emitDebugMessage)) // log inbound stream
                        .pipe(
                          asciiTxfrMode
                            ? deasciify().pipe(writeStream)
                            : writeStream
                        )
                    },
                    (error) => {
                      readSocket.destroy()
                      SessionErrorHandler(cmd)(error)
                      client.respond("501", `Transfer failed "${file}"`)
                    }
                  )
                  .finally(() => {
                    dataOffset = 0
                  }),
              (error: NodeJS.ErrnoException) => {
                SessionErrorHandler(cmd)(error)
                client.respond("501", "Command failed")
              }
            )
          }
        },

        RNFR(_: string, file: string) {
          if (!permissions.allowFileRename) {
            client.respond("550", "Permission denied")
          } else {
            fileRename(file).then(
              (renamingFunction) => {
                renameFileToFn = renamingFunction
                client.respond("350", "File exists")
              },
              () => {
                client.respond("550", "File does not exist")
              }
            )
          }
        },

        RNTO(cmd: string, file: string) {
          if (!permissions.allowFileRename) {
            client.respond("550", "Permission denied")
          } else if (!renameFileToFn) {
            client.respond("503", "RNFR missing")
          } else {
            renameFileToFn(file, permissions.allowFileOverwrite)
              .then(
                () => {
                  client.respond("250", "File renamed successfully")

                  // LATER: emit an Event object
                  emitter.emit("rename", {
                    username,
                    clientInfo,
                    fileFrom: path.join("/", renameFileToFn.fromFile),
                    fileTo: path.join(getFolder(), file),
                  })
                },
                (error) => {
                  if (error.code === StoreErrors.EEXIST) {
                    client.respond("550", "File already exists")
                    return
                  }

                  SessionErrorHandler(cmd)(error)
                  client.respond("550", "File rename failed")
                }
              )
              .finally(() => {
                renameFileToFn = undefined
              })
          }
        },

        MFMT(cmd: string, time: string, file: string) {
          const mtime = parse_rfc3659_time(time)
          fileSetAttributes(file, { mtime }).then(
            () => {
              client.respond("253", "Date/time changed okay")
            },
            (error) => {
              if (error.code === StoreErrors.ENOENT) {
                client.respond("550", "File does not exist")
                return
              }

              SessionErrorHandler(cmd)(error)
              client.respond("501", "Command failed")
            }
          )
        },
      }
    Object.assign(authenticatedMethods, {
      RMDA: authenticatedMethods.RMD,
      MLSD: authenticatedMethods.LIST,
      NLST: authenticatedMethods.LIST,
      MDTM: authenticatedMethods.SIZE,
    })

    // unimplemented:
    //  SPSV, LPSV, LPRT
    //  MLST (like MDTM and SIZE?)
    //  MFCT, MFF (like MFMT)
    //  ABOR, ACCT, NOOP, REIN, STAT
    //  APPE, CDUP, SMNT, STOU

    function startPassiveDataServer() {
      const addr = "0.0.0.0" // Server binds to default address, 0.0.0.0 or ipv6 ::

      return new Promise<number>((resolve, reject) => {
        // 'maxConnections' is the size of a block of ports for incoming data connections
        // TODO: avoid port scanning
        // TODO: if TCP and TLS ports are both listening, may need double maxConnections?
        // TODO: if minDataPort is not set, ignore maxConnections & just listen on a random port
        if (minDataPort > 0 && minDataPort < 65535) {
          return (function checkAvailablePort(port: number) {
            createServer()
              .once("close", function () {
                resolve(port)
              })
              .once("error", function () {
                if (port < minDataPort + maxConnections) {
                  return checkAvailablePort(++port) // recurse
                }
                reject(Error("exceeded maxConnections"))
              })
              .listen(port, function () {
                this.close()
              })
          })(minDataPort)
        }

        reject(Error("minDataPort out-of-range 1-65535"))
      }).then(async (port) => {
        debug(
          `starting passive data server addr[${addr}] port[${port}] secure[${
            "encrypted" in client && protectedMode
          }]`
        )

        const dataPort =
          "encrypted" in client && protectedMode
            ? createSecureServer(await secureOptions, function () {
                debug(`secure passive data connection established`)
                this.on(
                  "error",
                  SessionErrorHandler("secure passive data connection")
                ).on("close", () => {
                  debug(`secure passive data connection has closed`)
                })
              })
            : createServer(function () {
                debug(`passive data connection established`)
                this.on(
                  "error",
                  SessionErrorHandler("passive data connection")
                ).on("close", () => {
                  debug(`passive data connection has closed`)
                })
              })

        dataPort.maxConnections = 1
        if (dataTimeout ?? timeout) {
          dataPort.on("connection", (socket) => {
            socket.setTimeout(dataTimeout ?? timeout, () => {
              socket.destroy()
            })
          })
        }

        // TODO: close server if no connection made within a reasonable time

        // resolve the connection source when the server is successfully listening
        return new Promise<ConnectionSource>((resolve, reject) => {
          createConnectionSource(dataPort)
            .on("error", reject)
            .listen(port, function () {
              debug(`passive data port listening`)
              this.off("error", reject).on(
                "error",
                SessionErrorHandler("passive data port")
              )
              resolve(this)
            })
        })
      })
    }

    function getDataSocket() {
      if (dataPort instanceof Server) {
        client.respond("150", "Awaiting passive connection")
        return dataPort.next().then(({ value: socket, done }) => {
          if (done) {
            // the iterator is closed (due to error on listening port)
            throw new Error("passive data port closed")
          }

          return socket
        })
      }

      if (dataPort instanceof Object) {
        client.respond("150", "Opening data connection")

        // resolve a successful connection
        return new Promise<Socket>((resolve, reject) => {
          const { host: addr, port } = dataPort as TcpSocketConnectOpts
          debug(
            `connecting client data socket addr[${addr}] port[${port}] secure[${
              "encrypted" in client && protectedMode
            }]`
          )

          const socket = connect(dataPort as TcpSocketConnectOpts, function () {
            debug(`active data connection to client established`)
            this.off("error", reject)

            if ("encrypted" in client && protectedMode) {
              secureContext.then((secureContext) => {
                const socket = new TLSSocket(this, {
                  secureContext,
                  isServer: true,
                })

                // assume TLS negotiation is synchronous with constructor
                debug(`secure active data connection established`)
                resolve(socket)
              }, reject)
            } else {
              resolve(this)
            }
          }).on("error", reject)
        }).then((socket) => {
          if (dataTimeout ?? timeout) {
            socket.setTimeout(dataTimeout ?? timeout, () => {
              socket.destroy()
            })
          }

          return socket
            .on("error", SessionErrorHandler("active data connection"))
            .on("close", () => {
              debug(`active data connection has closed`)
            })
        })
      }

      return Promise.reject(Error("active or passive mode not selected"))
    }

    function CmdHandler(buf: Buffer) {
      const data = buf.toString(),
        [cmd, ...args] = data.trim().split(/\s+/)
      log(`>>> cmd[${cmd}] arg[${cmd === "PASS" ? "***" : args.join(" ")}]`)

      try {
        if (cmd in authenticatedMethods) {
          if (authenticated) {
            authenticatedMethods[cmd as keyof typeof authenticatedMethods].call(
              this,
              cmd,
              ...args
            )
          } else {
            client.respond("530", "Not logged in")
            client.end()
          }
        } else if (cmd in preAuthMethods) {
          preAuthMethods[cmd as keyof typeof preAuthMethods].call(
            this,
            cmd,
            ...args
          )
        } else {
          client.respond("500", "Command not implemented")
        }
      } catch (err) {
        client.respond("550", "Unexpected server error")
        SessionErrorHandler(`command exception[${[cmd, ...args].join(" ")}]`)(
          err
        )
      }
    }

    function SessionErrorHandler(socketType: string) {
      return function error(error: NodeJS.ErrnoException) {
        // LATER: emit an Event object
        emitter.emit(
          "warn", // don't say "error" -- Jest somehow detects "error" events that don't have a handler
          `${new Date().toISOString()} ${clientInfo}-${socketType} error ${inspect(
            error,
            {
              showHidden: false,
              depth: null,
              breakLength: Infinity,
            }
          )}`
        )
      }
    }

    function log(msg: string | { toString: () => string }) {
      // LATER: emit an Event object
      emitter.emit("log", `${new Date().toISOString()} ${clientInfo} ${msg}`)
    }

    function debug(msg: string | { toString: () => string }) {
      // LATER: emit an Event object
      emitter.emit("debug", `${new Date().toISOString()} ${clientInfo} ${msg}`)
    }
  }

  function ErrorHandler(error: NodeJS.ErrnoException) {
    // LATER: emit an Event object
    emitter.emit(
      "error",
      `server error ${new Date().toISOString()} ${inspect(error, {
        showHidden: false,
        depth: null,
        breakLength: Infinity,
      })}`
    )
  }

  // setup FTP, FTPS servers
  let tcpServer: Server, tlsServer: Server
  if (server) {
    server.on("connection", FtpSessionHandler)
  } else {
    if (port) {
      tcpServer = createServer(FtpSessionHandler).on("error", ErrorHandler)

      tcpServer.maxConnections = maxConnections
      tcpServer.listen(port, function () {
        // LATER: emit an Event object
        emitter.emit("listen", {
          protocol: "tcp",
          ...(this.address() as AddressInfo),
          basefolder: localStoreFactory.basefolder,
        })
      })
    }

    if (securePort) {
      secureOptions.then((secureOptions) => {
        tlsServer = createSecureServer(secureOptions, FtpSessionHandler).on(
          "error",
          ErrorHandler
        )

        tlsServer.maxConnections = maxConnections
        tlsServer.listen(securePort, function () {
          // LATER: emit an Event object
          emitter.emit("listen", {
            protocol: "tls",
            ...(this.address() as AddressInfo),
            basefolder: localStoreFactory.basefolder,
          })
        })
      })
    }
  }

  return Object.assign(emitter, {
    close() {
      for (const session of clientSessions) {
        session.destroy()
      }

      tcpServer && tcpServer.close()
      tlsServer && tlsServer.close()

      localStoreFactory.cleanup?.()
    },

    reloadAuth(authOptions: AuthOptions) {
      authenticate = authFactory(authOptions)
    },
  })
}
