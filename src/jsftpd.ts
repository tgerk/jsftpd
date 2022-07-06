/* eslint-disable @typescript-eslint/no-unused-vars */
/*
 * @package jsftpd
 * @author Sven <mailsvb@gmail.com>
 * @author Tim Gerk <tjgerk@gmail.com>
 * @license https://github.com/mailsvb/jsftpd/blob/main/LICENSE MIT License
 */

import {
  Server,
  Socket,
  AddressInfo,
  createServer,
  connect,
  ListenOptions,
  TcpSocketConnectOpts,
} from "net"
import {
  SecureContextOptions,
  TLSSocket,
  createServer as createSecureServer,
  createSecureContext,
} from "tls"
import util from "util"
import path from "path"
import { Readable, Writable } from "stream"
import { EventEmitter } from "events"

import { deasciify, asciify } from "./util/ascii.js"

import internalAuth, {
  AuthHandlersFactory,
  AuthOptions,
  LoginType,
  Permissions,
  Credential,
} from "./auth.js"

import localBackend, {
  StoreFactory,
  Store,
  Stats,
  Errors as StoreErrors,
  AbsolutePath,
} from "./store.js"

export type ComposableAuthHandlerFactory = (
  factory: AuthHandlersFactory
) => AuthHandlersFactory

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
  auth?: ComposableAuthHandlerFactory
  store?: ComposableStoreFactory | ComposableStoreFactory[]
} & AuthOptions
export type FtpServer = ReturnType<typeof createFtpServer>

interface FTPCommandTable {
  [fn: string]: (cmd: string, ...args: string[]) => void
}

// note vague resemblance to an async iterator
type ConnectionSource = Server & {
  nextConnection: () => Promise<Socket>
}

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

  // compose auth and storage backend handler factories
  const authFactory = auth?.(internalAuth) ?? internalAuth
  let { userLoginType, userAuthenticate } = authFactory(authOptions)

  const localStoreFactory = localBackend(basefolder)
  let storeFactory: StoreFactory
  if (store instanceof Array) {
    storeFactory = store.reduce((y, f) => f(y), localStoreFactory)
  } else if (store) {
    storeFactory = store(localStoreFactory)
  } else {
    storeFactory = localStoreFactory
  }

  // need to always prepare TLS certs and secure context,
  //  because we implement FTPS (via AUTH TLS, like STARTTLS),
  //  even if not necessarily SFTP(default port 990)
  const secureOptions = new Promise<SecureContextOptions>((resolve) => {
      tlsOptions = {
        honorCipherOrder: true,
        // rejectUnauthorized: false, // enforce CA trust
        ...tlsOptions,
      }
      if (
        "pfx" in tlsOptions ||
        ("key" in tlsOptions && "cert" in tlsOptions)
      ) {
        resolve(tlsOptions)
        return
      }

      // generate self-signed certificate
      import("./tls/index.js").then((options) =>
        resolve({ ...tlsOptions, ...options })
      )
    }),
    secureContext = secureOptions.then(createSecureContext)

  // setup FTP, FTPS servers
  let tcpServer: Server, tlsServer: Server
  if (server) {
    server.on("connection", FtpSessionHandler)
  } else {
    if (port) {
      tcpServer = createServer(FtpSessionHandler)

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

  const emitter = new EventEmitter()
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
      ;({ userLoginType, userAuthenticate } = authFactory(authOptions))
    },

    FtpSessionHandler,
  })

  function FtpSessionHandler(cmdSocket: Socket) {
    // setup client session
    let username = "nobody",
      authenticated = false,
      permissions: Permissions

    let asciiTxfrMode = false,
      pbszReceived = false,
      protectedMode = false,
      dataOffset = 0

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
      fileSetTimes: Store["fileSetTimes"]

    let dataPort: TcpSocketConnectOpts | ConnectionSource,
      renameFileToFn: Awaited<ReturnType<Store["fileRename"]>>

    clientSessions.add(cmdSocket)

    cmdSocket
      .on("error", SessionErrorHandler("command socket"))
      .on("close", function () {
        clientSessions.delete(this)
        if (dataPort instanceof Server) {
          dataPort.close()
        }
        emitDebugMessage(`FTP connection closed`)
      })
      .on("data", CmdHandler)

    if (timeout) {
      cmdSocket.setTimeout(timeout, () => {
        client.respond("221", "Goodbye")
        cmdSocket.end()

        // LATER: emit an Event object
        authenticated &&
          emitter.emit("logoff", {
            username,
            clientInfo,
            openSessions: clientSessions.size - 1,
          })
      })
    }

    const clientInfo = `[(${++clientCounter}) ${
      cmdSocket.remoteAddress?.replace(/::ffff:/g, "") ?? "unknown"
    }:${cmdSocket.remotePort}]`

    let client = Object.assign(cmdSocket, {
      respond: function respond(
        this: Socket,
        code: string,
        message: string,
        delimiter = " "
      ) {
        emitLogMessage(`<<< ${code} ${message}`)
        this.write(`${code}${delimiter}${message}\r\n`)
      },
    })

    emitDebugMessage(`established FTP connection`)
    client.respond("220", "Welcome")

    const preAuthMethods: FTPCommandTable = {
      /*
       *  USER
       */
      USER: function (cmd: string, user: string) {
        authenticated = false
        switch (
          userLoginType(client, user, (user) => {
            setUser(user)
            client.respond("232", "User logged in")
          })
        ) {
          case LoginType.Anonymous:
          case LoginType.Password:
            username = user
            client.respond("331", `Password required for ${username}`)
            break
          case LoginType.NoPassword:
            break
          case LoginType.None:
          default:
            client.respond("530", "Not logged in")
            break
        }
      },

      /*
       *  PASS
       */
      PASS: function (cmd: string, password: string) {
        switch (
          userAuthenticate(client, username, password, (credential) => {
            setUser(credential)
            client.respond("230", "Logged on")
          })
        ) {
          case LoginType.Anonymous:
          case LoginType.Password:
          case LoginType.NoPassword:
            break
          case LoginType.None:
          default:
            client.respond("530", "Username or password incorrect")
            client.end()
        }
      },

      /*
       *  AUTH (upgrade command socket security)
       */
      AUTH: function (cmd: string, auth: string) {
        switch (auth) {
          case "TLS":
          case "SSL":
            client.respond("234", `Using authentication type ${auth}`)
            resetSession() // reset session variables (User, CWD, Mode, etc.  RFC-4217)

            // Start TLS
            secureContext.then((secureContext) => {
              client = Object.assign(
                new TLSSocket(client, {
                  secureContext,
                  isServer: true,
                }),
                { respond: client.respond }
              )
              client.on("data", CmdHandler)
              emitDebugMessage(`command connection secured`)
            })
            break
          default:
            client.respond("504", `Unsupported auth type ${auth}`)
        }
      },
    }

    const authenticatedMethods: FTPCommandTable = {
      /*
       *  QUIT
       */
      QUIT: function () {
        client.respond("221", "Goodbye")
        client.end()

        // LATER: emit an Event object
        emitter.emit("logoff", {
          username,
          clientInfo,
          openSessions: clientSessions.size - 1,
        })
      },

      /*
       *  CLNT
       */
      CLNT: function () {
        client.respond("200", "Don't care")
      },

      /*
       *  PBSZ (set protection buffer size, irrelevant to SSL private mode)
       */
      PBSZ: function (cmd: string, size: string) {
        pbszReceived = true
        client.respond("200", `PBSZ=${size}`)
      },

      /*
       *  PROT
       */
      PROT: function (cmd: string, protection: string) {
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

      /*
       *  OPTS
       */
      OPTS: function (cmd: string, opt: string, value: string) {
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

      /*
       *  FEAT
       */
      FEAT: function () {
        const features = Object.keys(preAuthMethods)
          .concat(Object.keys(authenticatedMethods))
          .join("\r\n ")
          .replace("AUTH", "AUTH TLS\r\n AUTH SSL")
        client.respond("211", `Features:\r\n ${features}\r\n211 End`, "-")
      },

      /*
       *  PORT
       */
      PORT: function (cmd: string, spec: string) {
        const [net0, net1, net2, net3, portHi, portLo] = spec.split(","),
          addr = [net0, net1, net2, net3].join("."),
          port = parseInt(portHi, 10) * 256 + parseInt(portLo)
        if (addr.match(/\d{1,3}(\.\d{1,3}){3}/) && port > 0) {
          if (dataPort instanceof Server) {
            dataPort.close()
          }

          dataPort = { host: addr, port }
          client.respond("200", "Port command successful")
        } else {
          client.respond("501", "Port command failed")
        }
      },

      /*
       *  PASV
       */
      PASV: function (cmd: string) {
        if (dataPort instanceof Server) {
          dataPort.close()
        }
        dataPort = undefined

        startDataServer().then(
          (server) => {
            dataPort = server
            const port = (server.address() as AddressInfo).port
            emitDebugMessage(`listening on ${port} for data connection`)
            client.respond(
              "227",
              util.format(
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

      /*
       *  EPRT
       */
      EPRT: function (cmd: string, spec: string) {
        const addrSpec = spec.split("|"),
          addr = addrSpec[2],
          port = parseInt(addrSpec[3], 10)
        if (
          addrSpec.length === 5 &&
          addr.match(/\d{1,3}(\.\d{1,3}){3}/) &&
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

      /*
       *  EPSV
       */
      EPSV: function (cmd: string) {
        if (dataPort instanceof Server) {
          dataPort.close()
        }
        dataPort = undefined

        startDataServer().then(
          (server) => {
            dataPort = server
            const port = (server.address() as AddressInfo).port
            emitDebugMessage(`listening on ${port} for data connection`)
            client.respond(
              "229",
              util.format("Entering extended passive mode (|||%d|)", port)
            )
          },
          (error) => {
            SessionErrorHandler(cmd)(error)
            client.respond("501", "Extended passive command failed")
          }
        )
      },

      /*
       *  SYST
       */
      SYST: function () {
        client.respond("215", process.env["OS"] ?? "UNIX")
      },

      /*
       *  TYPE
       */
      TYPE: function (cmd: string, tfrType: string) {
        if (tfrType === "A") {
          asciiTxfrMode = true
          client.respond("200", "Type set to ASCII")
        } else {
          asciiTxfrMode = false
          client.respond("200", "Type set to BINARY")
        }
      },

      /*
       *  REST
       */
      REST: function (cmd: string, arg: string) {
        const offset = parseInt(arg, 10)
        if (offset >= 0) {
          dataOffset = offset
          client.respond("350", `Restarting at ${dataOffset}`)
        } else {
          dataOffset = 0
          client.respond("550", "Wrong restart offset")
        }
      },

      /*
       *  PWD
       */
      PWD: function () {
        client.respond("257", `"${getFolder()}" is current directory`)
      },

      /*
       *  CWD
       */
      CWD: function (cmd: string, folder: string) {
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

      /*
       *  RMD
       *  RMDA
       */
      RMD: function (cmd: string, folder: string) {
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

      /*
       *  MKD
       */
      MKD: function (cmd: string, folder: string) {
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

      /*
       *  LIST
       *  MLSD
       *  NLST
       */
      LIST: function (format: string, folder: string) {
        openDataSocket().then(
          (socket: Writable) =>
            folderList(folder).then(
              (stats) => {
                const listing = stats.map(formatListing(format)).join("\r\n")
                emitDebugMessage(
                  `LIST response on data channel\r\n${listing || "(empty)"}`
                )
                socket.end(listing + "\r\n")
                client.respond(
                  "226",
                  `Successfully transferred "${getFolder()}"`
                )
              },
              (error) => {
                socket.end()
                SessionErrorHandler(format)(error)
                client.respond("501", `Command failed`)
              }
            ),
          (error: NodeJS.ErrnoException) => {
            SessionErrorHandler(format)(error)
            client.respond("501", "Command failed")
          }
        )
      },

      /*
       *  DELE
       */
      DELE: function (cmd: string, file: string) {
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

      /*
       *  SIZE
       */
      SIZE: function (cmd: string, file: string) {
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

      /*
       *  RETR
       */
      RETR: function (cmd: string, file: string) {
        if (!permissions.allowFileRetrieve) {
          client.respond("550", `Transfer failed "${file}"`)
          // Could client connecton be waiting on passive port?
        } else {
          openDataSocket().then(
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

      /*
       *  STOR
       */
      STOR: function (cmd: string, file: string) {
        if (!permissions.allowFileOverwrite && !permissions.allowFileCreate) {
          client.respond("550", `Transfer failed "${file}"`)
          // Could client connecton be waiting on passive port?
        } else {
          // but what if allowFileOverwrite, but not allowFileCreate?
          openDataSocket().then(
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

      /*
       *  RNFR
       */
      RNFR: function (cmd: string, file: string) {
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

      /*
       *  RNTO
       */
      RNTO: function (cmd: string, file: string) {
        if (!permissions.allowFileRename) {
          client.respond("550", "Permission denied")
        } else if (!renameFileToFn) {
          client.respond("503", "RNFR missing")
        } else {
          renameFileToFn(file)
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

      /*
       *  MFMT
       */
      MFMT: function (cmd: string, time: string, file: string) {
        const mtime = parse_rfc3659_time(time)
        fileSetTimes(file, mtime).then(
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

    // LATER?:
    // SPSV, LPSV, LPRT
    // MLST (like MDTM and SIZE?)
    // MFCT, MFF (like MFMT)
    // ABOR, ACCT, NOOP, REIN, STAT
    // APPE, CDUP, SMNT, STOU

    authenticatedMethods.RMDA = authenticatedMethods.RMD
    authenticatedMethods.MLSD = authenticatedMethods.NLST =
      authenticatedMethods.LIST
    authenticatedMethods.MDTM = authenticatedMethods.SIZE

    function resetSession() {
      if (dataPort instanceof Server) {
        dataPort.close()
      }
      dataPort = undefined

      username = "nobody"
      authenticated = false

      asciiTxfrMode = false
      pbszReceived = false
      protectedMode = false
      permissions = renameFileToFn = undefined
      dataOffset = 0
    }

    function setUser(credential: Credential) {
      resetSession()
      ;({ username } = credential)
      authenticated = true
      permissions = Object.fromEntries(
        Object.entries(credential).filter((entry) =>
          entry[0].startsWith("allow")
        )
      ) as Permissions
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
        fileSetTimes,
      } = storeFactory(credential, client))

      emitter.emit("login", {
        username,
        clientInfo,
        openSessions: clientSessions.size,
      })
    }

    function startDataServer() {
      return new Promise<number>((resolve, reject) => {
        // TODO: avoid port scanning & if minDataPort is not set, just listen on a random port?
        // 'maxConnections' is the size of a block of ports for incoming data connections
        //  (consider non-stateful firewalls)
        // if TCP and TLS ports are both listening, may need double maxConnections?
        if (minDataPort > 0 && minDataPort < 65535) {
          return (function checkAvailablePort(port: number) {
            createServer()
              .once("error", function () {
                if (port < minDataPort + maxConnections) {
                  return checkAvailablePort(++port) // recurse
                }
                reject(Error("exceeded maxConnections"))
              })
              .once("close", function () {
                resolve(port)
              })
              .listen(port, function () {
                this.close()
              })
          })(minDataPort)
        }

        reject(Error("minDataPort out-of-range 1-65535"))
      }).then(async (port) => {
        const dataPort = Object.assign(
          "encrypted" in client && protectedMode
            ? createSecureServer(await secureOptions, DataHandler)
            : createServer(DataHandler),
          {
            _connectionQueue: [],
            _resolveNext: undefined,
            initConnection() {
              this._connectionQueue.push(
                new Promise<Socket>((resolve) => {
                  this._resolveNext = resolve
                })
              )
              return this
            },
            resolveConnection(socket?: Socket) {
              this._resolveNext(socket)
              this.initConnection()
            },
            nextConnection() {
              return this._connectionQueue.shift()
            },
          }
        ).initConnection() as ConnectionSource

        if (dataTimeout ?? timeout) {
          dataPort.on("connection", (socket) => {
            socket.setTimeout(dataTimeout ?? timeout, () => {
              socket.destroy()
            })
          })
        }

        dataPort.maxConnections = 1
        return new Promise<ConnectionSource>((resolve, reject) => {
          dataPort.once("error", reject)
          dataPort.listen(port, function () {
            this.off("error", reject)
            this.on("error", SessionErrorHandler("passive data port"))
            resolve(this)
          })
        })

        function DataHandler(socket: Socket) {
          emitDebugMessage(`data connection established`)
          socket.on("error", SessionErrorHandler("passive data connection"))
          socket.on("close", () => {
            emitDebugMessage(`data connection has closed`)
          })

          this.resolveConnection(socket)
        }
      })
    }

    function openDataSocket() {
      if (dataPort instanceof Server) {
        client.respond("150", "Awaiting passive connection")

        // TODO: reject if port is not accepting connections
        // TODO: reject if no connection within a reasonable time
        // cross fingers the client stays in sync!
        return dataPort.nextConnection()
      }

      if (dataPort instanceof Object) {
        client.respond("150", "Opening data connection")
        return new Promise((resolve, reject) => {
          const { host: addr, port } = dataPort as TcpSocketConnectOpts
          emitDebugMessage(
            `client data socket addr[${addr}] port[${port}] secure[${
              "encrypted" in client && protectedMode
            }]`
          )
          let socket = connect(dataPort as TcpSocketConnectOpts, async () => {
            emitDebugMessage(`data connection established`)
            if ("encrypted" in client && protectedMode) {
              // connect FTPS and SFTP clients the same, negotiate TLS after
              //  socket connection, i.e. it's exactly like tls.connect()
              socket = new TLSSocket(socket, {
                secureContext: await secureContext,
                isServer: true,
              })
                .on("error", reject)
                .on(
                  "error",
                  SessionErrorHandler("secured active data connection")
                )
                .on("close", () => {
                  emitDebugMessage(`secured data connection has closed`)
                })

              emitDebugMessage(`data connection secured`)
            }

            if (dataTimeout ?? timeout) {
              socket.setTimeout(dataTimeout ?? timeout, () => {
                socket.destroy()
              })
            }

            resolve(socket)
          })
            .on("error", reject)
            .on("error", SessionErrorHandler("active data connection"))
            .on("close", () => {
              emitDebugMessage(`data connection has closed`)
            })
        })
      }

      return Promise.reject(Error("active or passive mode not selected"))
    }

    function CmdHandler(buf: Buffer) {
      const data = buf.toString(),
        [cmd, ...args] = data.trim().split(/\s+/)
      emitLogMessage(
        `>>> cmd[${cmd}] arg[${cmd === "PASS" ? "***" : args.join(" ")}]`
      )

      try {
        if (authenticated) {
          if (cmd in authenticatedMethods) {
            authenticatedMethods[cmd as keyof FTPCommandTable](cmd, ...args)
          } else {
            client.respond("500", "Command not implemented")
          }
        } else if (cmd in preAuthMethods) {
          preAuthMethods[cmd as keyof FTPCommandTable](cmd, ...args)
        } else {
          client.respond("530", "Not logged in")
          client.end()
        }
      } catch (err) {
        SessionErrorHandler(
          `exception on command [${[cmd, ...args].join(" ")}]`
        )(err)
        client.respond("550", "Unexpected server error")
      }
    }

    function SessionErrorHandler(socketType: string) {
      return function (error: NodeJS.ErrnoException) {
        // LATER: emit an Event object
        emitter.emit(
          "warn", // don't say "error" -- Jest somehow detects "error" events that don't have a handler
          `${socketType} error ${clientInfo} ${new Date().toISOString()} ${util.inspect(
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

    function emitLogMessage(msg: string | { toString: () => string }) {
      // LATER: emit an Event object
      emitter.emit("log", `${new Date().toISOString()} ${clientInfo} ${msg}`)
    }

    function emitDebugMessage(msg: string | { toString: () => string }) {
      // LATER: emit an Event object
      emitter.emit("debug", `${new Date().toISOString()} ${clientInfo} ${msg}`)
    }
  }

  function ErrorHandler(error: NodeJS.ErrnoException) {
    // LATER: emit an Event object
    emitter.emit(
      "error",
      `server error ${new Date().toISOString()} ${util.inspect(error, {
        showHidden: false,
        depth: null,
        breakLength: Infinity,
      })}`
    )
  }
}

// utilities
function formatListing(format = "LIST") {
  switch (format) {
    case "NLST":
      return ({ name }: Stats) => name
    case "MLSD":
      return (fstat: Stats) =>
        util.format(
          "type=%s;modify=%s;%s %s",
          fstat.isDirectory() ? "dir" : "file",
          format_rfc3659_time(fstat.mtime),
          fstat.isDirectory() ? "" : "size=" + fstat.size.toString() + ";",
          fstat.name
        )
    case "LIST":
    default:
      return (fstat: Stats) =>
        util.format(
          "%s 1 ? ? %s %s %s", // showing link-count = 1, don't expose uid, gid
          fstat.isDirectory() ? "dr--r--r--" : "-r--r--r--",
          String(fstat.isDirectory() ? "0" : fstat.size).padStart(14, " "),
          formatDate_Mmm_DD_HH_mm(fstat.mtime),
          fstat.name
        )
  }
}

function formatDate_Mmm_DD_HH_mm(mtime: Date): string {
  mtime = new Date(mtime)
  return mtime.toLocaleString([], {
    month: "short",
    day: "numeric",
    hour12: false,
    hour: "numeric",
    minute: "2-digit",
  })
}

function format_rfc3659_time(mtime: Date): string {
  mtime = new Date(mtime)
  const MM = (mtime.getMonth() + 1).toString().padStart(2, "0"),
    DD = mtime.getDate().toString().padStart(2, "0"),
    H = mtime.getHours().toString().padStart(2, "0"),
    M = mtime.getMinutes().toString().padStart(2, "0"),
    S = mtime.getSeconds().toString().padStart(2, "0"),
    s = mtime.getMilliseconds().toString().padStart(3, "0")
  return `${mtime.getFullYear()}${MM}${DD}${H}${M}${S}.${s}`
}

function parse_rfc3659_time(rfc3659_time: string): Date {
  const Y = rfc3659_time.substring(0, 4),
    M = rfc3659_time.substring(4, 6),
    D = rfc3659_time.substring(6, 8),
    Hrs = rfc3659_time.substring(8, 10),
    Min = rfc3659_time.substring(10, 12),
    Sec = rfc3659_time.substring(12, 14)
  return new Date(`${Y}-${M}-${D}T${Hrs}:${Min}:${Sec}+00:00`)
}
