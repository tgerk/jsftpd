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
  Server as TlsServer,
  TLSSocket,
  createServer as createSecureServer,
  createSecureContext,
} from "tls"
import util from "util"
import path from "path"
import { Readable, Writable } from "stream"
import { EventEmitter } from "events"
import { readFile } from "fs/promises"

import { deasciify, asciify } from "./ascii"
// import { tee } from "./ascii"

import internalAuth, {
  AuthHandlersFactory,
  AuthOptions,
  LoginType,
  Permissions,
  Credential,
} from "./auth"

import localStore, {
  getBaseFolder as getLocalStoreBaseFolder,
  cleanup as cleanupLocalStore,
  StoreFactory,
  Store,
  Stats,
  Errors as StoreErrors,
} from "./store"

export type ComposableAuthHandlerFactory = (
  factory: AuthHandlersFactory
) => AuthHandlersFactory

export type ComposableStoreFactory = (factory: StoreFactory) => StoreFactory

export type ServerOptions = {
  port?: number | ListenOptions
  securePort?: number
  minDataPort?: number
  maxConnections?: number
  timeout?: number
  dataTimeout?: number
  // overlooks misc options for TLS servers and TLS client/server sockets, e.g. session resume, OCSP, pre-shared keys
  tls?: SecureContextOptions // excludes CommonConnectionOptions, e.g. client certificates and SNI
  auth?: ComposableAuthHandlerFactory
  store?: ComposableStoreFactory
}
interface FTPCommandTable {
  [fn: string]: (cmd: string, arg: string) => void
}

type IncomingConnectionSource = Server & { connectionQueue: Promise<Socket>[] }

export async function createFtpServer({
  tls: tlsOptions,
  auth,
  store,
  basefolder,
  ...options
}: ServerOptions & AuthOptions = {}) {
  options = {
    port: 21,
    minDataPort: 1024,
    maxConnections: 10,
    ...options,
  }

  tlsOptions = {
    honorCipherOrder: true,
    // rejectUnauthorized: false, // enforce CA trust
    ...tlsOptions,
  }

  if (!("key" in tlsOptions) || !("cert" in tlsOptions)) {
    // because we implement FTPS (via AUTH TLS), but not necessarily SFTP (default port 990)
    //  use certs module to provide a backup self-signed certificate
    const { cert, key } = await import("./cert")
    tlsOptions.cert = cert
    tlsOptions.key = key
  } else {
    // TODO: expand to support all schemes fs/promises.readFile can handle
    if (tlsOptions.cert.toString().startsWith("file:")) {
      tlsOptions.cert = await readFile(tlsOptions.cert.toString().substring(5))
    }
    if (tlsOptions.key.toString().startsWith("file:")) {
      tlsOptions.key = await readFile(tlsOptions.key.toString().substring(5))
    }
    if (tlsOptions.passphrase.startsWith("file:")) {
      tlsOptions.passphrase = await readFile(
        tlsOptions.passphrase.substring(5)
      ).toString()
    }
  }

  const tlsContext = createSecureContext(tlsOptions),
    useTls = "securePort" in options

  // compose auth and storage backend handler factories
  const authFactory = auth?.(internalAuth) ?? internalAuth
  let { userLoginType, userAuthenticate } = authFactory(options)

  const localStoreFactory = localStore(basefolder),
    storeFactory = store?.(localStoreFactory) ?? localStoreFactory

  // setup FTP on TCP
  const tcpServer = createServer(SessionHandler)

  // setup FTP on TLS
  let tlsServer: TlsServer
  if (useTls) {
    tlsServer = createSecureServer(tlsOptions, SessionHandler)
  }

  // track client sessions
  let clientCounter = 0
  const clientSessions: Set<Socket> = new Set()

  const emitter = new EventEmitter()
  return Object.assign(emitter, {
    start() {
      setupServer(tcpServer)
      tcpServer.listen(options.port, function () {
        emitListenEvent.call(this, "tcp")
      })

      if (useTls) {
        setupServer(tlsServer)
        tlsServer.listen(options.securePort, function () {
          emitListenEvent.call(this, "tls")
        })
      }

      function setupServer(server: Server | TlsServer) {
        // concurrent connections, distinct from the listen backlog
        // (excess connections are immediately closed after connecting)
        server.maxConnections = options.maxConnections
        server.on(
          "error",
          function ServerErrorHandler(err: NodeJS.ErrnoException) {
            emitter.emit(
              "error",
              `server error ${getDateForLogs()} ${util.inspect(err, {
                showHidden: false,
                depth: null,
                breakLength: Infinity,
              })}`
            )
          }
        )
      }

      function emitListenEvent(this: Server, protocol: string) {
        const address = this.address() as AddressInfo
        emitter.emit("listen", {
          protocol,
          ...address,
          basefolder: getLocalStoreBaseFolder(),
        })
      }
    },

    stop() {
      for (const session of clientSessions) {
        session.destroy()
      }

      tcpServer.close()
      useTls && tlsServer.close()
    },

    cleanup() {
      cleanupLocalStore()
    },

    reloadAuth(options: AuthOptions) {
      ;({ userLoginType, userAuthenticate } = authFactory(options))
    },
  })

  function SessionHandler(cmdSocket: Socket | TLSSocket) {
    // setup client
    clientSessions.add(cmdSocket)
    cmdSocket.on("close", function () {
      clientSessions.delete(this)
      emitDebugMessage(`FTP connection closed`)
      if (dataPort instanceof Server) {
        dataPort.close()
      }
    })
    cmdSocket.on("error", SessionErrorHandler("command socket"))
    cmdSocket.on("data", CmdHandler)

    if ("timeout" in options) {
      cmdSocket.setTimeout(options.timeout, () => {
        authenticated && emitLogoffEvent()
        client.respond("221", "Goodbye")
        cmdSocket.end()
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
      fileSize: Store["fileSize"],
      fileDelete: Store["fileDelete"],
      fileRetrieve: Store["fileRetrieve"],
      fileStore: Store["fileStore"],
      fileRename: Store["fileRename"],
      fileSetTimes: Store["fileSetTimes"]

    let dataPort: IncomingConnectionSource | TcpSocketConnectOpts,
      renameFileToFn: Awaited<ReturnType<Store["fileRename"]>>

    emitDebugMessage(`established FTP connection`)
    client.respond("220", "Welcome")

    const preAuthMethods: FTPCommandTable = {
      /*
       *  USER
       */
      USER: function (_cmd: string, user: string) {
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
      PASS: function (_cmd: string, password: string) {
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
      AUTH: function (_cmd: string, auth: string) {
        switch (auth) {
          case "TLS":
          case "SSL":
            client.respond("234", `Using authentication type ${auth}`)
            resetSession() // reset session variables (User, CWD, Mode, etc.  RFC-4217)

            // Start TLS
            client = Object.assign(
              new TLSSocket(client, {
                secureContext: tlsContext,
                isServer: true,
              }),
              { respond: client.respond }
            )
            client.on("data", CmdHandler)
            emitDebugMessage(`command connection secured`)
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
        authenticated && emitLogoffEvent()
        client.respond("221", "Goodbye")
        client.end()
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
      PBSZ: function (_cmd: string, size: string) {
        pbszReceived = true
        client.respond("200", `PBSZ=${size}`)
      },

      /*
       *  PROT
       */
      PROT: function (_cmd: string, protection: string) {
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
      OPTS: function (_cmd: string, opt: string) {
        opt = opt.toLowerCase()
        if (opt === "utf8 on") {
          client.respond("200", "UTF8 ON")
        } else if (opt === "utf8 off") {
          client.respond("200", "UTF8 OFF")
        } else {
          client.respond("451", "Not supported")
        }
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
      PORT: function (_cmd: string, spec: string) {
        const [net0, net1, net2, net3, portHi, portLo] = spec.split(","),
          addr = [net0, net1, net2, net3].join("."),
          port = parseInt(portHi, 10) * 256 + parseInt(portLo)
        if (addr.match(/\d{1,3}(\.\d{1,3}){3}/) && port > 0) {
          setupActiveConnect(addr, port)
          client.respond("200", "Port command successful")
        } else {
          client.respond("501", "Port command failed")
        }
      },

      /*
       *  PASV
       */
      PASV: function (cmd: string) {
        setupPassiveListen().then(
          (port) => {
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
      EPRT: function (_cmd: string, spec: string) {
        const addrSpec = spec.split("|"),
          addr = addrSpec[2],
          port = parseInt(addrSpec[3], 10)
        if (
          addrSpec.length === 5 &&
          addr.match(/\d{1,3}(\.\d{1,3}){3}/) &&
          port > 0
        ) {
          setupActiveConnect(addr, port)
          client.respond("200", "Extended Port command successful")
        } else {
          client.respond("501", "Extended port command failed")
        }
      },

      /*
       *  EPSV
       */
      EPSV: function (cmd: string) {
        setupPassiveListen().then(
          (port) => {
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
      TYPE: function (_cmd: string, tfrType: string) {
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
      REST: function (_cmd: string, arg: string) {
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
       *  SIZE
       */
      SIZE: function (cmd: string, file: string) {
        fileSize(file).then(
          (size) => {
            client.respond("213", size.toString())
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
                        emitDownloadEvent(file)
                        client.respond(
                          "226",
                          `Successfully transferred "${file}"`
                        )
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
                        emitUploadEvent(file)
                        client.respond(
                          "226",
                          `Successfully transferred "${file}"`
                        )
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
      RNFR: function (_cmd: string, file: string) {
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
                emitRenameEvent(renameFileToFn.fromFile, file)
                client.respond("250", "File renamed successfully")
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
      MFMT: function (cmd: string, arg: string) {
        const [time, ...rest] = arg.split(/\s+/),
          mtime = getDateForMFMT(time)
        fileSetTimes(rest.join(" "), mtime).then(
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

    authenticatedMethods.RMDA = authenticatedMethods.RMD
    authenticatedMethods.MLSD = authenticatedMethods.LIST
    authenticatedMethods.NLST = authenticatedMethods.LIST
    authenticatedMethods.MDTM = authenticatedMethods.MFMT

    function resetSession() {
      if (dataPort instanceof Server) {
        dataPort.close()
        dataPort = undefined
      }
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

        fileSize,
        fileDelete,
        fileRetrieve,
        fileStore,
        fileRename,
        fileSetTimes,
      } = storeFactory(credential, client))

      emitLoginEvent()
    }

    function setupPassiveListen() {
      if (dataPort instanceof Server) {
        dataPort.close()
      }

      dataPort = Object.assign(
        "encrypted" in client && protectedMode
          ? createSecureServer(tlsOptions)
          : createServer(),
        {
          connectionQueue: [],
        }
      )

      let resolveNext: (value: Socket | PromiseLike<Socket>) => void
      function resolveConnection(socket?: Socket) {
        resolveNext?.(socket)
        ;(dataPort as IncomingConnectionSource).connectionQueue.push(
          new Promise<Socket>((resolve) => {
            resolveNext = resolve
          })
        )
      }

      dataPort.maxConnections = 1

      dataPort.on("error", SessionErrorHandler("passive data port"))
      if ("dataTimeout" in options || "timeout" in options) {
        dataPort.on("connection", (socket) => {
          socket.setTimeout(options.dataTimeout ?? options.timeout, () => {
            socket.destroy()
          })
        })
      }

      resolveConnection() // initialize
      dataPort.on(
        "addContext" in dataPort ? "secureConnection" : "connection",
        (socket: Socket) => {
          emitDebugMessage(`data connection established`)
          socket.on("error", SessionErrorHandler("passive data connection"))
          socket.on("close", () => {
            emitDebugMessage(`data connection has closed`)
          })

          // to avoid race condition, need to handle connections as they come (not wait for client command to arrive)
          resolveConnection(socket)
        }
      )

      return findAvailablePort().then(
        (port) =>
          new Promise<AddressInfo["port"]>((resolve, reject) => {
            ;(dataPort as Server).once("error", reject)
            ;(dataPort as Server).listen(port, function () {
              resolve(this.address().port)
            })
          })
      )

      /**
       * 'maxConnections' is the size of a block of ports for incoming data connections
       * This is necessary for firewalls that can relate connections to port-range to
       *  the FTP port (TODO:) If minDataPort is not set, NBD: just listen on a random port
       * if TCP and TLS ports are both listening, may need double maxConnections?
       * TODO: this port scanning is an embarrassment:
       *  keep a inc/dec connection count if minDataPort is not specified
       *  else keep list of available ports in a push/pop array
       */
      function findAvailablePort() {
        return new Promise<number>((resolve, reject) => {
          const { minDataPort, maxConnections } = options
          if (minDataPort > 0 && minDataPort < 65535) {
            return checkAvailablePort(minDataPort)
          }
          reject(Error("minDataPort out-of-range 1-65535"))

          function checkAvailablePort(port: number) {
            const server = createServer()
            server.once("close", function () {
              resolve(port)
            })
            server.once("error", function () {
              if (port < minDataPort + maxConnections) {
                return checkAvailablePort(++port) // recurse
              }
              reject(Error("exceeded maxConnections"))
            })

            server.listen(port, function () {
              server.close()
            })
          }
        })
      }
    }

    function setupActiveConnect(host: string, port: number) {
      if (dataPort instanceof Server) {
        dataPort.close()
        dataPort = undefined
      }

      dataPort = { host, port }
    }

    function openDataSocket() {
      if (dataPort instanceof Server) {
        client.respond("150", "Awaiting passive connection")

        // TODO: reject if port is not accepting connections
        // TODO: reject if no connection within a reasonable time

        return dataPort.connectionQueue.shift()
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
          let socket = connect(dataPort as TcpSocketConnectOpts, () => {
            emitDebugMessage(`data connection established`)
            if ("encrypted" in client && protectedMode) {
              socket = new TLSSocket(socket, {
                secureContext: tlsContext,
                isServer: true,
              })
              emitDebugMessage(`data connection secured`)
            }

            if ("dataTimeout" in options || "timeout" in options) {
              socket.setTimeout(options.dataTimeout || options.timeout, () => {
                socket.destroy()
              })
            }

            resolve(socket)
          })

          socket.on("error", SessionErrorHandler("active data connection"))
          socket.on("close", () => {
            emitDebugMessage(`data connection has closed`)
          })
        })
      }

      return Promise.reject(Error("active or passive mode not selected"))
    }

    function emitLogMessage(msg: string | { toString: () => string }) {
      emitter.emit("log", `${getDateForLogs()} ${clientInfo} ${msg}`)
    }

    function emitDebugMessage(msg: string | { toString: () => string }) {
      emitter.emit("debug", `${getDateForLogs()} ${clientInfo} ${msg}`)
    }

    function emitLoginEvent() {
      emitter.emit("login", {
        username,
        clientInfo,
        openSessions: Array.from(clientSessions.values()).length,
      })
    }

    function emitLogoffEvent() {
      emitter.emit("logoff", {
        username,
        clientInfo,
        openSessions: Array.from(clientSessions.values()).length - 1,
      })
    }

    function emitDownloadEvent(file: string) {
      emitter.emit("download", {
        username,
        clientInfo,
        file: path.join(getFolder(), file),
      })
    }

    function emitUploadEvent(file: string) {
      emitter.emit("upload", {
        username,
        clientInfo,
        file: path.join(getFolder(), file),
      })
    }

    function emitRenameEvent(fileFrom: string, fileTo: string) {
      emitter.emit("rename", {
        username,
        clientInfo,
        fileFrom: path.join("/", fileFrom),
        fileTo: path.join(getFolder(), fileTo),
      })
    }

    function SessionErrorHandler(socketType: string) {
      return function (error: NodeJS.ErrnoException) {
        emitter.emit(
          "warn", // don't say "error" -- Jest somehow detects "error" events that don't have a handler
          `${socketType} error ${clientInfo} ${getDateForLogs()} ${util.inspect(
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

    function CmdHandler(buf: Buffer) {
      const data = buf.toString(),
        [cmd, ...args] = data.trim().split(/\s+/),
        arg = args.join(" ")
      emitLogMessage(`>>> cmd[${cmd}] arg[${cmd === "PASS" ? "***" : arg}]`)

      try {
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
          client.end()
        }
      } catch (err) {
        SessionErrorHandler(
          `exception on command [${[cmd, ...args].join(" ")}]`
        )(err)
        client.respond("550", "Unexpected server error")
        client.end()
      }
    }
  }
}
export default createFtpServer

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
          getDateForMLSD(fstat.mtime),
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
          getDateForLIST(fstat.mtime),
          fstat.name
        )
  }
}

function getDateForLIST(mtime: Date): string {
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

function getDateForMLSD(mtime: Date): string {
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
