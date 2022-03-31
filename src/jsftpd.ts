/* eslint-disable @typescript-eslint/no-unused-vars */
/*
 * @package jsftpd
 * @author Sven <mailsvb@gmail.com>
 * @author Tim Gerk <tjgerk@gmail.com>
 * @license https://github.com/mailsvb/jsftpd/blob/main/LICENSE MIT License
 */

import { Server, Socket, AddressInfo, createServer, connect } from "net"
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

import Deferred from "./deferred"
import { deasciify, asciify } from "./ascii"
import internalAuth, {
  AuthHandlersFactory,
  AuthOptions,
  LoginType,
  Permissions,
  Credential,
} from "./auth"
import localStore, {
  StoreHandlersFactory,
  StoreHandlers,
  FStats,
} from "./store"
import { readFileSync } from "fs"

export type ComposableAuthHandlerFactory = (
  factory: AuthHandlersFactory
) => AuthHandlersFactory

export type ComposableStoreHandlerFactory = (
  factory: StoreHandlersFactory
) => StoreHandlersFactory

export type ServerOptions = {
  port?: number
  securePort?: number
  minDataPort?: number
  maxConnections?: number
  timeout?: number
  dataTimeout?: number
  // overlooks misc options for TLS servers and TLS client/server sockets, e.g. session resume, OCSP, pre-shared keys
  tls?: SecureContextOptions // excludes CommonConnectionOptions, e.g. client certificates and SNI
  auth?: ComposableAuthHandlerFactory
  store?: ComposableStoreHandlerFactory
}

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
  
  // because we implement FTPS (via AUTH TLS), but not necessarily SFTP (default port 990)
  //  use certs module to provide a backup self-signed certificate
  if (!("key" in tlsOptions) || !("cert" in tlsOptions)) {
    const { cert, key } = await import("./cert")
    tlsOptions.cert = cert
    tlsOptions.key = key
  } else {
    if (tlsOptions.cert.toString().startsWith("file:")) {
      tlsOptions.cert = readFileSync(tlsOptions.cert.toString().substring(5))
    }
    if (tlsOptions.key.toString().startsWith("file:")) {
      tlsOptions.key = readFileSync(tlsOptions.key.toString().substring(5))
    }
    if (tlsOptions.passphrase.startsWith("file:")) {
      tlsOptions.passphrase = readFileSync(tlsOptions.passphrase.substring(5)).toString()
    }
  }

  const tlsContext = createSecureContext(tlsOptions),
    useTls = "securePort" in options

  // compose auth and storage backend handler factories
  const authBackend = auth?.(internalAuth) ?? internalAuth,
    { userLoginType, userAuthenticate } = authBackend(options)

  const storeBackend = store?.(localStore) ?? localStore
  if (!storeBackend.baseFolderExists(basefolder)) {
    throw new Error("Basefolder must exist")
  }

  // setup FTP on TCP
  const tcpServer = createServer(SessionHandler)
  tcpServer.on("error", ServerErrorHandler)
  tcpServer.on("listening", () => {
    emitListenEvent("tcp", tcpServer.address() as AddressInfo)
  })

  // concurrent connections, distinct from the listen backlog, excess connections are immediately closed
  tcpServer.maxConnections = options.maxConnections

  // setup FTP on TLS
  let tlsServer: TlsServer
  if (useTls) {
    tlsServer = createSecureServer(tlsOptions, SessionHandler)
    tlsServer.on("error", ServerErrorHandler)
    tlsServer.on("listening", function () {
      emitListenEvent("tls", tlsServer.address() as AddressInfo)
    })

    // concurrent connections, distinct from the listen backlog, excess connections are immediately closed
    tlsServer.maxConnections = options.maxConnections
  }

  // track client sessions
  let lastSessionKey = 0
  const openSessions: Map<number, Socket> = new Map()

  const emitter = new EventEmitter()
  return Object.assign(emitter, {
    start() {
      tcpServer.listen(options.port)
      useTls && tlsServer.listen(options.securePort)
    },

    stop() {
      for (const session of openSessions.values()) {
        session.destroy()
      }
      tcpServer.close()
      useTls && tlsServer.close()
    },

    cleanup() {
      storeBackend.baseFolderCleanup(basefolder)
    },
  })

  function SessionHandler(cmdSocket: Socket | TLSSocket) {
    const socketKey = ++lastSessionKey
    openSessions.set(socketKey, cmdSocket)

    let resolveFolder: StoreHandlers["resolveFolder"],
      resolveFile: StoreHandlers["resolveFile"],
      setFolder: StoreHandlers["setFolder"],
      getFolder: StoreHandlers["getFolder"],
      folderExists: StoreHandlers["folderExists"],
      folderDelete: StoreHandlers["folderDelete"],
      folderCreate: StoreHandlers["folderCreate"],
      folderList: StoreHandlers["folderList"],
      fileExists: StoreHandlers["fileExists"],
      fileSize: StoreHandlers["fileSize"],
      fileDelete: StoreHandlers["fileDelete"],
      fileRetrieve: StoreHandlers["fileRetrieve"],
      fileStore: StoreHandlers["fileStore"],
      fileRename: StoreHandlers["fileRename"],
      fileSetTimes: StoreHandlers["fileSetTimes"]

    let username = "nobody",
      authenticated = false,
      permissions: Permissions

    let asciiTxfrMode = false
    let pbszReceived = false
    let protectedMode = false
    let renameFileFrom = ""
    let dataOffset = 0

    const localAddr =
        cmdSocket.localAddress?.replace(/::ffff:/g, "") ?? "unknown",
      remoteAddr =
        cmdSocket.remoteAddress?.replace(/::ffff:/g, "") ?? "unknown",
      remoteInfo = `[(${socketKey}) ${remoteAddr}:${cmdSocket.remotePort}]`

    cmdSocket.on("error", SessionErrorHandler("command socket"))
    cmdSocket.on("data", CmdHandler)
    cmdSocket.on("close", () => {
      openSessions.delete(socketKey)
      emitDebugMessage(`FTP connection closed`)
      if (passivePort) {
        passivePort.close()
      }
    })

    emitDebugMessage(`established FTP connection`)

    function respond(
      this: Socket,
      code: string,
      message: string,
      delimiter = " "
    ) {
      emitDebugMessage(`<<< ${code} ${message}`)
      this.write(`${code}${delimiter}${message}\r\n`)
    }
    let client = Object.assign(cmdSocket, { respond })
    client.respond("220", "Welcome")

    let passivePort: Server, dataSocket: Deferred<Socket | TLSSocket>

    if ("timeout" in options) {
      cmdSocket.setTimeout(options.timeout, () => {
        authenticated && emitLogoffEvent()
        client.respond("221", "Goodbye")
        cmdSocket.end()
      })
    }

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
        emitDebugMessage(`>>> cmd[${cmd}] arg[${cmd === "PASS" ? "***" : arg}]`)
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
        SessionErrorHandler(`command execution [${data}]`)(err)
        client.respond("550", "Unexpected server error")
        cmdSocket.end()
      }

      /*
       *  USER
       */
      function USER(cmd: string, user: string) {
        username = user
        authenticated = false
        switch (
          userLoginType(username, (credential) =>
            setUser(credential).then(() => {
              client.respond("232", "User logged in")
            })
          )
        ) {
          case LoginType.NoPassword:
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
        switch (
          userAuthenticate(username, password, (credential) =>
            setUser(credential).then(() => {
              client.respond("230", "Logged on")
            })
          )
        ) {
          case LoginType.Anonymous:
          case LoginType.NoPassword: // eslint-disable-line no-fallthrough
          case LoginType.Password:
            break
          default:
            client.respond("530", "Username or password incorrect")
            cmdSocket.end()
        }
      }

      /*
       *  AUTH (upgrade command socket security)
       */
      function AUTH(cmd: string, auth: string) {
        switch (auth) {
          case "TLS":
          case "SSL":
            client.respond("234", `Using authentication type ${auth}`)
            cmdSocket = new TLSSocket(cmdSocket, {
              secureContext: tlsContext,
              isServer: true,
            })
            cmdSocket.on("secure", () => {
              emitDebugMessage(`command connection secured`)
              client = Object.assign(cmdSocket, { respond })
            })
            cmdSocket.on("data", CmdHandler)
            break
          default:
            client.respond("504", `Unsupported auth type ${auth}`)
        }
      }

      /*
       *  QUIT
       */
      function QUIT() {
        authenticated && emitLogoffEvent()
        client.respond("221", "Goodbye")
        cmdSocket.end()
      }

      /*
       *  CLNT
       */
      function CLNT() {
        client.respond("200", "Don't care")
      }

      /*
       *  PBSZ (set protection buffer size, irrelevant to SSL private mode)
       */
      function PBSZ(cmd: string, size: string) {
        pbszReceived = true
        client.respond("200", `PBSZ=${size}`)
      }

      /*
       *  PROT
       */
      function PROT(cmd: string, protection: string) {
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
      function PORT(cmd: string, spec: string) {
        const [net0, net1, net2, net3, portHi, portLo] = spec.split(","),
          addr = [net0, net1, net2, net3].join("."),
          port = parseInt(portHi, 10) * 256 + parseInt(portLo)
        if (addr.match(/\d{1,3}(\.\d{1,3}){3}/) && port > 0) {
          setupDataSocket(addr, port)
          client.respond("200", "Port command successful")
        } else {
          client.respond("501", "Port command failed")
        }
      }

      /*
       *  PASV
       */
      function PASV() {
        setupPassiveSocket().then(
          (port) => {
            emitDebugMessage(`listening on ${port} for data connection`)
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
            emitLogMessage(error)
            client.respond("501", "Passive command failed")
          }
        )
      }

      /*
       *  EPRT
       */
      function EPRT(cmd: string, spec: string) {
        const addrSpec = spec.split("|"),
          addr = addrSpec[2],
          port = parseInt(addrSpec[3], 10)
        if (
          addrSpec.length === 5 &&
          addr.match(/\d{1,3}(\.\d{1,3}){3}/) &&
          port > 0
        ) {
          setupDataSocket(addr, port)
          client.respond("200", "Extended Port command successful")
        } else {
          client.respond("501", "Extended port command failed")
        }
      }

      /*
       *  EPSV
       */
      function EPSV() {
        setupPassiveSocket().then(
          (port) => {
            emitDebugMessage(`listening on ${port} for data connection`)
            client.respond(
              "229",
              util.format("Entering extended passive mode (|||%d|)", port)
            )
          },
          (error) => {
            emitLogMessage(error)
            client.respond("501", "Extended passive command failed")
          }
        )
      }

      /*
       *  SYST
       */
      function SYST() {
        client.respond("215", process.env["OS"] ?? "UNIX")
      }

      /*
       *  TYPE
       */
      function TYPE(cmd: string, tfrType: string) {
        if (tfrType === "A") {
          asciiTxfrMode = true
          client.respond("200", "Type set to ASCII")
        } else {
          asciiTxfrMode = false
          client.respond("200", "Type set to BINARY")
        }
      }

      /*
       *  REST
       */
      function REST(cmd: string, arg: string) {
        const offset = parseInt(arg, 10)
        if (offset >= 0) {
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
                    emitLogMessage(error)
                    client.respond("530", "CWD not successful")
                  }
                )
              } else {
                client.respond("550", "Folder not found")
              }
            }),
          (error) => {
            emitLogMessage(error)
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
            if (!permissions.allowFolderDelete || folder === "/") {
              client.respond("550", "Permission denied")
            } else {
              folderExists(folder).then((isFolder) => {
                if (isFolder) {
                  folderDelete(folder).then(
                    () => {
                      client.respond("250", "Folder deleted successfully")
                    },
                    (error) => {
                      emitLogMessage(error)
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
            emitLogMessage(error)
            client.respond("550", `Command failed "${folder}`)
          }
        )
      }

      /*
       *  MKD
       */
      function MKD(cmd: string, folder: string) {
        if (!permissions.allowFolderCreate) {
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
                      emitLogMessage(error)
                      client.respond("501", "Command failed")
                    }
                  )
                }
              }),
            (error) => {
              emitLogMessage(error)
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
      function LIST(cmd: string, folder: string) {
        openDataSocket().then(
          (socket: Writable) => {
            folderList(folder)
              .then((stats) => stats.map(formatListing(cmd)).join("\r\n"))
              .then((listing) => {
                emitDebugMessage(`LIST response on data channel\r\n${listing}`)
                socket.end(listing + "\r\n")
                client.respond(
                  "226",
                  `Successfully transferred "${getFolder()}"`
                )
              })
          },
          (error: NodeJS.ErrnoException) => {
            emitLogMessage(error)
            client.respond("501", "Command failed")
          }
        )
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
                emitLogMessage(error)
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
            emitLogMessage(error)
            client.respond("501", "Command failed")
          }
        )
      }

      /*
       *  DELE
       */
      function DELE(cmd: string, file: string) {
        if (!permissions.allowFileDelete) {
          client.respond("550", "Permission denied")
        } else {
          resolveFile(file).then(
            (file) =>
              fileDelete(file).then(
                () => {
                  client.respond("250", "File deleted successfully")
                },
                (error) => {
                  emitLogMessage(error)
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
              emitLogMessage(error)
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
            if (!permissions.allowFileRetrieve) {
              client.respond("550", `Transfer failed "${file}"`)
            } else {
              fileExists(file).then((isFile) => {
                if (!isFile) {
                  client.respond("550", "File not found")
                } else {
                  openDataSocket().then(
                    (writeSocket: Writable) =>
                      fileRetrieve(file, dataOffset)
                        .then((readStream) => {
                          readStream.on(
                            "error",
                            (error: NodeJS.ErrnoException) => {
                              // incomplete write
                              emitLogMessage(error)
                              writeSocket.destroy()
                              client.respond("550", `Transfer failed "${file}"`)
                            }
                          )
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
                            emitDownloadEvent(file)
                            client.respond(
                              "226",
                              `Successfully transferred "${file}"`
                            )
                          })
                          if (asciiTxfrMode) {
                            readStream = asciify(readStream)
                          }
                          // transform or log outbound stream
                          readStream.pipe(writeSocket)
                        })
                        .finally(() => {
                          dataOffset = 0
                        }),
                    (error: NodeJS.ErrnoException) => {
                      emitLogMessage(error)
                      client.respond("501", "Command failed")
                    }
                  )
                }
              })
            }
          },
          (error) => {
            emitLogMessage(error)
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
              if (
                isFile
                  ? !permissions.allowFileOverwrite
                  : !permissions.allowFileCreate
              ) {
                client.respond(
                  "550",
                  isFile ? "File already exists" : `Transfer failed "${file}"`
                )
              } else {
                openDataSocket().then(
                  (readSocket: Readable) =>
                    fileStore(file, dataOffset)
                      .then((writeStream) => {
                        writeStream.on(
                          "error",
                          (error: NodeJS.ErrnoException) => {
                            // incomplete write
                            emitLogMessage(error)
                            readSocket.destroy()
                            client.respond("550", `Transfer failed "${file}"`)
                          }
                        )
                        readSocket.on("error", (error) => {
                          // incomplete upload
                          emitLogMessage(error)
                          writeStream.destroy()
                          client.respond("550", `Transfer failed "${file}"`)
                        })
                        readSocket.on("end", () => {
                          // end of file
                          writeStream.end()
                          emitUploadEvent(file)
                          client.respond(
                            "226",
                            `Successfully transferred "${file}"`
                          )
                        })
                        if (asciiTxfrMode) {
                          readSocket = deasciify(readSocket)
                        }
                        // transform or log inbound stream
                        readSocket.pipe(writeStream)
                      })
                      .finally(() => {
                        dataOffset = 0
                      }),
                  (error: NodeJS.ErrnoException) => {
                    emitLogMessage(error)
                    client.respond("501", "Command failed")
                  }
                )
              }
            }),
          (error) => {
            emitLogMessage(error)
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
              } else if (!permissions.allowFileRename) {
                client.respond("550", "Permission denied")
              } else {
                renameFileFrom = path.relative(
                  "/",
                  path.join(getFolder(), file)
                )
                client.respond("350", "File exists")
              }
            }),
          (error) => {
            emitLogMessage(error)
            client.respond("501", "Command failed")
          }
        )
      }

      /*
       *  RNTO
       */
      function RNTO(cmd: string, file: string) {
        if (!permissions.allowFileRename) {
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
                        emitRenameEvent(renameFileFrom, file)
                        client.respond("250", "File renamed successfully")
                      },
                      (error) => {
                        emitLogMessage(error)
                        client.respond("550", "File rename failed")
                      }
                    )
                    .finally(() => {
                      renameFileFrom = ""
                    })
                }
              }),
            (error) => {
              emitLogMessage(error)
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
                emitLogMessage(error)
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
            emitLogMessage(error)
            client.respond("501", "Command failed")
          }
        )
      }
    }

    function setUser(credential: Credential) {
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
      } = storeBackend(credential))

      return folderExists().then(
        () => {
          ;({ username } = credential)
          authenticated = true
          permissions = credential

          emitLoginEvent()
          asciiTxfrMode = false
          pbszReceived = false
          protectedMode = false
          renameFileFrom = ""
          dataOffset = 0
        },
        () => {
          throw Object.assign(
            Error(`user basefolder [${credential.basefolder}] does not exist`),
            { code: "ENOTDIR" }
          )
        }
      )
    }

    function setupPassiveSocket() {
      if (passivePort) {
        passivePort.close()
      }

      // inbound connection is deferred
      dataSocket = new Deferred<Socket | TLSSocket>()
      function setupSocket(socket: Socket | TLSSocket) {
        if ("dataTimeout" in options || "timeout" in options) {
          socket.setTimeout(options.dataTimeout || options.timeout, () => {
            socket.destroy()
          })
        }
        socket.on("error", SessionErrorHandler("passive data socket"))
        socket.on("close", () => {
          // reset for subsequent connection
          dataSocket = new Deferred<Socket | TLSSocket>()
          emitDebugMessage(`data connection has closed`)
        })

        dataSocket.resolve(socket)
      }

      if ("encrypted" in client && protectedMode) {
        passivePort = createSecureServer(tlsOptions, (socket) => {
          emitDebugMessage(`secure data connection established`)
          setupSocket(socket)
        })
      } else {
        passivePort = createServer((socket) => {
          emitDebugMessage(`data connection established`)
          if ("encrypted" in client && protectedMode) {
            socket = new TLSSocket(socket, {
              secureContext: tlsContext,
              isServer: true,
            })
            socket.on("secure", () => {
              emitDebugMessage(`data connection secured`)
              setupSocket(socket)
            })
          } else {
            setupSocket(socket)
          }
        })
      }

      passivePort.maxConnections = 1
      passivePort.on("error", SessionErrorHandler)

      return findAvailablePort().then(
        (port) =>
          new Promise<AddressInfo["port"]>((resolve, reject) => {
            passivePort.once("error", reject)
            passivePort.listen(port, () => {
              resolve((passivePort?.address() as AddressInfo).port)
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
            server.once("error", function () {
              if (port < minDataPort + maxConnections) {
                return checkAvailablePort(++port) // recurse
              }
              reject(Error("exceeded maxConnections"))
            })
            server.once("close", function () {
              resolve(port)
            })

            server.listen(port, function () {
              server.close()
            })
          }
        })
      }
    }

    function setupDataSocket(addr: string, port: number) {
      if (passivePort) {
        passivePort.close()
        passivePort = undefined
      }

      // defer initiating outbound connection
      dataSocket = new Deferred<Socket | TLSSocket>(makeDataConnection)
      function makeDataConnection(
        resolve: (value: Socket | TLSSocket) => void
      ) {
        function setupSocket(socket: Socket | TLSSocket) {
          if ("dataTimeout" in options || "timeout" in options) {
            socket.setTimeout(options.dataTimeout || options.timeout, () => {
              socket.destroy()
            })
          }

          resolve(socket)
        }

        emitDebugMessage(
          `connect to client data socket isSecure[${
            "encrypted" in client
          }] protection[${protectedMode}] addr[${addr}] port[${port}]`
        )
        let socket = connect(port, addr, () => {
          emitDebugMessage(`data connection to ${addr}:${port} established`)
          if ("encrypted" in client && protectedMode) {
            socket = new TLSSocket(socket, {
              secureContext: tlsContext,
              isServer: true,
            })
            socket.on("secure", () => {
              emitDebugMessage(`data connection to ${addr}:${port} secured`)
              setupSocket(socket)
            })
          } else {
            setupSocket(socket)
          }
        })
        socket.on("error", SessionErrorHandler("active data socket"))
        socket.on("close", () => {
          // reset for subsequent connection
          dataSocket = new Deferred<Socket | TLSSocket>(makeDataConnection)
          emitDebugMessage(`data connection has closed`)
        })
      }
    }

    function openDataSocket() {
      if (!dataSocket) {
        return Promise.reject(Error("active or passive mode not selected"))
      }

      client.respond(
        "150",
        passivePort ? "Awaiting passive connection" : "Opening data connection"
      )
      return dataSocket
    }

    function emitLogMessage(msg: string | { toString: () => string }) {
      emitter.emit("log", `${getDateForLogs()} ${remoteInfo} ${msg}`)
    }

    function emitDebugMessage(msg: string | { toString: () => string }) {
      emitter.emit("debug", `${getDateForLogs()} ${remoteInfo} ${msg}`)
    }

    function emitLoginEvent() {
      emitter.emit("login", {
        remoteInfo,
        username,
        openSessions: Array.from(openSessions.keys()).length,
      })
    }

    function emitLogoffEvent() {
      emitter.emit("logoff", {
        remoteInfo,
        username,
        openSessions: Array.from(openSessions.keys()).length - 1,
      })
    }

    function emitDownloadEvent(file: string) {
      emitter.emit("download", {
        remoteInfo,
        username,
        file: path.join(getFolder(), file),
      })
    }

    function emitUploadEvent(file: string) {
      emitter.emit("upload", {
        username,
        remoteInfo,
        file: path.join(getFolder(), file),
      })
    }

    function emitRenameEvent(fileFrom: string, fileTo: string) {
      emitter.emit("rename", {
        username,
        remoteInfo,
        fileFrom: path.join("/", fileFrom),
        fileTo: path.join(getFolder(), fileTo),
      })
    }

    function SessionErrorHandler(socketType: string) {
      return function SocketErrorHandler(err: NodeJS.ErrnoException) {
        if (err?.code === "ECONNRESET") {
          emitLogMessage(err)
          return
        }

        emitter.emit(
          "error",
          `${socketType} error ${remoteInfo} ${getDateForLogs()} ${util.inspect(
            err,
            {
              showHidden: false,
              depth: null,
              breakLength: Infinity,
            }
          )}`
        )
      }
    }
  }

  function emitListenEvent(protocol: string, address: AddressInfo) {
    emitter.emit("listen", {
      protocol,
      address: (address as AddressInfo).address,
      port: (address as AddressInfo).port,
      basefolder: storeBackend.baseFolder(basefolder),
    })
  }

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
}
export default createFtpServer

// formatter utilities: time/date, folder listing
function formatListing(format = "LIST") {
  switch (format) {
    case "NLST":
      return (fstat: FStats) => fstat.fname
    case "MLSD":
      return (fstat: FStats) =>
        util.format(
          "type=%s;modify=%s;%s %s",
          fstat.isDirectory() ? "dir" : "file",
          getDateForMLSD(fstat.mtime),
          fstat.isDirectory() ? "" : "size=" + fstat.size.toString() + ";",
          fstat.fname
        )
    case "LIST":
    default:
      return (fstat: FStats) =>
        util.format(
          "%s 1 ? ? %s %s %s", // showing link-count = 1, don't expose uid, gid
          fstat.isDirectory() ? "dr--r--r--" : "-r--r--r--",
          String(fstat.isDirectory() ? "0" : fstat.size).padStart(14, " "),
          getDateForLIST(fstat.mtime),
          fstat.fname
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
