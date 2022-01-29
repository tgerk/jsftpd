/*
 * @package jsftpd
 * @author Sven <mailsvb@gmail.com>
 * @license https://github.com/mailsvb/jsftpd/blob/main/LICENSE MIT License
 */

"use strict";

import { Socket, SocketAddress } from "net";

const tls = require("tls");
const fs = require("fs");
const util = require("util");
const path = require("path");
const net = require("net");
const EventEmitter = require("events").EventEmitter;
const defaultBaseFolder = path.join(__dirname, "jsftpd-tmp");
const defaultCert = Buffer.from(
  "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdHpOM1dKdHE5MjAzYWQ0eFRxb2hHM3hLUVdvUnJFejArd3JTUnNhZitMQTQzSWQ4CjRWUUU0elpsaEhSRVJzSGJjQkdGd0dNTEwxaGJXTWc3eDErSFhKYXlxNXJwcldTZ1g4TVRwZllkN2RUNkxRT3oKdmdBTUx3WUJwM3VkYm5IM2tyUERQazBibWRDcTZ4RmxqaUR4bHB6dWxIN1Vqb2crRE1XYmdpVHFYU2YrUThZTwpXS2xVRXhMVzZ5L3hFNUNIVVN3ZGI3MWREc2pDSG90YWliTTNXdlpGdEc3MnAvUXBaWldtZmQreEQwL3VoVnhNCnBualR0S21xWlMwcnJZM3Y1SFR5dVpBMUJRMFBVWmV0NzdLdWZKUis2aVlzQjQ4Z3NSM0szNmd6WHoyMzRXUXUKbEppcWk0dXo4Wjk1LzQyZmJOUlR3eWxRZXBQY1Ruc0Rib0Y0Q1FJREFRQUJBb0lCQVFDanR1UmlWSkVraDM5TApwbm9kdUQ5WjFwcHRGcUt3ZlIwMzhwV3pGZkVEUmtlcUc1SG5zek9pOEl1TDhITExZSlgrOGttNmdVZ1BpVUFvCmVOZWk5YVY3Z2xnc3JvVkFwSG9FMmNtSE9BZks3OWFadjRNeXVjd3BnWTZjNHdUdkcvMklKZ2pHZGhYQ1FRMWMKZi9Gbkw5MTFJTXk3K3hOc1JDaGZOWUFncjJpWTBZOUpRQndncTlJM1BWZ1RGQUtkTTBKZ1hySzhXVCtsN3NDRQpWc0kyUkVnYUxzeUxud2VmYnRwbVV0ankrbWtLemIzcnNyY1JVVmJOZjB3aEFlTG9HS01wZjVPNVUzMVNjd2xwClB2RnpHWkUyM01HbHpheGpZVVJTVmV3TFlzR2dwNTg5SDF6WmZaQVhSRWRiOEx2MGYra0I5MSthUi9Hdy9IT3gKS3ZlVXEvTVpBb0dCQU9BQkhxWWdXNmFwM3BjMjZJNVdNNURrMnJ1TnArRENQbzJUV3RRTklwTlREMEorRWt6SgpMZ1ZEK0xGVWZmNDFTQlZEbWZXR2x3cnVtajdWWGtTbjZyWmZXQUVKYTBySkljdHV3TDcxQ1Y0Q280cnFsUGlpCnhEazdhUFpYSXJBcjdaOG5UOG1kVStmcENMS1FNVUhYY0wydDI0cE85NytFVGVycVVYcGtEQXVEQW9HQkFORmUKVitZYThuVGxjVVhkbktqQVU4czJNSlhUUFZkeDlIM3BzQjNOVjJtR2lmM1h2d2F6ei9mYTg5NG5Ha3FxS2N6cwppV1BLdlR0MytVdUwxSlhWSlcwMllycHpUMlpMd2lqY3pCQlc1OGtIeU9UUGZ4UENjemh1dGlQUHJoMnQwbGJtCkR6WFpuTzJPUlpJWlp3MFllVFlNVzFUcnZ3WnRpT0VxMFp4cVVkeURBb0dBYld0K21pMmlOMll3NmZLVFpMdnMKMG5GSCsyZTF3bzkvMk01TEJ0d25zSWxaSWVUTmNaNndFVGhqcWRPWSsrencraG9jZ1pldC9sUVJHbkpGYXdvUApGK2k0NTBDL25UZGtmNmZwRlI1QzVoNHAzdmk1cmo1cjFYMFV4NGhHMUlHUXdEYUd2ZmhRL1M2UzVnNlRVUk00CjZoNmI2QktzNkd0cldEMy9jT2FnRDVzQ2dZQXpwNHdXS0dYVE0xeHIrVTRTVUVrY0pNVjk0WDBMMndDUUpCeWcKYmEzNFNnbzNoNGdJdGtwRUExQVJhaUpSYzRRV20vRVZuc3BySnFGcDR4alMwcUNHUGxuRFdIbXBhbDEveVdITApValdqWW5sTkFtaCt6b1d3MFplOFpCdTRGTStGUXdOVHJObkx2a01wMVh5WVBZYUNNREJFVmxsdDA0NW14ektwCjNZMU8wd0tCZ0FHaVkyNVZLOGJyMVFydXlzM3Vhb21LQ3BYUmhjZU15eHdBazdxeUlpNnpHeEx3bnFaVldaQmQKbkcxbkFaT2JET1JSTGRBRktPZ2tncGtVbGgrTEE3dTRuUytGWEdteGtLZlF1cTNTcTNaWHhiTjMxcXBCcERHTQoxbE9QSlVWY2UxV3ZyeXcrWVI4M1VFQ0ZTOEZjeDdibEVEM3oyNnVOQnN0dlBwVTUrV3ZxCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDNGpDQ0FjcWdBd0lCQWdJSWJqQ2hhajZDT2Iwd0RRWUpLb1pJaHZjTkFRRUxCUUF3RVRFUE1BMEdBMVVFCkF4TUdhbk5tZEhCa01DQVhEVEl3TURFd01UQXdNREF3TUZvWUR6azVPVGt4TWpNeE1qTTFPVFU1V2pBUk1ROHcKRFFZRFZRUURFd1pxYzJaMGNHUXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDMwpNM2RZbTJyM2JUZHAzakZPcWlFYmZFcEJhaEdzVFBUN0N0Skd4cC80c0RqY2gzemhWQVRqTm1XRWRFUkd3ZHR3CkVZWEFZd3N2V0Z0WXlEdkhYNGRjbHJLcm11bXRaS0Jmd3hPbDloM3QxUG90QTdPK0FBd3ZCZ0duZTUxdWNmZVMKczhNK1RSdVowS3JyRVdXT0lQR1duTzZVZnRTT2lENE14WnVDSk9wZEovNUR4ZzVZcVZRVEV0YnJML0VUa0lkUgpMQjF2dlYwT3lNSWVpMXFKc3pkYTlrVzBidmFuOUNsbGxhWjkzN0VQVCs2RlhFeW1lTk8wcWFwbExTdXRqZS9rCmRQSzVrRFVGRFE5Umw2M3ZzcTU4bEg3cUppd0hqeUN4SGNyZnFETmZQYmZoWkM2VW1LcUxpN1B4bjNuL2paOXMKMUZQREtWQjZrOXhPZXdOdWdYZ0pBZ01CQUFHalBEQTZNQXdHQTFVZEV3RUIvd1FDTUFBd0hRWURWUjBPQkJZRQpGQkRRdzE4NC91Qk5zMHlxczVqaU92dnd4TFBTTUFzR0ExVWREd1FFQXdJRjREQU5CZ2txaGtpRzl3MEJBUXNGCkFBT0NBUUVBaWdSa0draEMxeTVMendOQ0N1T0I5eUsyS2NkUGJhcm9lZGlSWVVxZmpVU2JsT3NweWFTNjEvQjgKVk9UdHZSRjBxZkJFZTVxZVhVUTRIV1JGSnRVZmQ1eisvZTRZNkJHVmR3eFJ5aktIYkVGQ3NpOFlFZDNHOTdaZwpWM1RFV08xVVlCTlJhN2tZajE2QXFDOWtXaG5WRVU3bUdRWE5nR1NJaDNNTmx5RG1RblBIdHdzS2d3cUs5VWcvCk9QVUhUNGlTa2h2OEVoTjYyUFlRaHBEaU1udWFQbUZ1bGVKbmllQnNFMTlvSVBtbWsxblRIZXRPZDg4VU1PeUEKWDFKY0ZBZXI2dmVPQkxVMUhRSEdtd1Iyalgzai83YzI3SjJFdjRQWW1rU2R2N0FYcm5LaENDeGRSblA2WDlGaApTYlEwRHBhbW5zaWFEWld4QzNuUks2LzVndXdlOHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
  "base64"
);

const TLSserverDefaults = {
  key: defaultCert,
  cert: defaultCert,
  honorCipherOrder: true,
  rejectUnauthorized: false,
};

const HandlerDefaults = {
  upload: async function () {},
  download: async function () {},
  list: async function () {},
  rename: async function () {},
};

const FTPdefaults = {
  port: 21,
  securePort: 990,
  maxConnections: 10,
  basefolder: defaultBaseFolder,
  user: [],
  allowAnonymousFileCreate: false,
  allowAnonymousFileRetrieve: false,
  allowAnonymousFileOverwrite: false,
  allowAnonymousFileDelete: false,
  allowAnonymousFileRename: false,
  allowAnonymousFolderDelete: false,
  allowAnonymousFolderCreate: false,
  allowAnonymousLogin: false,
  minDataPort: 1024,
};

const UserDefaults = {
  allowLoginWithoutPassword: false,
  allowUserFileCreate: true,
  allowUserFileRetrieve: true,
  allowUserFileOverwrite: true,
  allowUserFileDelete: true,
  allowUserFileRename: true,
  allowUserFolderDelete: true,
  allowUserFolderCreate: true,
};

const LoginType = Object.freeze({
  None: 0,
  Anonymous: 1,
  Password: 2,
  NoPassword: 3,
});

export class ftpd extends EventEmitter {
  constructor(options) {
    super(options);

    this.lastSessionKey = 0;
    this.openSessions = {};

    // options
    this._useTLS = options && Object.keys(options).indexOf("tls") > -1;
    this._useHdl = options && Object.keys(options).indexOf("hdl") > -1;
    this._opt = {
      tls: { ...TLSserverDefaults, ...options?.tls },
      hdl: { ...HandlerDefaults, ...options?.hdl },
      cnf: { ...FTPdefaults, ...UserDefaults, ...options?.cnf },
    };

    // checks
    if (!this.directoryExists(this._opt.cnf.basefolder)) {
      if (this._opt.cnf.basefolder === defaultBaseFolder) {
        fs.mkdirSync(defaultBaseFolder);
      } else {
        throw new Error("Basefolder must exist");
      }
    }

    // setup FTP on TCP
    this._tcp = net.createServer();
    this._tcp.on("error", this.ErrorHandler);
    this._tcp.on("listening", (server) => { this.emitListen("tcp", server.address()); });
    this._tcp.on("connection", (socket) => this.SessionHandler(this, socket));
    this._tcp.maxConnections = this._opt.cnf.maxConnections;

    // setup FTP on TLS
    if (this._useTLS) {
      this._tls = tls.createServer(this._opt.tls);
      this._tls.on("error", this.ErrorHandler);
      this._tls.on("listening", (server) => { this.emitListen("tls", server.address()); });
      this._tls.on("secureConnection", (socket) => this.SessionHandler(this, socket));
      this._tls.maxConnections = this._opt.cnf.maxConnections;
    }
  }

  start() {
    this._tcp.listen(this._opt.cnf.port);
    this._useTLS && this._tls.listen(this._opt.cnf.securePort);
  }

  stop() {
    Object.keys(this.openSessions).forEach((key) =>
      this.openSessions[key].destroy()
    );
    this._tcp.close();
    this._useTLS && this._tls.close();
  }

  cleanup() {
    if (this.directoryExists(defaultBaseFolder)) {
      fs.rmSync(defaultBaseFolder, { force: true, recursive: true });
    }
  }

  ErrorHandler(err) {
    if (err.code !== "ECONNRESET") {
      console.error(
        "error",
        `${getDateForLogs()} ${util.inspect(err, {
          showHidden: false,
          depth: null,
          breakLength: "Infinity",
        })}`
      );
    }
  }

  LogHandler(msg) {
    this.emit("log", `${getDateForLogs()} ${msg}`);
  }

  DebugHandler(msg) {
    this.emit("debug", `${getDateForLogs()} ${msg}`);
  }

  emitListen(protocol, address) {
    this.DebugHandler(
      `FTP server listening on ${util.inspect(address, {
        showHidden: false,
        depth: null,
        breakLength: "Infinity",
      })}`
    );
    this.emit("listen", {
      protocol,
      address: address.address.replace(/::ffff:/g, ""),
      port: address.port,
    });
  }

  emitLogin(username, remoteAddr) {
    this.emit("login", {
      user: username,
      address: remoteAddr,
      total: Object.keys(this.openSessions).length,
    });
  }

  emitLogoff(username, remoteAddr) {
    this.emit("logoff", {
      user: username,
      address: remoteAddr,
      total: Object.keys(this.openSockets).length,
    });
  }

  SessionHandler(server, cmdSocket) {
    const socketKey = ++server.lastSessionKey;
    server.openSessions[socketKey] = cmdSocket;

    const localAddr = cmdSocket.localAddress.replace(/::ffff:/g, "");
    const remoteAddr = cmdSocket.remoteAddress.replace(/::ffff:/g, "");
    const remoteInfo = `[${remoteAddr}] [${cmdSocket.remotePort}]`;
    cmdSocket.respond = function (code, message, delimiter = " ") {
      server.LogHandler(`${remoteInfo} > ${code} ${message}`);
      this.writable &&
        this.write(Buffer.from(`${code}${delimiter}${message}\r\n`));
    };

    let isEncrypted = cmdSocket.encrypted || false;
    let pbszReceived = false;
    let shouldProtect = false;

    let asciiOn = false;

    let pasv = true;
    let pasvChannel = null;
    let setPasvSocket,
      pasvSocket = new Promise<Socket>((resolve, reject) => {
        setPasvSocket = { resolve, reject };
      });

    let actv = false;
    let addr: string;
    let port: number;

    let username = "";
    let authenticated = false;
    let allowFileCreate = false;
    let allowFileRetrieve = false;
    let allowFileOverwrite = false;
    let allowFileDelete = false;
    let allowFileRename = false;
    let allowFolderDelete = false;
    let allowFolderCreate = false;

    let basefolder = server._opt.cnf.basefolder;
    let folderPath = "/";
    let renameFile = "";
    let restOffset = 0;
    
    cmdSocket.on("error", server.ErrorHandler);
    cmdSocket.on("data", CmdHandler);
    cmdSocket.on("close", () => {
      delete server.openSessions[socketKey];
      server.DebugHandler(`${remoteInfo} FTP connection closed`);
      if (pasvChannel) {
        pasvChannel.close();
      }
    });

    server.DebugHandler(`${remoteInfo} new FTP connection established`);
    cmdSocket.respond("220", "Welcome");

    function CmdHandler(data) {
      const preAuthFunctions = {
        USER: USER,
        PASS: PASS,
        AUTH: AUTH,
      };

      const authenticatedFunc = {
        QUIT: QUIT,
        PWD: PWD,
        CLNT: CLNT,
        PBSZ: PBSZ,
        OPTS: OPTS,
        PROT: PROT,
        FEAT: FEAT,
        CWD: CWD,
        SIZE: SIZE,
        DELE: DELE,
        RMD: RMD,
        RMDA: RMD,
        MKD: MKD,
        LIST: LIST,
        MLSD: LIST,
        PORT: PORT,
        PASV: PASV,
        EPRT: EPRT,
        EPSV: EPSV,
        RETR: RETR,
        REST: REST,
        STOR: STOR,
        SYST: SYST,
        TYPE: TYPE,
        RNFR: RNFR,
        RNTO: RNTO,
        MFMT: MFMT,
        MDTM: MFMT,
      };

      try {
        data = data.toString();
        server.DebugHandler(
          `${remoteInfo} < ${data.trim().replace(/^PASS\s.*$/i, "PASS ***")}`
        );
        let [cmd, ...arg] = data.split(" ");
        cmd = cmd.trim();
        arg = arg.join(" ").trim();
        server.LogHandler(
          `${remoteInfo} cmd[${cmd}] arg[${cmd === "PASS" ? "***" : arg}]`
        );
        if (authenticated) {
          if (Object.keys(authenticatedFunc).indexOf(cmd) >= 0) {
            authenticatedFunc[cmd](cmd, arg);
          } else {
            cmdSocket.respond("500", "Command not implemented");
          }
        } else if (Object.keys(preAuthFunctions).indexOf(cmd) >= 0) {
          preAuthFunctions[cmd](cmd, arg);
        } else {
          cmdSocket.respond("530", "Not logged in");
          cmdSocket.close();
        }
      } catch (err) {
        // application errors are a more interesting class of errors than network errors
        server.LogHandler(`${remoteInfo} ${err.message}`);
        server.ErrorHandler(err);
        cmdSocket.respond("550", "Server error");
        cmdSocket.close();
      }

      /*
       *  USER
       */
      function USER(cmd, arg) {
        authenticated = false;
        folderPath = "/";
        username = arg;
        const [loginType, userRights] = server.validateLoginType(username);
        switch (loginType) {
          case LoginType.None:
            cmdSocket.respond("530", "Not logged in");
            break;
          case LoginType.Anonymous:
          case LoginType.Password:
            cmdSocket.respond("331", `Password required for ${username}`);
            break;
          case LoginType.NoPassword:
            server.DebugHandler(
              `${remoteInfo} password-less username[${username}] authenticated`
            );
            authenticated = true;
            setUserRights(userRights);
            cmdSocket.respond("232", "User logged in");
            server.emitLogin(username, remoteAddr);
            break;
          default:
            cmdSocket.respond("331", `Password required for ${username}`);
        }
      }

      /*
       *  PASS
       */
      function PASS(cmd, arg) {
        const userRights = server.authenticateUser(username, arg);
        if (userRights) {
          authenticated = true;
          setUserRights(userRights);
          cmdSocket.respond("230", "Logged on");
          server.emitLogin(username, remoteAddr);
        } else {
          cmdSocket.respond("530", "Username or password incorrect");
          cmdSocket.end();
        }
        server.DebugHandler(
          `${remoteInfo} authenticateUser success[${authenticated}] username[${username}]`
        );
      }

      /*
       *  AUTH (switch protocol)
       */
      function AUTH(cmd, arg) {
        if (arg === "TLS" || arg === "SSL") {
          cmdSocket.respond("234", `Using authentication type ${arg}`);
          cmdSocket = new tls.TLSSocket(cmdSocket, {
            isServer: true,
            secureContext: tls.createSecureContext(server._opt.tls),
          });
          cmdSocket.on("secure", () => {
            server.DebugHandler(`${remoteInfo} secure connection established`);
            isEncrypted = cmdSocket.encrypted;
          });
          cmdSocket.on("data", CmdHandler);
        } else {
          cmdSocket.respond("504", `Unsupported auth type ${arg}`);
        }
      }

      /*
       *  QUIT
       */
      function QUIT(cmd, arg) {
        cmdSocket.respond("221", "Goodbye");
        cmdSocket.close();
        authenticated && server.emitLogoff(username, remoteAddr);
      }

      /*
       *  PWD
       */
      function PWD(cmd, arg) {
        cmdSocket.respond("257", `"${folderPath}" is current directory`);
      }

      /*
       *  CLNT
       */
      function CLNT(cmd, arg) {
        cmdSocket.respond("200", "Don't care");
      }

      /*
       *  PBSZ
       */
      function PBSZ(cmd, arg) {
        const size = arg;
        pbszReceived = true;
        cmdSocket.respond("200", `PBSZ=${size}`);
      }

      /*
       *  OPTS
       */
      function OPTS(cmd, arg) {
        arg = arg.toLowerCase();
        if (arg === "utf8 on") {
          cmdSocket.respond("200", "UTF8 ON");
        } else if (arg === "utf8 off") {
          cmdSocket.respond("200", "UTF8 OFF");
        } else {
          cmdSocket.respond("451", "Not supported");
        }
      }

      /*
       *  PROT
       */
      function PROT(cmd, arg) {
        if (pbszReceived === true) {
          if (arg === "C" || arg === "P") {
            shouldProtect = arg === "P";
            cmdSocket.respond("200", `Protection level is ${arg}`);
          } else {
            cmdSocket.respond("534", "Protection level must be C or P");
          }
        } else {
          cmdSocket.respond("503", "PBSZ missing");
        }
      }

      /*
       *  FEAT
       */
      function FEAT(cmd, arg) {
        const features = Object.keys(preAuthFunctions)
          .concat(Object.keys(authenticatedFunc))
          .join("\r\n ")
          .replace("AUTH", "AUTH TLS\r\n AUTH SSL");
        cmdSocket.respond("211", `Features:\r\n ${features}\r\n211 End`, "-");
      }

      /*
       *  PORT
       */
      function PORT(cmd, arg) {
        const cmdData = arg.split(",");
        pasv = false;
        actv = false;
        if (cmdData.length === 6) {
          actv = true;
          addr =
            cmdData[0] + "." + cmdData[1] + "." + cmdData[2] + "." + cmdData[3];
          port = parseInt(cmdData[4], 10) * 256 + parseInt(cmdData[5]);
          cmdSocket.respond("200", "Port command successful");
        } else {
          cmdSocket.respond("501", "Port command failed");
        }
      }

      /*
       *  PASV
       */
      function PASV(cmd, arg) {
        pasv = false;
        actv = false;
        openPassiveChannel().then(
          (address) => {
            pasv = true;
            server.DebugHandler(
              `${remoteInfo} listening on ${address.port} for data connection`
            );
            cmdSocket.respond(
              "227",
              util.format(
                "Entering passive mode (%s,%d,%d)",
                localAddr.split(".").join(","),
                (address.port / 256) | 0,
                address.port % 256
              )
            );
          },
          () => {
            cmdSocket.respond("501", "Passive command failed");
          }
        );
      }

      /*
       *  EPRT
       */
      function EPRT(cmd, arg) {
        const cmdData = arg.split("|");
        pasv = false;
        actv = false;
        if (cmdData.length === 5) {
          actv = true;
          addr = cmdData[2];
          port = parseInt(cmdData[3], 10);
          cmdSocket.respond("200", "Extended Port command successful");
        } else {
          cmdSocket.respond("501", "Extended port command failed");
        }
      }

      /*
       *  EPSV
       */
      function EPSV(cmd, arg) {
        pasv = false;
        actv = false;
        openPassiveChannel().then(
          (address) => {
            pasv = true;
            server.DebugHandler(
              `${remoteInfo} listening on ${address.port} for data connection`
            );
            cmdSocket.respond(
              "229",
              util.format(
                "Entering extended passive mode (|||%d|)",
                address.port
              )
            );
          },
          () => {
            cmdSocket.respond("501", "Extended passive command failed");
          }
        );
      }

      /*
       *  SYST
       */
      function SYST(cmd, arg) {
        cmdSocket.respond("215", "UNIX");
      }

      /*
       *  REST
       */
      function REST(cmd, arg) {
        const offset = parseInt(arg, 10);
        if (offset > -1) {
          restOffset = offset;
          cmdSocket.respond("350", `Restarting at ${restOffset}`);
        } else {
          restOffset = 0;
          cmdSocket.respond("550", "Wrong restart offset");
        }
      }

      /*
       *  TYPE
       */
      function TYPE(cmd, arg) {
        if (arg === "A") {
          asciiOn = true;
          cmdSocket.respond("200", "Type set to ASCII");
        } else {
          asciiOn = false;
          cmdSocket.respond("200", "Type set to BINARY");
        }
      }

      /*
       *  CWD
       */
      function CWD(cmd, arg) {
        const path = resolvePath(arg);
        if (!server.directoryExists(path)) {  // or user has no access?
          cmdSocket.respond("530", "CWD not successful");
        } else {
          folderPath = path.substring(basefolder.length) || "/";
          cmdSocket.respond( "250", `CWD successful. "${folderPath}" is current directory` );
        }
      }

      /*
       *  SIZE
       */
      function SIZE(cmd, arg) {
        const file = resolvePath(arg);
        if (server._useHdl) {
          cmdSocket.respond("550", "not capable");
        } else if (!server.fileExists(file)) {
          cmdSocket.respond("550", "File not found");
        } else {
          const fstat = fs.statSync(file);
          cmdSocket.respond("213", fstat.size.toString());
        }
      }

      /*
       *  DELE
       */
      function DELE(cmd, arg) {
        const file = resolvePath(arg);
        if (server._useHdl) {
          cmdSocket.respond("550", "not capable");
        } else if (!allowFileDelete) {
          cmdSocket.respond("550", "Permission denied");
        } else if (!server.fileExists(file)) {
          cmdSocket.respond("550", "File not found");
        } else {
          fs.unlinkSync(file);
          cmdSocket.respond("250", "File deleted successfully");
        }
      }

      /*
       *  RMD
       *  RMDA
       */
      function RMD(cmd, arg) {
        const folder = resolvePath(arg);
        if (server._useHdl) {
          cmdSocket.respond("550", "not capable");
        } else if (!allowFolderDelete || folder === basefolder) {
          cmdSocket.respond("550", "Permission denied");
        } else if (!server.directoryExists(folder)) {
          cmdSocket.respond("550", "Folder not found");
        } else {
          fs.rmSync(folder, { force: true, recursive: true });
          cmdSocket.respond("250", "Folder deleted successfully");
        }
      }

      /*
       *  MKD
       */
      function MKD(cmd, arg) {
        const folder = resolvePath(arg);
        if (server._useHdl) {
          cmdSocket.respond("550", "not capable");
        } else if (!allowFolderCreate) {
          cmdSocket.respond("550", "Permission denied");
        } else if (server.directoryExists(folder)) {
          cmdSocket.respond("550", "Folder exists");
        } else {
          fs.mkdirSync(folder, { recursive: true });
          cmdSocket.respond("250", "Folder created successfully");
        }
      }

      /*
       *  LIST
       *  MLSD
       */
      function LIST(cmd, arg) {
        const isMLSD = cmd === "MLSD";
        openDataSocket().then(async (dataSocket) => {
            if (dataSocket && cmdSocket && folderPath) {
              asciiOn && dataSocket.setEncoding("ascii");
              let listData = "";
              if (server._useHdl) {
                const data = await server._opt.hdl.list(
                  username,
                  folderPath,
                  isMLSD
                );
                data && (listData = data);
              } else {
                const read = fs.readdirSync(path.join(basefolder, folderPath));
                for (let i = 0; i < read.length; i++) {
                  const file = path.join(
                    basefolder,
                    folderPath,
                    read[i].trim()
                  );
                  const stat = fs.statSync(file);
                  if (isMLSD === true) {
                    listData += util.format(
                      "type=%s;modify=%s;%s %s\r\n",
                      stat.isDirectory() ? "dir" : "file",
                      getDateForMLSD(stat.mtime),
                      stat.isDirectory() ? "" : "size=" + stat.size.toString() + ";",
                      read[i].trim()
                    );
                  } else {
                    listData += util.format(
                      "%s 1 %s %s %s %s %s\r\n",
                      stat.isDirectory() ? "dr--r--r--" : "-r--r--r--", // ignoring other node types: sym-links, pipes, etc.
                      // skipping n-links
                      username, // uid
                      username, // gid
                      String(stat.isDirectory() ? "0" : stat.size).padStart(14, " "),
                      getDateForLIST(stat.mtime),
                      read[i].trim()
                    );
                  }
                }
              }
              if (listData.length === 0) {
                listData = "\r\n";
              }
              server.DebugHandler(
                `${remoteInfo} LIST response on data channel\r\n${listData}`
              );
              dataSocket.end(Buffer.from(listData));
              cmdSocket.respond(
                "226",
                `Successfully transferred "${folderPath}"`
              );
            }
          },
          () => {
            cmdSocket.respond("501", "Command failed");
          }
        );
      }

      /*
       *  RETR
       */
      function RETR(cmd, arg) {
        const relativeFile = arg;
        const file = resolvePath(arg),
          fileExists = server.fileExists(file);
        if (!allowFileRetrieve) {
          cmdSocket.respond("550", `Transfer denied "${relativeFile}"`);
        } else if (!fileExists) {
          cmdSocket.respond("550", `Transfer failed "${relativeFile}"`);
        } else {
          openDataSocket().then(async (dataSocket) => {
              if (dataSocket && cmdSocket && file && relativeFile) {
                asciiOn && dataSocket.setEncoding("ascii");
                if (server._useHdl) {
                  // hey, what about getting a ReadableStream from handler?
                  const data = await server._opt.hdl.download(
                    username,
                    folderPath,
                    relativeFile,
                    restOffset
                  );
                  if (Buffer.isBuffer(data)) {
                    dataSocket.end(data);
                    cmdSocket.respond(
                      "226",
                      `Successfully transferred "${relativeFile}"`
                    );
                  } else {
                    dataSocket.end();
                    cmdSocket.respond(
                      "550",
                      `Transfer failed "${relativeFile}"`
                    );
                  }
                } else {
                  const readStream = fs.createReadStream(file, {
                    flags: "r",
                    start: restOffset,
                    encoding: asciiOn ? "ascii" : null,
                    autoClose: true,
                    emitClose: true,
                  });
                  readStream.on("error", server.ErrorHandler);
                  readStream.on("open", () => {
                    dataSocket.on("close", () => {
                      // write error?
                      readStream.destroy();
                      cmdSocket.respond(
                        "426",
                        `Connection closed. Aborted transfer of "${relativeFile}"`
                      );
                    });
                    readStream.pipe(dataSocket);
                  });
                  readStream.on("close", () => {
                    // end of file?
                    dataSocket.end();
                    cmdSocket.respond(
                      "226",
                      `Successfully transferred "${relativeFile}"`
                    );
                  });
                }
                restOffset = 0;
              }
            },
            () => {
              cmdSocket.respond("501", "Command failed");
            }
          );
        }
      }

      /*
       *  STOR
       */
      function STOR(cmd, arg) {
        const relativeFile = arg;
        const file = resolvePath(arg),
          fileExists = server.fileExists(file);
        if (!(fileExists ? allowFileOverwrite : allowFileCreate)) {
          cmdSocket.respond("550", `Permission denied${fileExists ? ", File already exists":""}`);
        } else {
          openDataSocket().then((dataSocket) => {
              if (dataSocket && cmdSocket && relativeFile) {
                asciiOn && dataSocket.setEncoding("ascii");
                if (server._useHdl) {
                  // hey, what about giving handler a ReadableStream?
                  const data = [];
                  dataSocket.on("data", (d) => data.push(d));
                  dataSocket.on("close", async () => {
                    const success = await server._opt.hdl.upload(
                      username,
                      folderPath,
                      relativeFile,
                      Buffer.concat(data),
                      restOffset
                    );
                    if (success === true) {
                      cmdSocket.respond(
                        "226",
                        `Successfully transferred "${relativeFile}"`
                      );
                    } else {
                      cmdSocket.respond(
                        "550",
                        `Transfer failed "${relativeFile}"`
                      );
                    }
                    restOffset = 0;
                  });
                } else {
                  const writeStream = fs.createWriteStream(file, {
                    flags: restOffset > 0 ? "a+" : "w",
                    start: restOffset,
                    encoding: asciiOn ? "ascii" : null,
                    autoClose: true,
                    emitClose: true,
                  });
                  writeStream.on("error", server.ErrorHandler);
                  writeStream.on("open", () => {
                    dataSocket.on("close", () => {
                      // end of file?
                      writeStream.destroy();
                      cmdSocket.respond(
                        "226",
                        `Successfully transferred "${relativeFile}"`
                      );
                    });
                    dataSocket.pipe(writeStream);
                  });
                  writeStream.on("end", () => {
                    // write error?
                    dataSocket.end();
                    cmdSocket.respond(
                      "550",
                      `Transfer failed "${relativeFile}"`
                    );
                  });
                  restOffset = 0;
                }
              }
            },
            () => {
              cmdSocket.respond("501", "Command failed");
            }
          );
        }
      }

      /*
       *  RNFR
       */
      function RNFR(cmd, arg) {
        const file = resolvePath(arg);
        if (!allowFileRename) {
          cmdSocket.respond("550", "Permission denied");
        } else if (!server.fileExists(file)) {
          cmdSocket.respond("550", "File does not exist");
        } else {
          renameFile = file;
          cmdSocket.respond("350", "File exists");
        }
      }

      /*
       *  RNTO
       */
      async function RNTO(cmd, arg) {
        const file = resolvePath(arg); // or folder?
        if (!allowFileRename) {
          cmdSocket.respond("550", "Permission denied");
        } else if (server.fileExists(file)) {
          cmdSocket.respond("550", "File already exists");
        } else if (server._useHdl === true) {
          const success = await server._opt.hdl.rename(
            username,
            folderPath,
            renameFile
              .substring(basefolder.length)
              .substring(folderPath.length),
            file.substring(basefolder.length).substring(folderPath.length)
          );
          if (success === true) {
            cmdSocket.respond("250", "File renamed successfully");
          } else {
            cmdSocket.respond("550", "File rename failed");
          }
          renameFile = "";
        } else  {
          fs.renameSync(renameFile, file);
          cmdSocket.respond("250", "File renamed successfully");
          renameFile = "";
        }


      }

      /*
       *  MFMT
       */
      function MFMT(cmd, arg) {
        let [time, file] = arg.split(" ");
        file = resolvePath(file);
        if (server._useHdl) {
          cmdSocket.respond("550", "not capable");
        } else if (!server.fileExists(file)) {
          cmdSocket.respond("550", "File does not exist");
        } else {
          const mtime = getDateForMFMT(time);
          fs.utimesSync(file, mtime, mtime);
          cmdSocket.respond("253", "Date/time changed okay");
        }
      }
    }

    function setUserRights(user) {
      if ( Object.prototype.hasOwnProperty.call(user, "basefolder") && server.directoryExists(user.basefolder) ) {
        basefolder = user.basefolder;
        folderPath = "/";
      }
      Object.prototype.hasOwnProperty.call(user, "username") &&
        (username = user.allowUserFileCreate);
      Object.prototype.hasOwnProperty.call(user, "allowUserFileCreate") &&
        (allowFileCreate = user.allowUserFileCreate);
      Object.prototype.hasOwnProperty.call(user, "allowUserFileRetrieve") &&
        (allowFileRetrieve = user.allowUserFileRetrieve);
      Object.prototype.hasOwnProperty.call(user, "allowUserFileOverwrite") &&
        (allowFileOverwrite = user.allowUserFileOverwrite);
      Object.prototype.hasOwnProperty.call(user, "allowUserFileDelete") &&
        (allowFileDelete = user.allowUserFileDelete);
      Object.prototype.hasOwnProperty.call(user, "allowUserFileRename") &&
        (allowFileRename = user.allowUserFileRename);
      Object.prototype.hasOwnProperty.call(user, "allowUserFolderDelete") &&
        (allowFolderDelete = user.allowUserFolderDelete);
      Object.prototype.hasOwnProperty.call(user, "allowUserFolderCreate") &&
        (allowFolderCreate = user.allowUserFolderCreate);
    }

    function openPassiveChannel() {
      if (pasvChannel) {
        pasvChannel.close();
        pasvSocket = new Promise<Socket>((resolve, reject) => {
          setPasvSocket = { resolve, reject };
        });
      }
      return new Promise<SocketAddress>((resolve) => {
        if (isEncrypted === true && shouldProtect === true) {
          pasvChannel = tls.Server(server._opt.tls);
          pasvChannel.on("secureConnection", (socket) => {
            server.DebugHandler(
              `${remoteInfo} secure data connection established`
            );
            setPasvSocket.resolve(socket);
          });
        } else {
          pasvChannel = net.Server();
          pasvChannel.on("connection", (socket) => {
            if (isEncrypted === true && shouldProtect === true) {
              socket = new tls.TLSSocket(socket, {
                isServer: true,
                secureContext: tls.createSecureContext(server._opt.tls),
              });
              socket.on("secure", () => {
                server.DebugHandler(`${remoteInfo} data connection is secure`);
                setPasvSocket.resolve(socket);
              });
            } else {
              setPasvSocket.resolve(socket);
            }
            server.DebugHandler(`${remoteInfo} data connection established`);
          });
        }
        pasvChannel.on("error", server.ErrorHandler);
        pasvChannel.maxConnections = 1;
        return findAvailablePort().then((port) => {
          pasvChannel.listen(port, () => {
            pasv = true;
            resolve(pasvChannel.address());
          });
        });
      });
    }

    function findAvailablePort() {
      const { minDataPort, maxConnections } = server._opt.cnf;
      return new Promise((resolve, reject) => {
        if (minDataPort > 0 && minDataPort < 65535) {
          function checkListenPort(port) {
            const server = net.createServer(); // throwaway
            server.once("error", function (_err) {
              if (port < minDataPort + maxConnections) {
                checkListenPort(port + 1);
              } else {
                reject();
              }
            });
            server.once("listening", function () {
              server.close();
            });
            server.once("close", function () {
              resolve(port);
            });
            server.listen(port);
          }
          checkListenPort(minDataPort);
        } else {
          reject();
        }
      });
    }

    function openDataSocket() {
      return new Promise<Socket>((resolve, reject) => {
        if (actv === true || pasv === true) {
          cmdSocket.respond("150", "Opening data channel");
          if (actv === true) {
            server.DebugHandler(
              `${remoteInfo} openDataChannel isSecure[${isEncrypted}] protection[${shouldProtect}] addr[${addr}] port[${port}]`
            );
            let socket = net.connect(port, addr, () => {
              if (isEncrypted === true && shouldProtect === true) {
                socket = new tls.TLSSocket(socket, {
                  isServer: true,
                  secureContext: tls.createSecureContext(server._opt.tls),
                });
                socket.on("secure", () => {
                  server.DebugHandler(
                    `${remoteInfo} data connection is secure`
                  );
                  resolve(socket); // data connection resolved
                });
              } else {
                resolve(socket); // data connection resolved
              }
            });
            socket.on("error", server.ErrorHandler);
          } else {
            resolve(pasvSocket);
          }
        } else {
          reject();
        }
      });
    }

    function resolvePath(newPath) {
      const absolutePath = path.join(
        basefolder,
        newPath.charAt(0) === "/" ? "" : folderPath,
        newPath
      );
      if (absolutePath.startsWith(basefolder)) {
        return absolutePath;
      }

      return basefolder;
    }
  }

  validateLoginType(username) {
    if (username === "anonymous" && this._opt.cnf.allowAnonymousLogin) {
      return LoginType.Anonymous;
    } else if (this._opt.cnf.user.length > 0) {
      for (let i = 0; i < this._opt.cnf.user.length; i++) {
        const u = Object.assign({}, UserDefaults, this._opt.cnf.user[i]);
        if (typeof u === "object" && username === u.username) {
          if (
            Object.prototype.hasOwnProperty.call(
              u,
              "allowLoginWithoutPassword"
            ) &&
            u.allowLoginWithoutPassword
          ) {
            return [LoginType.NoPassword, u];
          } else {
            return [LoginType.Password];
          }
          break;
        }
      }
    } else if (username === this._opt.cnf.username) {
      if (this._opt.cnf.allowLoginWithoutPassword === true) {
        return [LoginType.NoPassword, this._opt.cnf];
      } else {
        return [LoginType.Password];
      }
    }
    return [LoginType.None];
  }

  authenticateUser(username, password) {
    if (username === "anonymous" && this._opt.cnf.allowAnonymousLogin) {
      return {
        username: password,
        allowFileCreate: this._opt.cnf.allowAnonymousFileCreate,
        allowFileRetrieve: this._opt.cnf.allowAnonymousFileRetrieve,
        allowFileOverwrite: this._opt.cnf.allowAnonymousFileOverwrite,
        allowFileDelete: this._opt.cnf.allowAnonymousFileDelete,
        allowFileRename: this._opt.cnf.allowAnonymousFileRename,
        allowFolderDelete: this._opt.cnf.allowAnonymousFolderDelete,
        allowFolderCreate: this._opt.cnf.allowAnonymousFolderCreate,
      };
    }
    if (this._opt.cnf.user.length > 0) {
      for (let i = 0; i < this._opt.cnf.user.length; i++) {
        const u = Object.assign({}, UserDefaults, this._opt.cnf.user[i]);
        if (
          typeof u === "object" &&
          username === u.username &&
          (u.allowLoginWithoutPassword === true || // this case was handled by validateLoginType
            password === u.password)
        ) {
          return u;
        }
      }
    } else if (
      username === this._opt.cnf.username &&
      (this._opt.cnf.allowLoginWithoutPassword === true || // this case was handled by validateLoginType
        password === this._opt.cnf.password)
    ) {
      return this._opt.cnf;
    }
  }

  directoryExists(folder) {
    return fs.existsSync(folder) && fs.statSync(folder).isDirectory() || this._useHdl;
  }

  fileExists(file) {    
    return fs.existsSync(file) && fs.statSync(file).isFile() || this._useHdl;
  }
}

function getDateForLIST(mtime) {
  const now = new Date(mtime);
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
  ][now.getMonth()];
  const DD = now.getDate().toString().padStart(2, "0");
  const H = now.getHours().toString().padStart(2, "0");
  const M = now.getMinutes().toString().padStart(2, "0");
  return `${MM} ${DD} ${H}:${M}`;
}

function getDateForMLSD(mtime) {
  const now = new Date(mtime);
  const MM = (now.getMonth() + 1).toString().padStart(2, "0");
  const DD = now.getDate().toString().padStart(2, "0");
  const H = now.getHours().toString().padStart(2, "0");
  const M = now.getMinutes().toString().padStart(2, "0");
  const S = now.getSeconds().toString().padStart(2, "0");
  return `${now.getFullYear()}${MM}${DD}${H}${M}${S}`;
}

function getDateForMFMT(time) {
  // expect format YYYYMMDDhhmmss
  const Y = time.substr(0, 4);
  const M = time.substr(4, 2);
  const D = time.substr(6, 2);
  const Hrs = time.substr(8, 2);
  const Min = time.substr(10, 2);
  const Sec = time.substr(12, 2);
  return Date.parse(`${Y}-${M}-${D}T${Hrs}:${Min}:${Sec}+00:00`) / 1000;
}

function getDateForLogs(date?: Date) {
  const now = date || new Date();
  const MM = (now.getMonth() + 1).toString().padStart(2, "0");
  const DD = now.getDate().toString().padStart(2, "0");
  const H = now.getHours().toString().padStart(2, "0");
  const M = now.getMinutes().toString().padStart(2, "0");
  const S = now.getSeconds().toString().padStart(2, "0");
  return `${DD}.${MM}.${now.getFullYear()} - ${H}:${M}:${S}`;
}
