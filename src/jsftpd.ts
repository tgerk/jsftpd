/*
 * @package jsftpd
 * @author Sven <mailsvb@gmail.com>
 * @author Tim Gerk <tjgerk@gmail.com>
 * @license https://github.com/mailsvb/jsftpd/blob/main/LICENSE MIT License
 */

import tls, { TlsOptions } from "tls";
import util from "util";
import net, { Socket, AddressInfo } from "net";
import path from "path";
import fs from "fs";
import { EventEmitter } from "events";

const defaultBaseFolder = path.join(__dirname, "jsftpd-tmp");
const defaultCert = Buffer.from(
  "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdHpOM1dKdHE5MjAzYWQ0eFRxb2hHM3hLUVdvUnJFejArd3JTUnNhZitMQTQzSWQ4CjRWUUU0elpsaEhSRVJzSGJjQkdGd0dNTEwxaGJXTWc3eDErSFhKYXlxNXJwcldTZ1g4TVRwZllkN2RUNkxRT3oKdmdBTUx3WUJwM3VkYm5IM2tyUERQazBibWRDcTZ4RmxqaUR4bHB6dWxIN1Vqb2crRE1XYmdpVHFYU2YrUThZTwpXS2xVRXhMVzZ5L3hFNUNIVVN3ZGI3MWREc2pDSG90YWliTTNXdlpGdEc3MnAvUXBaWldtZmQreEQwL3VoVnhNCnBualR0S21xWlMwcnJZM3Y1SFR5dVpBMUJRMFBVWmV0NzdLdWZKUis2aVlzQjQ4Z3NSM0szNmd6WHoyMzRXUXUKbEppcWk0dXo4Wjk1LzQyZmJOUlR3eWxRZXBQY1Ruc0Rib0Y0Q1FJREFRQUJBb0lCQVFDanR1UmlWSkVraDM5TApwbm9kdUQ5WjFwcHRGcUt3ZlIwMzhwV3pGZkVEUmtlcUc1SG5zek9pOEl1TDhITExZSlgrOGttNmdVZ1BpVUFvCmVOZWk5YVY3Z2xnc3JvVkFwSG9FMmNtSE9BZks3OWFadjRNeXVjd3BnWTZjNHdUdkcvMklKZ2pHZGhYQ1FRMWMKZi9Gbkw5MTFJTXk3K3hOc1JDaGZOWUFncjJpWTBZOUpRQndncTlJM1BWZ1RGQUtkTTBKZ1hySzhXVCtsN3NDRQpWc0kyUkVnYUxzeUxud2VmYnRwbVV0ankrbWtLemIzcnNyY1JVVmJOZjB3aEFlTG9HS01wZjVPNVUzMVNjd2xwClB2RnpHWkUyM01HbHpheGpZVVJTVmV3TFlzR2dwNTg5SDF6WmZaQVhSRWRiOEx2MGYra0I5MSthUi9Hdy9IT3gKS3ZlVXEvTVpBb0dCQU9BQkhxWWdXNmFwM3BjMjZJNVdNNURrMnJ1TnArRENQbzJUV3RRTklwTlREMEorRWt6SgpMZ1ZEK0xGVWZmNDFTQlZEbWZXR2x3cnVtajdWWGtTbjZyWmZXQUVKYTBySkljdHV3TDcxQ1Y0Q280cnFsUGlpCnhEazdhUFpYSXJBcjdaOG5UOG1kVStmcENMS1FNVUhYY0wydDI0cE85NytFVGVycVVYcGtEQXVEQW9HQkFORmUKVitZYThuVGxjVVhkbktqQVU4czJNSlhUUFZkeDlIM3BzQjNOVjJtR2lmM1h2d2F6ei9mYTg5NG5Ha3FxS2N6cwppV1BLdlR0MytVdUwxSlhWSlcwMllycHpUMlpMd2lqY3pCQlc1OGtIeU9UUGZ4UENjemh1dGlQUHJoMnQwbGJtCkR6WFpuTzJPUlpJWlp3MFllVFlNVzFUcnZ3WnRpT0VxMFp4cVVkeURBb0dBYld0K21pMmlOMll3NmZLVFpMdnMKMG5GSCsyZTF3bzkvMk01TEJ0d25zSWxaSWVUTmNaNndFVGhqcWRPWSsrencraG9jZ1pldC9sUVJHbkpGYXdvUApGK2k0NTBDL25UZGtmNmZwRlI1QzVoNHAzdmk1cmo1cjFYMFV4NGhHMUlHUXdEYUd2ZmhRL1M2UzVnNlRVUk00CjZoNmI2QktzNkd0cldEMy9jT2FnRDVzQ2dZQXpwNHdXS0dYVE0xeHIrVTRTVUVrY0pNVjk0WDBMMndDUUpCeWcKYmEzNFNnbzNoNGdJdGtwRUExQVJhaUpSYzRRV20vRVZuc3BySnFGcDR4alMwcUNHUGxuRFdIbXBhbDEveVdITApValdqWW5sTkFtaCt6b1d3MFplOFpCdTRGTStGUXdOVHJObkx2a01wMVh5WVBZYUNNREJFVmxsdDA0NW14ektwCjNZMU8wd0tCZ0FHaVkyNVZLOGJyMVFydXlzM3Vhb21LQ3BYUmhjZU15eHdBazdxeUlpNnpHeEx3bnFaVldaQmQKbkcxbkFaT2JET1JSTGRBRktPZ2tncGtVbGgrTEE3dTRuUytGWEdteGtLZlF1cTNTcTNaWHhiTjMxcXBCcERHTQoxbE9QSlVWY2UxV3ZyeXcrWVI4M1VFQ0ZTOEZjeDdibEVEM3oyNnVOQnN0dlBwVTUrV3ZxCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDNGpDQ0FjcWdBd0lCQWdJSWJqQ2hhajZDT2Iwd0RRWUpLb1pJaHZjTkFRRUxCUUF3RVRFUE1BMEdBMVVFCkF4TUdhbk5tZEhCa01DQVhEVEl3TURFd01UQXdNREF3TUZvWUR6azVPVGt4TWpNeE1qTTFPVFU1V2pBUk1ROHcKRFFZRFZRUURFd1pxYzJaMGNHUXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDMwpNM2RZbTJyM2JUZHAzakZPcWlFYmZFcEJhaEdzVFBUN0N0Skd4cC80c0RqY2gzemhWQVRqTm1XRWRFUkd3ZHR3CkVZWEFZd3N2V0Z0WXlEdkhYNGRjbHJLcm11bXRaS0Jmd3hPbDloM3QxUG90QTdPK0FBd3ZCZ0duZTUxdWNmZVMKczhNK1RSdVowS3JyRVdXT0lQR1duTzZVZnRTT2lENE14WnVDSk9wZEovNUR4ZzVZcVZRVEV0YnJML0VUa0lkUgpMQjF2dlYwT3lNSWVpMXFKc3pkYTlrVzBidmFuOUNsbGxhWjkzN0VQVCs2RlhFeW1lTk8wcWFwbExTdXRqZS9rCmRQSzVrRFVGRFE5Umw2M3ZzcTU4bEg3cUppd0hqeUN4SGNyZnFETmZQYmZoWkM2VW1LcUxpN1B4bjNuL2paOXMKMUZQREtWQjZrOXhPZXdOdWdYZ0pBZ01CQUFHalBEQTZNQXdHQTFVZEV3RUIvd1FDTUFBd0hRWURWUjBPQkJZRQpGQkRRdzE4NC91Qk5zMHlxczVqaU92dnd4TFBTTUFzR0ExVWREd1FFQXdJRjREQU5CZ2txaGtpRzl3MEJBUXNGCkFBT0NBUUVBaWdSa0draEMxeTVMendOQ0N1T0I5eUsyS2NkUGJhcm9lZGlSWVVxZmpVU2JsT3NweWFTNjEvQjgKVk9UdHZSRjBxZkJFZTVxZVhVUTRIV1JGSnRVZmQ1eisvZTRZNkJHVmR3eFJ5aktIYkVGQ3NpOFlFZDNHOTdaZwpWM1RFV08xVVlCTlJhN2tZajE2QXFDOWtXaG5WRVU3bUdRWE5nR1NJaDNNTmx5RG1RblBIdHdzS2d3cUs5VWcvCk9QVUhUNGlTa2h2OEVoTjYyUFlRaHBEaU1udWFQbUZ1bGVKbmllQnNFMTlvSVBtbWsxblRIZXRPZDg4VU1PeUEKWDFKY0ZBZXI2dmVPQkxVMUhRSEdtd1Iyalgzai83YzI3SjJFdjRQWW1rU2R2N0FYcm5LaENDeGRSblA2WDlGaApTYlEwRHBhbW5zaWFEWld4QzNuUks2LzVndXdlOHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
  "base64"
);

interface FTPCmdHandlers {
  upload: (
    username: string,
    folder: string,
    file: string,
    data: Buffer,
    restOffset: number
  ) => Promise<void>;
  download: (
    username: string,
    folder: string,
    file: string,
    restOffset: number
  ) => Promise<Buffer>;
  list: (username: string, folder: string, format: FTPCmdLsFormat) => [string];
  rename: (
    username: string,
    folder: string,
    fromFile: string,
    toFile: string
  ) => Promise<void>;
}

type UserCredential = {
  username: string,
  password?: string,
  basefolder?: string;
}

type UserOptions = {
  allowLoginWithoutPassword?: boolean;
  allowUserFileCreate?: boolean;
  allowUserFileRetrieve?: boolean;
  allowUserFileOverwrite?: boolean;
  allowUserFileDelete?: boolean;
  allowUserFileRename?: boolean;
  allowUserFolderDelete?: boolean;
  allowUserFolderCreate?: boolean;
};

type FTPdOptions = UserOptions & {
  port?: number;
  securePort?: number;
  maxConnections?: number;
  minDataPort?: number;
  basefolder?: string;

  allowAnonymousLogin?: boolean;
  allowAnonymousFileCreate?: boolean;
  allowAnonymousFileRetrieve?: boolean;
  allowAnonymousFileOverwrite?: boolean;
  allowAnonymousFileDelete?: boolean;
  allowAnonymousFileRename?: boolean;
  allowAnonymousFolderDelete?: boolean;
  allowAnonymousFolderCreate?: boolean;
  
  username?: string;
  password?: string;
  allowLoginWithoutPassword?: boolean;

  user?: (UserCredential & UserOptions)[];
};

type FTPCmdLsFormat = "MSLD" | null;

const FTPdefaults: FTPdOptions = {
  port: 21,
  securePort: 990,
  maxConnections: 10,
  minDataPort: 1024,
  basefolder: defaultBaseFolder,
  
  allowAnonymousLogin: false,
  allowAnonymousFileCreate: false,
  allowAnonymousFileRetrieve: false,
  allowAnonymousFileOverwrite: false,
  allowAnonymousFileDelete: false,
  allowAnonymousFileRename: false,
  allowAnonymousFolderDelete: false,
  allowAnonymousFolderCreate: false,
  
  user: [],
};

const TLSserverDefaults: TlsOptions = {
  key: defaultCert,
  cert: defaultCert,
  honorCipherOrder: true,
  rejectUnauthorized: false,
};

const UserDefaults: UserOptions = {
  allowLoginWithoutPassword: false,
  allowUserFileCreate: true,
  allowUserFileRetrieve: true,
  allowUserFileOverwrite: true,
  allowUserFileDelete: true,
  allowUserFileRename: true,
  allowUserFolderDelete: true,
  allowUserFolderCreate: true,
};

enum LoginType {
  None,
  Anonymous,
  Password,
  NoPassword,
};

export function ftpd(options: FTPdOptions & { cnf?: FTPdOptions, tls?: TlsOptions, hdl?: FTPCmdHandlers }) {
  let lastSessionKey = 0;
  const openSessions = {};

  // options
  const usingTLS = "tls" in options;
  const usingHandlers = "hdl" in options;
  const config = {
    ...FTPdefaults, ...UserDefaults, ...options, ...options.cnf,
    tls: { ...TLSserverDefaults, ...options?.tls },
    handler: options?.hdl,
  };

  // checks
  if (!folderExists(config.basefolder)) {
    if (config.basefolder === defaultBaseFolder) {
      fs.mkdirSync(defaultBaseFolder);
    } else {
      throw new Error("Basefolder must exist");
    }
  }

  // setup FTP on TCP
  const tcpServer = net.createServer();
  tcpServer.on("error", ErrorHandler);
  tcpServer.on("listening", (server) => {
    emitListen("tcp", server.address());
  });
  tcpServer.on("connection", SessionHandler);
  tcpServer.maxConnections = config.maxConnections;

  // setup FTP on TLS
  const tlsServer = usingTLS && tls.createServer(config.tls);
  if (usingTLS) {
    tlsServer.on("error", ErrorHandler);
    tlsServer.on("listening", (server) => {
      emitListen("tls", server.address());
    });
    tlsServer.on("secureConnection", SessionHandler);
    tlsServer.maxConnections = config.maxConnections;
  }

  function SessionHandler(cmdSocket) {
    const socketKey = ++lastSessionKey;
    openSessions[socketKey] = cmdSocket;

    const localAddr = cmdSocket.localAddress.replace(/::ffff:/g, "");
    const remoteAddr = cmdSocket.remoteAddress.replace(/::ffff:/g, "");
    const remoteInfo = `[${remoteAddr}] [${cmdSocket.remotePort}]`;

    let isEncrypted = cmdSocket.encrypted || false;
    let pbszReceived = false;
    let shouldProtect = false;

    let asciiOn = false;

    let pasv = true;
    let pasvChannel: net.Server = null;
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

    let basefolder: string = config.basefolder;
    let folderPath = "/";
    let renameFile = "";
    let restOffset = 0;

    cmdSocket.on("error", ErrorHandler);
    cmdSocket.on("data", CmdHandler);
    cmdSocket.on("close", () => {
      delete openSessions[socketKey];
      DebugHandler(`${remoteInfo} FTP connection closed`);
      if (pasvChannel) {
        pasvChannel.close();
      }
    });

    cmdSocket.respond = function (code, message, delimiter = " ") {
      LogHandler(`${remoteInfo} > ${code} ${message}`);
      this.writable &&
        this.write(Buffer.from(`${code}${delimiter}${message}\r\n`));
    };

    DebugHandler(`${remoteInfo} new FTP connection established`);
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
        DebugHandler(
          `${remoteInfo} < ${data.trim().replace(/^PASS\s.*$/i, "PASS ***")}`
        );
        let [cmd, ...arg] = data.split(" ");
        cmd = cmd.trim();
        arg = arg.join(" ").trim();
        LogHandler(
          `${remoteInfo} cmd[${cmd}] arg[${cmd === "PASS" ? "***" : arg}]`
        );
        if (authenticated) {
          if (cmd in authenticatedFunc) {
            authenticatedFunc[cmd](cmd, arg);
          } else {
            cmdSocket.respond("500", "Command not implemented");
          }
        } else if (cmd in preAuthFunctions) {
          preAuthFunctions[cmd](cmd, arg);
        } else {
          cmdSocket.respond("530", "Not logged in");
          cmdSocket.close();
        }
      } catch (err) {
        LogHandler(`${remoteInfo} ${err.message}`);
        ErrorHandler(err);
        cmdSocket.respond("550", "Unexpected server error");
        cmdSocket.close();
      }

      /*
       *  USER
       */
      function USER(cmd, arg) {
        authenticated = false;
        folderPath = "/";
        username = arg;
        const [loginType, userRights] = validateLoginType(username);
        switch (loginType) {
          case LoginType.None:
            cmdSocket.respond("530", "Not logged in");
            break;
          case LoginType.Anonymous:
          case LoginType.Password:
            cmdSocket.respond("331", `Password required for ${username}`);
            break;
          case LoginType.NoPassword:
            DebugHandler(
              `${remoteInfo} password-less username[${username}] authenticated`
            );
            authenticated = true;
            setUserRights(userRights);
            cmdSocket.respond("232", "User logged in");
            emitLogin(username, remoteAddr);
            break;
          default:
            cmdSocket.respond("331", `Password required for ${username}`);
        }
      }

      /*
       *  PASS
       */
      function PASS(cmd, arg) {
        const userRights = authenticateUser(username, arg);
        if (userRights) {
          authenticated = true;
          setUserRights(userRights);
          cmdSocket.respond("230", "Logged on");
          emitLogin(username, remoteAddr);
        } else {
          cmdSocket.respond("530", "Username or password incorrect");
          cmdSocket.end();
        }
        DebugHandler(
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
            secureContext: tls.createSecureContext(config.tls),
          });
          cmdSocket.on("secure", () => {
            DebugHandler(`${remoteInfo} secure connection established`);
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
        authenticated && emitLogoff(username, remoteAddr);
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
          (port) => {
            pasv = true;
            DebugHandler(
              `${remoteInfo} listening on ${port} for data connection`
            );
            cmdSocket.respond(
              "227",
              util.format(
                "Entering passive mode (%s,%d,%d)",
                localAddr.split(".").join(","),
                (port / 256) | 0,
                port % 256
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
          (port) => {
            pasv = true;
            DebugHandler(
              `${remoteInfo} listening on ${port} for data connection`
            );
            cmdSocket.respond(
              "229",
              util.format(
                "Entering extended passive mode (|||%d|)",
                port
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
       *  CWD
       */
      function CWD(cmd, arg) {
        const path = resolvePath(arg);
        if (!folderExists(path)) {
          // or user has no access?
          cmdSocket.respond("530", "CWD not successful");
        } else {
          folderPath = path.substring(basefolder.length) || "/";
          cmdSocket.respond(
            "250",
            `CWD successful. "${folderPath}" is current directory`
          );
        }
      }

      /*
       *  RMD
       *  RMDA
       */
      function RMD(cmd, arg) {
        const folder = resolvePath(arg);
        if (!allowFolderDelete || folder === basefolder) {
          cmdSocket.respond("550", "Permission denied");
        } else if (!folderExists(folder)) {
          cmdSocket.respond("550", "Folder not found");
        } else {
          folderDelete(folder);
          cmdSocket.respond("250", "Folder deleted successfully");
        }
      }

      /*
       *  MKD
       */
      function MKD(cmd, arg) {
        const folder = resolvePath(arg);
        if (!allowFolderCreate) {
          cmdSocket.respond("550", "Permission denied");
        } else if (folderExists(folder)) {
          cmdSocket.respond("550", "Folder exists");
        } else {
          folderCreate(folder);
          cmdSocket.respond("250", "Folder created successfully");
        }
      }

      /*
       *  SIZE
       */
      function SIZE(cmd, arg) {
        const file = resolvePath(arg);
        if (!fileExists(file)) {
          cmdSocket.respond("550", "File not found");
        } else {
          const fstat = fileStat(file);
          cmdSocket.respond("213", fstat.size.toString());
        }
      }

      /*
       *  DELE
       */
      function DELE(cmd, arg) {
        const file = resolvePath(arg);
        if (!allowFileDelete) {
          cmdSocket.respond("550", "Permission denied");
        } else if (!fileExists(file)) {
          cmdSocket.respond("550", "File not found");
        } else {
          fileDelete(file);
          cmdSocket.respond("250", "File deleted successfully");
        }
      }

      /*
       *  LIST
       *  MLSD
       */
      function LIST(cmd, arg) {
        openDataSocket()
          .then((socket) => {
            const folderListing =
              folderList(username, [basefolder, folderPath], cmd).join("\r\n");
            DebugHandler(
              `${remoteInfo} LIST response on data channel\r\n${folderListing}`
            );
            socket.end(Buffer.from(folderListing || "\r\n"));
          })
          .then(
            () => {
              cmdSocket.respond(
                "226",
                `Successfully transferred "${folderPath}"`
              );
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
        const file = resolvePath(arg);
        if (!allowFileRetrieve) {
          cmdSocket.respond("550", `Transfer denied "${relativeFile}"`);
        } else if (!fileExists(file)) {
          cmdSocket.respond("550", `Transfer failed "${relativeFile}"`);
        } else {
          fileRetrieve(
            username,
            [folderPath, relativeFile],
            file,
            restOffset,
            asciiOn ? "ascii" : null
          )
            .then(
              (data) => {
                openDataSocket().then((socket) => {
                  if (data instanceof fs.ReadStream) {
                    data.on("error", ErrorHandler);
                    data.on("open", () => {
                      socket.on("close", () => {
                        // write error?
                        data.destroy();
                        cmdSocket.respond(
                          "426",
                          `Connection closed. Aborted transfer of "${relativeFile}"`
                        );
                      });
                      data.pipe(socket);
                    });
                    data.on("close", () => {
                      // end of file?
                      socket.end();
                      cmdSocket.respond(
                        "226",
                        `Successfully transferred "${relativeFile}"`
                      );
                    });
                    restOffset = 0;
                  } else if (Buffer.isBuffer(data)) {
                    socket.end(data);
                    cmdSocket.respond(
                      "226",
                      `Successfully transferred "${relativeFile}"`
                    );
                    restOffset = 0;
                  } else {
                    socket.end();
                    cmdSocket.respond(
                      "550",
                      `Transfer failed "${relativeFile}"`
                    );
                  }
                });
              },
              () => {
                cmdSocket.respond("501", "Command failed");
              }
            )
            .finally(() => {
              restOffset = 0;
            });
        }
      }

      /*
       *  STOR
       */
      function STOR(cmd, arg) {
        const relativeFile = arg;
        const file = resolvePath(arg);
        if (!(fileExists(file) ? allowFileOverwrite : allowFileCreate)) {
          cmdSocket.respond("550", `Permission denied`);
        } else {
          openDataSocket().then(
            (socket) => {
              fileStore(
                socket,
                username,
                [folderPath, relativeFile],
                file,
                restOffset,
                asciiOn ? "ascii" : null
              )
                .then(
                  () => {
                    cmdSocket.respond(
                      "226",
                      `Successfully transferred "${relativeFile}"`
                    );
                  },
                  () => {
                    cmdSocket.respond(
                      "550",
                      `Transfer failed "${relativeFile}"`
                    );
                  }
                )
                .finally(() => {
                  restOffset = 0;
                });
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
        } else if (!fileExists(file)) {
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
        } else if (fileExists(file)) {
          cmdSocket.respond("550", "File already exists");
        } else {
          fileRename(
            username,
            [basefolder, folderPath],
            renameFile.substring(basefolder.length),
            file.substring(basefolder.length)
          )
            .then(
              () => {
                cmdSocket.respond("250", "File renamed successfully");
              },
              () => {
                cmdSocket.respond("550", "File rename failed");
              }
            )
            .finally(() => {
              renameFile = "";
            });
        }
      }

      /*
       *  MFMT
       */
      function MFMT(cmd, arg) {
        let [time, file] = arg.split(" ");
        file = resolvePath(file);
        if (!fileExists(file)) {
          cmdSocket.respond("550", "File does not exist");
        } else {
          fileSetTimes(file, time);
          cmdSocket.respond("253", "Date/time changed okay");
        }
      }
    }

    function setUserRights(user) {
      if (
        Object.prototype.hasOwnProperty.call(user, "basefolder") &&
        folderExists(user.basefolder)
      ) {
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

    function openPassiveChannel() {
      if (pasvChannel) {
        pasvChannel.close();
        pasvSocket = new Promise<Socket>((resolve, reject) => {
          setPasvSocket = { resolve, reject };
        });
      }
      return new Promise<number>((resolve) => {
        if (isEncrypted === true && shouldProtect === true) {
          pasvChannel = new tls.Server(config.tls);
          pasvChannel.on("secureConnection", (socket) => {
            DebugHandler(`${remoteInfo} secure data connection established`);
            setPasvSocket.resolve(socket);
          });
        } else {
          pasvChannel = new net.Server();
          pasvChannel.on("connection", (socket) => {
            if (isEncrypted === true && shouldProtect === true) {
              socket = new tls.TLSSocket(socket, {
                isServer: true,
                secureContext: tls.createSecureContext(config.tls),
              });
              socket.on("secure", () => {
                DebugHandler(`${remoteInfo} data connection is secure`);
                setPasvSocket.resolve(socket);
              });
            } else {
              setPasvSocket.resolve(socket);
            }
            DebugHandler(`${remoteInfo} data connection established`);
          });
        }
        pasvChannel.on("error", ErrorHandler);
        pasvChannel.maxConnections = 1;
        return findAvailablePort().then((port) => {
          pasvChannel.listen(port, function () {
            pasv = true;
            resolve((this.address() as AddressInfo).port);
          });
        });
      });
    }

    function findAvailablePort() {
      const { minDataPort, maxConnections } = config;
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
            DebugHandler(
              `${remoteInfo} openDataChannel isSecure[${isEncrypted}] protection[${shouldProtect}] addr[${addr}] port[${port}]`
            );
            let socket = net.connect(port, addr, () => {
              if (isEncrypted === true && shouldProtect === true) {
                socket = new tls.TLSSocket(socket, {
                  isServer: true,
                  secureContext: tls.createSecureContext(config.tls),
                });
                socket.on("secure", () => {
                  DebugHandler(`${remoteInfo} data connection is secure`);
                  resolve(socket); // data connection resolved
                });
              } else {
                resolve(socket); // data connection resolved
              }
            });
            socket.on("error", ErrorHandler);
          } else {
            resolve(pasvSocket);
          }
        } else {
          reject();
        }
      }).then((socket) => {
        asciiOn && socket.setEncoding("ascii");
        return socket;
      });
    }
  }

  function ErrorHandler(err) {
    if (err.code !== "ECONNRESET") {
      console.error( "error", `${getDateForLogs()} ${util.inspect(err, {
        showHidden: false,
        depth: null,
        breakLength: Infinity,
      })}` );
    }
  }

  const emitter = new EventEmitter();

  function LogHandler(msg) {
    emitter.emit("log", `${getDateForLogs()} ${msg}`);
  }

  function DebugHandler(msg) {
    emitter.emit("debug", `${getDateForLogs()} ${msg}`);
  }

  function emitListen(protocol, address) {
    DebugHandler(
      `FTP server listening on ${util.inspect(address, {
        showHidden: false,
        depth: null,
        breakLength: Infinity,
      })}`
    );
    emitter.emit("listen", {
      protocol,
      address: address.address.replace(/::ffff:/g, ""),
      port: address.port,
    });
  }

  function emitLogin(username, remoteAddr) {
    emitter.emit("login", {
      user: username,
      address: remoteAddr,
      total: Object.keys(openSessions).length,
    });
  }

  function emitLogoff(username, remoteAddr) {
    emitter.emit("logoff", {
      user: username,
      address: remoteAddr,
      total: Object.keys(openSessions).length,
    });
  }

  return Object.assign(emitter, {
    start() {
      tcpServer.listen(config.port);
      usingTLS && tlsServer.listen(config.securePort);
    },

    stop() {
      Object.keys(openSessions).forEach((key) => openSessions[key].destroy());
      tcpServer.close();
      usingTLS && tlsServer.close();
    },

    cleanup() {
      if (folderExists(defaultBaseFolder)) {
        fs.rmSync(defaultBaseFolder, { force: true, recursive: true });
      }
    },
  });

  // the following methods should be defined by dependency injection (externalize user authentication scheme)
  function validateLoginType(username): [LoginType, UserOptions?] {
    if (username === "anonymous" && config.allowAnonymousLogin) {
      return [LoginType.Anonymous];
    } else if (config.user.length > 0) {
      for (let i = 0; i < config.user.length; i++) {
        const u = Object.assign({}, UserDefaults, config.user[i]);
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
    } else if (username === config.username) {
      if (config.allowLoginWithoutPassword === true) {
        return [LoginType.NoPassword, config];
      } else {
        return [LoginType.Password];
      }
    }
    return [LoginType.None];
  }

  function authenticateUser(username, password) {
    if (username === "anonymous" && config.allowAnonymousLogin) {
      return {
        username: password,
        allowFileCreate: config.allowAnonymousFileCreate,
        allowFileRetrieve: config.allowAnonymousFileRetrieve,
        allowFileOverwrite: config.allowAnonymousFileOverwrite,
        allowFileDelete: config.allowAnonymousFileDelete,
        allowFileRename: config.allowAnonymousFileRename,
        allowFolderDelete: config.allowAnonymousFolderDelete,
        allowFolderCreate: config.allowAnonymousFolderCreate,
      };
    }
    if (config.user.length > 0) {
      for (let i = 0; i < config.user.length; i++) {
        const u = Object.assign({}, UserDefaults, config.user[i]);
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
      username === config.username &&
      (config.allowLoginWithoutPassword === true || // this case was handled by validateLoginType
        password === config.password)
    ) {
      return config;
    }
  }

  // the following methods should be defined by dependency injection (externalize backend, replacing the handler options)
  function folderExists(folder) {
    return fs.existsSync(folder) && fs.statSync(folder).isDirectory();
  }

  function folderDelete(folder) {
    return fs.rmSync(folder, { force: true, recursive: true });
  }

  function folderCreate(folder) {
    return fs.mkdirSync(folder, { recursive: true });
  }

  function folderList(
    username,
    [basefolder, folderPath]: [string, string],
    format
  ) {
    if (usingHandlers) {
      return config.handler.list(username, folderPath, format);
    } else {
      const read = fs.readdirSync(path.join(basefolder, folderPath));
      const listData = Array(read.length);
      const isMLSD = format === "MLSD";
      for (let i = 0; i < read.length; i++) {
        const file = read[i].trim();
        const stat = fs.statSync(path.join(basefolder, folderPath, file));
        if (isMLSD === true) {
          listData.push(
            util.format(
              "type=%s;modify=%s;%s %s",
              stat.isDirectory() ? "dir" : "file",
              getDateForMLSD(stat.mtime),
              stat.isDirectory() ? "" : "size=" + stat.size.toString() + ";",
              file
            )
          );
        } else {
          listData.push(
            util.format(
              "%s 1 %s %s %s %s %s",
              stat.isDirectory() ? "dr--r--r--" : "-r--r--r--", // ignoring other node types: sym-links, pipes, etc.
              // skipping n-links
              username, // uid
              username, // gid
              String(stat.isDirectory() ? "0" : stat.size).padStart(14, " "),
              getDateForLIST(stat.mtime),
              file
            )
          );
        }
      }
      return listData;
    }
  }

  function fileExists(file) {
    return fs.existsSync(file) && fs.statSync(file).isFile();
  }

  function fileStat(file) {
    return fs.statSync(file);
  }

  function fileDelete(file) {
    return fs.unlinkSync(file);
  }

  function fileRetrieve(
    username: string,
    [basefolder, folderPath]: [string, string],
    relativeFile: string,
    restOffset: number,
    encoding?: BufferEncoding
  ): Promise<Buffer | fs.ReadStream> {
    if (usingHandlers) {
      return config.handler.download(username, folderPath, relativeFile, restOffset);
    } else {
      return Promise.resolve(
        fs.createReadStream(path.join(basefolder, folderPath, relativeFile), {
          flags: "r",
          start: restOffset,
          encoding,
          autoClose: true,
          emitClose: true,
        })
      );
    }
  }

  function fileStore(
    socket: Socket,
    username: string,
    [basefolder, folderPath]: [string, string],
    relativeFile: string,
    restOffset: number,
    encoding?: BufferEncoding
  ) {
    return new Promise<void>((resolve, reject) => {
      if (usingHandlers) {
        // hey, what about giving handler a ReadableStream?
        const data = [];
        socket.on("data", (d) => data.push(d));
        socket.on("close", () => {
          config.handler
            .upload(
              username,
              folderPath,
              relativeFile,
              Buffer.concat(data),
              restOffset
            )
            .then(resolve, reject);
        });
      } else {
        const writeStream = fs.createWriteStream(
          path.join(basefolder, folderPath, relativeFile),
          {
            flags: restOffset > 0 ? "a+" : "w",
            start: restOffset,
            encoding,
            autoClose: true,
            emitClose: true,
          }
        );
        writeStream.on("error", ErrorHandler);
        writeStream.on("open", () => {
          socket.on("close", () => {
            writeStream.destroy();
            resolve();
          });
          socket.pipe(writeStream);
        });
        writeStream.on("end", () => {
          socket.end();
          reject();
        });
      }
    });
  }

  function fileRename(
    username: string,
    [basefolder, folderPath]: [string, string],
    renameFile: string,
    file: string
  ) {
    if (usingHandlers === true) {
      return config.handler.rename(
        username,
        folderPath,
        renameFile.substring(basefolder.length),
        file.substring(basefolder.length)
      );
    } else {
      return Promise.resolve(fs.renameSync(renameFile, file));
    }
  }

  function fileSetTimes(file: string, time: string) {
    const mtime = getDateForMFMT(time);
    return fs.utimesSync(file, mtime, mtime);
  }
}

function getDateForLIST(mtime: Date): string {
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

function getDateForMLSD(mtime: Date): string {
  const now = new Date(mtime);
  const MM = (now.getMonth() + 1).toString().padStart(2, "0");
  const DD = now.getDate().toString().padStart(2, "0");
  const H = now.getHours().toString().padStart(2, "0");
  const M = now.getMinutes().toString().padStart(2, "0");
  const S = now.getSeconds().toString().padStart(2, "0");
  return `${now.getFullYear()}${MM}${DD}${H}${M}${S}`;
}

function getDateForMFMT(time: string): number {
  // expect format YYYYMMDDhhmmss
  const Y = time.substr(0, 4);
  const M = time.substr(4, 2);
  const D = time.substr(6, 2);
  const Hrs = time.substr(8, 2);
  const Min = time.substr(10, 2);
  const Sec = time.substr(12, 2);
  return Date.parse(`${Y}-${M}-${D}T${Hrs}:${Min}:${Sec}+00:00`) / 1000;
}

function getDateForLogs(date?: Date): string {
  const now = date || new Date();
  const MM = (now.getMonth() + 1).toString().padStart(2, "0");
  const DD = now.getDate().toString().padStart(2, "0");
  const H = now.getHours().toString().padStart(2, "0");
  const M = now.getMinutes().toString().padStart(2, "0");
  const S = now.getSeconds().toString().padStart(2, "0");
  return `${DD}.${MM}.${now.getFullYear()} - ${H}:${M}:${S}`;
}
