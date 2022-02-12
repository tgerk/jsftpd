const { createFtpServer: createServer } = require("../jsftpd.ts")
const net = require("net")
const tls = require("tls")
const { PromiseSocket, TimeoutError } = require("promise-socket")
const {
  sleep,
  getCmdPortTCP,
  getCmdPortTLS,
  getDataPort,
  formatPort,
} = require("./utils")
const { fstat } = require("fs")

jest.setTimeout(5000)
let server,
  content,
  dataContent = null
const cmdPortTCP = getCmdPortTCP()
const cmdPortTLS = getCmdPortTLS()
const dataPort = getDataPort()
const localhost = "127.0.0.1"

const cleanup = function () {
  if (server) {
    server.stop()
    server.cleanup()
    server = null
  }
  content = ""
  dataContent = ""
}
beforeEach(() => cleanup())
afterEach(() => cleanup())

test("create ftpd instance without options created with default values", async () => {
  server = createServer()
  /* Bad checks:  "show, don't tell" principle means to test the effects & behavior of a server created with all defaults
      an adequate implementation can behave identically, regardless of inspection of internal data structures
    expect(server._opt.cnf.allowAnonymousFileDelete).toBeFalsy()
    expect(server._opt.cnf.allowAnonymousFolderCreate).toBeFalsy()
    expect(server._opt.cnf.allowAnonymousFolderDelete).toBeFalsy()
    expect(server._opt.cnf.allowAnonymousLogin).toBeFalsy()
    expect(server._opt.cnf.allowLoginWithoutPassword).toBeFalsy()
    expect(server._opt.cnf.allowUserFileDelete).toBeTruthy()
    expect(server._opt.cnf.allowUserFileOverwrite).toBeTruthy()
    expect(server._opt.cnf.allowUserFolderCreate).toBeTruthy()
    expect(server._opt.cnf.allowUserFolderDelete).toBeTruthy()
    expect(server._opt.cnf.allowUserFolderDelete).toBeTruthy()
    expect(server._opt.cnf.allowUserFolderDelete).toBeTruthy() */
  server.start()
  const handler = jest.fn()
  server.on("listen", handler)

  {
    // expect(server._opt.cnf.port).toBe(21)
    const promiseSocket = new PromiseSocket(new net.Socket())
    const socket = promiseSocket.stream

    await socket.connect(21, localhost)
    content = await promiseSocket.read()
    expect(content.toString().trim()).toBe("220 Welcome")

    expect(handler).toBeCalledTimes(1)

    await promiseSocket.end()
  }

  // expect(server._opt.cnf.securePort).toBe(990)
  expect(async () => {
    const promiseSocket = new PromiseSocket(new tls.TLSSocket())
    const socket = promiseSocket.stream

    await socket.connect(990, localhost)
    content = await promiseSocket.read()
  }).rejects.toThrow("ECONNREFUSED")
})

test("ftp server can be started on non default ports", async () => {
  server = createServer({
    tls: { rejectUnauthorized: false },
    cnf: { port: cmdPortTCP + 2, securePort: cmdPortTLS + 2 },
  })
  // expect(server._opt.cnf.port).toBe(cmdPortTCP)
  // expect(server._opt.cnf.securePort).toBe(cmdPortTLS)
  server.start()
  // expect(server._tcp.address().port).toBe(cmdPortTCP)
  // expect(server._tls.address().port).toBe(cmdPortTLS)
  const handler = jest.fn()
  server.on("listen", handler)

  const promiseSocket = new PromiseSocket(new net.Socket())
  const socket = promiseSocket.stream

  await socket.connect(cmdPortTCP + 2, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  expect(handler).toBeCalledTimes(2)

  await promiseSocket.end()
})

test("ftp server fails when basefolder does not exist", () => {
  try {
    server = createServer({ cnf: { basefolder: "/NOTEXISTING" } })
  } catch (err) {
    expect(err.message).toMatch("Basefolder must exist")
  }
})

test("test unknown message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("SOMETHING")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("500 Command not implemented")

  await promiseSocket.end()
})

test("test CLNT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("CLNT tests")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 Don't care")

  await promiseSocket.end()
})

test("test SYST message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("SYST")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("215 UNIX")

  await promiseSocket.end()
})

test("test FEAT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("FEAT")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toMatch("211-Features")

  await promiseSocket.end()
})

test("test PWD message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("PWD")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe('257 "/" is current directory')

  await promiseSocket.end()
})

test("test QUIT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("QUIT")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("221 Goodbye")

  await promiseSocket.end()
})

test("test PBSZ message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("PBSZ 0")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 PBSZ=0")

  await promiseSocket.end()
})

test("test TYPE message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("TYPE A")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 Type set to ASCII")

  await promiseSocket.write("TYPE")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 Type set to BINARY")

  await promiseSocket.end()
})

test("test OPTS message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("OPTS UTF8 ON")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 UTF8 ON")

  await promiseSocket.write("OPTS UTF8 OFF")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 UTF8 OFF")

  await promiseSocket.write("OPTS SOMETHING")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("451 Not supported")

  await promiseSocket.end()
})

test("test PROT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("PROT C")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("503 PBSZ missing")

  await promiseSocket.write("PBSZ 0")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 PBSZ=0")

  await promiseSocket.write("PROT C")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 Protection level is C")

  await promiseSocket.write("PROT P")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 Protection level is P")

  await promiseSocket.write("PROT Z")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("534 Protection level must be C or P")

  await promiseSocket.end()
})

test("test REST message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("REST 0")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("350 Restarting at 0")

  await promiseSocket.write("REST -1")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 Wrong restart offset")

  await promiseSocket.end()
})

test("test MKD message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("MKD john/paul/ringo/george")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("250 Folder created successfully")

  await promiseSocket.write("MKD /john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 Folder exists")

  await promiseSocket.end()
})

test("test MKD message cannot create folder without permission", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: false,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("MKD john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 Permission denied")

  await promiseSocket.end()
})

test("test RMD message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
      allowUserFolderDelete: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("MKD john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("250 Folder created successfully")

  await promiseSocket.write("RMD /pete")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 Folder not found")

  await promiseSocket.write("RMD john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("250 Folder deleted successfully")

  await promiseSocket.end()
})

test("test RMD message cannot delete folder without permission", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
      allowUserFolderDelete: false,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("MKD john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("250 Folder created successfully")

  await promiseSocket.write("RMD john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 Permission denied")

  await promiseSocket.end()
})

test("test CWD message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("MKD john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("250 Folder created successfully")

  await promiseSocket.write("CWD john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '250 CWD successful. "/john" is current directory'
  )

  await promiseSocket.write("CWD /john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '250 CWD successful. "/john" is current directory'
  )

  await promiseSocket.write("CWD ..")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '250 CWD successful. "/" is current directory'
  )

  await promiseSocket.write("CWD ..")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '250 CWD successful. "/" is current directory'
  )

  await promiseSocket.write("CWD false")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 Folder not found")

  await promiseSocket.end()
})

test("test MFMT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({
    cnf: { port: cmdPortTCP, user: users, minDataPort: dataPort },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  await promiseSocket.write("MFMT 20150215120000 mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("253 Date/time changed okay")

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  promiseDataSocket = new PromiseSocket(new net.Socket())
  dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("MLSD")
  content = await promiseSocket.read()

  dataContent = await promiseDataSocket.read()
  expect(dataContent.toString().trim()).toMatch("type=file")
  expect(dataContent.toString().trim()).toMatch("modify=20150215")
  expect(dataContent.toString().trim()).toMatch("size=15")
  expect(dataContent.toString().trim()).toMatch("mytestfile")
  await promiseDataSocket.end()

  await sleep(100)

  content += await promiseSocket.read()
  expect(content.toString().trim()).toMatch("150 Opening data channel")
  expect(content.toString().trim()).toMatch('226 Successfully transferred "/"')

  await promiseSocket.end()
})

test("test MFMT message with handler", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({
    cnf: { port: cmdPortTCP, user: users },
    hdl: {
      fileExists() {
        return Promise.resolve(true)
      },
      fileSetTimes() {
        return Promise.resolve()
      },
    },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("MFMT 2022020220202202 mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("253 Date/time changed okay")

  await promiseSocket.end()
})

test("test MFMT message file does not exist", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({
    cnf: { port: cmdPortTCP, user: users, minDataPort: dataPort },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  await promiseSocket.write("MFMT 20150215120000 /someotherfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 File does not exist")

  await promiseSocket.end()
})

test("test DELE message without permission", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileDelete: false,
    },
  ]
  server = createServer({
    cnf: { port: cmdPortTCP, user: users, minDataPort: dataPort },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  await promiseSocket.write("DELE mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 Permission denied")

  await promiseSocket.end()
})

test("test DELE message relative path", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileDelete: true,
    },
  ]
  server = createServer({
    cnf: { port: cmdPortTCP, user: users, minDataPort: dataPort },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  await promiseSocket.write("DELE someotherfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 File not found")

  await promiseSocket.write("DELE mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("250 File deleted successfully")

  await promiseSocket.end()
})

test("test DELE message absolute path", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileDelete: true,
    },
  ]
  server = createServer({
    cnf: { port: cmdPortTCP, user: users, minDataPort: dataPort },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  await promiseSocket.write("DELE /mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("250 File deleted successfully")

  await promiseSocket.end()
})

test("test SIZE message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({
    cnf: { port: cmdPortTCP, user: users, minDataPort: dataPort },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  await promiseSocket.write("SIZE /myfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 File not found")

  await promiseSocket.write("SIZE /mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("213 15")

  await promiseSocket.write("SIZE mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("213 15")

  await promiseSocket.end()
})

test("test AUTH message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("AUTH NONE")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("504 Unsupported auth type NONE")

  await promiseSocket.write("AUTH TLS")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("234 Using authentication type TLS")

  promiseSocket = new PromiseSocket(
    new tls.connect({ socket: socket, rejectUnauthorized: false })
  )
  await promiseSocket.stream.once("secureConnect", function () {})

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.end()
})

test("test PORT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("MKD john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("250 Folder created successfully")

  const dataServer = net.createServer()
  let promiseDataSocket = new PromiseSocket(dataServer)
  await promiseDataSocket.stream.listen(dataPort, "127.0.0.1")

  await promiseSocket.write("PORT something")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("501 Port command failed")

  const portData = formatPort("127.0.0.1", dataPort)
  await promiseSocket.write(`PORT ${portData}`)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 Port command successful")

  await promiseSocket.write("MLSD")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toMatch("150 Opening data channel")

  await promiseDataSocket.stream.close()
  await promiseSocket.end()
})

test("test EPRT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("MKD john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("250 Folder created successfully")

  const dataServer = net.createServer()
  let promiseDataSocket = new PromiseSocket(dataServer)
  await promiseDataSocket.stream.listen(dataPort, "127.0.0.1")

  await promiseSocket.write("EPRT something")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("501 Extended port command failed")

  await promiseSocket.write(`EPRT ||127.0.0.1|${dataPort}|`)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 Extended Port command successful")

  await promiseSocket.write("MLSD")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toMatch("150 Opening data channel")

  await promiseDataSocket.stream.close()
  await promiseSocket.end()
})
