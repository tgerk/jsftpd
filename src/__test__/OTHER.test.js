/* eslint-disable @typescript-eslint/no-var-requires */
const { createFtpServer } = require("../jsftpd.ts")
const tls = require("tls")
const {
  getCmdPortTCP,
  getCmdPortTLS,
  getDataPort,
  formatPort,
  ExpectServer,
  ExpectSocket,
  addFactoryExtensions,
} = require("./utils")

jest.setTimeout(5000)
let server
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
}
beforeEach(() => cleanup())
afterEach(() => cleanup())

test("create ftpd instance without options created with default values", async () => {
  server = await createFtpServer()
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
    const cmdSocket = new ExpectSocket()
    expect(await cmdSocket.connect(21, localhost).response()).toBe(
      "220 Welcome"
    )

    expect(handler).toBeCalledTimes(1)

    await cmdSocket.end()
  }

  // expect(server._opt.cnf.securePort).toBe(990)
  expect(async () => {
    const cmdSocket = new ExpectSocket(new tls.TLSSocket())
    await cmdSocket.connect(990, localhost).response()
  }).rejects.toThrow("ECONNREFUSED")
})

test("connect to secure ftp server", async () => {
  server = await createFtpServer({
    securePort: cmdPortTLS,
  })
  server.start()

  const cmdSocket = new ExpectSocket()
  expect(
    await cmdSocket
      .connect(cmdPortTLS, localhost)
      .startTLS({ rejectUnauthorized: false })
      .response()
  ).toBe("220 Welcome")

  await cmdSocket.end()
})

test("ftp server can be started on non default ports", async () => {
  server = await createFtpServer({
    port: cmdPortTCP + 2,
    securePort: cmdPortTLS + 2,
  })
  // expect(server._opt.cnf.port).toBe(cmdPortTCP)
  // expect(server._opt.cnf.securePort).toBe(cmdPortTLS)
  server.start()
  // expect(server._tcp.address().port).toBe(cmdPortTCP)
  // expect(server._tls.address().port).toBe(cmdPortTLS)
  const handler = jest.fn()
  server.on("listen", handler)

  const cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP + 2, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(handler).toBeCalledTimes(2)

  await cmdSocket.end()
})

test("ftp server fails when basefolder does not exist", async () => {
  try {
    server = await createFtpServer({ basefolder: "/NOTEXISTING" })
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
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("SOMETHING").response()).toBe(
    "500 Command not implemented"
  )

  await cmdSocket.end()
})

test("test CLNT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("CLNT tests").response()).toBe(
    "200 Don't care"
  )

  await cmdSocket.end()
})

test("test SYST message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("SYST").response()).toBe("215 UNIX")

  await cmdSocket.end()
})

test("test FEAT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("FEAT").response()).toMatch("211-Features")

  await cmdSocket.end()
})

test("test PWD message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("PWD").response()).toBe(
    '257 "/" is current directory'
  )

  await cmdSocket.end()
})

test("test QUIT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("QUIT").response()).toBe("221 Goodbye")

  await cmdSocket.end()
})

test("test PBSZ message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("PBSZ 0").response()).toBe("200 PBSZ=0")

  await cmdSocket.end()
})

test("test TYPE message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("TYPE A").response()).toBe(
    "200 Type set to ASCII"
  )

  expect(await cmdSocket.command("TYPE").response()).toBe(
    "200 Type set to BINARY"
  )

  await cmdSocket.end()
})

test("test OPTS message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("OPTS UTF8 ON").response()).toBe("200 UTF8 ON")

  expect(await cmdSocket.command("OPTS UTF8 OFF").response()).toBe(
    "200 UTF8 OFF"
  )

  expect(await cmdSocket.command("OPTS SOMETHING").response()).toBe(
    "451 Not supported"
  )

  await cmdSocket.end()
})

test("test PROT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("PROT C").response()).toBe("503 PBSZ missing")

  expect(await cmdSocket.command("PBSZ 0").response()).toBe("200 PBSZ=0")

  expect(await cmdSocket.command("PROT C").response()).toBe(
    "200 Protection level is C"
  )

  expect(await cmdSocket.command("PROT P").response()).toBe(
    "200 Protection level is P"
  )

  expect(await cmdSocket.command("PROT Z").response()).toBe(
    "534 Protection level must be C or P"
  )

  await cmdSocket.end()
})

test("test REST message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("REST 0").response()).toBe(
    "350 Restarting at 0"
  )

  expect(await cmdSocket.command("REST -1").response()).toBe(
    "550 Wrong restart offset"
  )

  await cmdSocket.end()
})

test("test MKD message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("MKD john/paul/ringo/george").response()).toBe(
    "250 Folder created successfully"
  )

  expect(await cmdSocket.command("MKD /john").response()).toBe(
    "550 Folder exists"
  )

  await cmdSocket.end()
})

test("test MKD message cannot create folder without permission", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: false,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("MKD john").response()).toBe(
    "550 Permission denied"
  )

  await cmdSocket.end()
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
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("MKD john").response()).toBe(
    "250 Folder created successfully"
  )

  expect(await cmdSocket.command("RMD /pete").response()).toBe(
    "550 Folder not found"
  )

  expect(await cmdSocket.command("RMD john").response()).toBe(
    "250 Folder deleted successfully"
  )

  await cmdSocket.end()
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
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("MKD john").response()).toBe(
    "250 Folder created successfully"
  )

  expect(await cmdSocket.command("RMD john").response()).toBe(
    "550 Permission denied"
  )

  await cmdSocket.end()
})

test("test CWD message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("MKD john").response()).toBe(
    "250 Folder created successfully"
  )

  expect(await cmdSocket.command("CWD john").response()).toBe(
    '250 CWD successful. "/john" is current directory'
  )

  expect(await cmdSocket.command("CWD /john").response()).toBe(
    '250 CWD successful. "/john" is current directory'
  )

  expect(await cmdSocket.command("CWD ..").response()).toBe(
    '250 CWD successful. "/" is current directory'
  )

  expect(await cmdSocket.command("CWD ..").response()).toBe(
    '250 CWD successful. "/" is current directory'
  )

  expect(await cmdSocket.command("CWD false").response()).toBe(
    "550 Folder not found"
  )

  await cmdSocket.end()
})

test("test MFMT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost).send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(
    await cmdSocket.command("MFMT 20150215120000 mytestfile").response()
  ).toBe("253 Date/time changed okay")

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  expect(await cmdSocket.command("MLSD").response()).toMatch(
    "150 Awaiting passive connection"
  )

  dataSocket = new ExpectSocket()
  const data = await dataSocket.connect(dataPort, localhost).receive()
  expect(data.toString().trim()).toMatch("type=file")
  expect(data.toString().trim()).toMatch("modify=20150215")
  expect(data.toString().trim()).toMatch("size=15")
  expect(data.toString().trim()).toMatch("mytestfile")

  expect(await cmdSocket.response()).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test MFMT message with handler", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    store: addFactoryExtensions({
      fileExists() {
        return Promise.resolve(true)
      },
      fileSetTimes() {
        return Promise.resolve()
      },
    }),
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(
    await cmdSocket.command("MFMT 2022020220202202 mytestfile").response()
  ).toBe("253 Date/time changed okay")

  await cmdSocket.end()
})

test("test MFMT message file does not exist", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileOverwrite: true,
      allowUserFileRename: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost).send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(
    await cmdSocket.command("MFMT 20150215120000 /someotherfile").response()
  ).toBe("550 File does not exist")

  await cmdSocket.end()
})

test("test DELE message without permission", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileDelete: false,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost).send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("DELE mytestfile").response()).toBe(
    "550 Permission denied"
  )

  await cmdSocket.end()
})

test("test DELE message relative path", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileDelete: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )
  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost).send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("DELE someotherfile").response()).toBe(
    "550 File not found"
  )

  expect(await cmdSocket.command("DELE mytestfile").response()).toBe(
    "250 File deleted successfully"
  )

  await cmdSocket.end()
})

test("test DELE message absolute path", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileDelete: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost).send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("DELE /mytestfile").response()).toBe(
    "250 File deleted successfully"
  )

  await cmdSocket.end()
})

test("test SIZE message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost).send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("SIZE /myfile").response()).toBe(
    "550 File not found"
  )

  expect(await cmdSocket.command("SIZE /mytestfile").response()).toBe("213 15")

  expect(await cmdSocket.command("SIZE mytestfile").response()).toBe("213 15")

  await cmdSocket.end()
})

test("test AUTH message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("AUTH NONE").response()).toBe(
    "504 Unsupported auth type NONE"
  )

  expect(await cmdSocket.command("AUTH TLS").response()).toBe(
    "234 Using authentication type TLS"
  )

  cmdSocket = cmdSocket.startTLS({ rejectUnauthorized: false })

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  await cmdSocket.end()
})

// TODO: test AUTH TLS _after_ login (should reset session)

test("test PORT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("MKD john").response()).toBe(
    "250 Folder created successfully"
  )

  const dataServer = new ExpectServer().listen(dataPort, "127.0.0.1")

  expect(await cmdSocket.command("PORT something").response()).toBe(
    "501 Port command failed"
  )

  const portData = formatPort("127.0.0.1", dataPort)
  expect(await cmdSocket.command(`PORT ${portData}`).response()).toBe(
    "200 Port command successful"
  )

  expect(await cmdSocket.command("MLSD").response()).toMatch(
    "150 Opening data connection"
  )

  const data = await (await dataServer.getConnection()).receive()

  expect(await cmdSocket.response()).toMatch('226 Successfully transferred "/"')

  expect(data).toMatch("type=dir;")
  expect(data).toMatch("modify=")
  expect(data).not.toMatch("size=")
  expect(data).toMatch("john")

  await dataServer.close()
  await cmdSocket.end()
})

test("test EPRT message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = await createFtpServer({ port: cmdPortTCP, user: users })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("MKD john").response()).toBe(
    "250 Folder created successfully"
  )

  const dataServer = new ExpectServer().listen(dataPort, "127.0.0.1")

  expect(await cmdSocket.command("EPRT something").response()).toBe(
    "501 Extended port command failed"
  )

  expect(
    await cmdSocket.command(`EPRT ||127.0.0.1|${dataPort}|`).response()
  ).toBe("200 Extended Port command successful")

  expect(await cmdSocket.command("MLSD").response()).toMatch(
    "150 Opening data connection"
  )

  const data = await (await dataServer.getConnection()).receive()

  expect(await cmdSocket.response()).toMatch('226 Successfully transferred "/"')

  expect(data).toMatch("type=dir;")
  expect(data).toMatch("modify=")
  expect(data).not.toMatch("size=")
  expect(data).toMatch("john")

  await dataServer.close()
  await cmdSocket.end()
})