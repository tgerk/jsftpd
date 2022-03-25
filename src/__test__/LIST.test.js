/* eslint-disable @typescript-eslint/no-var-requires */
const { createFtpServer: createServer } = require("../jsftpd.ts")
const tls = require("tls")
const {
  getCmdPortTCP,
  getDataPort,
  formatPort,
  ExpectSocket,
  addFactoryExtensions,
} = require("./utils")

jest.setTimeout(5000)
let server = null
const cmdPortTCP = getCmdPortTCP()
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

test("test LIST message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = createServer({
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

  expect(await cmdSocket.command("MKD john").response()).toBe(
    "250 Folder created successfully"
  )

  const passiveModeData = formatPort("127.0.0.1", dataPort)
  expect(await cmdSocket.command("PASV").response()).toBe(
    `227 Entering passive mode (${passiveModeData})`
  )

  await cmdSocket.command("LIST")

  let dataSocket = new ExpectSocket()
  const data = await dataSocket.connect(dataPort, localhost).receive()
  expect(data).toMatch("dr--r--r-- 1 ? ?")

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test MLSD message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = createServer({
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

  expect(await cmdSocket.command("MKD john").response()).toBe(
    "250 Folder created successfully"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  await cmdSocket.command("MLSD")

  let dataSocket = new ExpectSocket()
  const data = await dataSocket.connect(dataPort, localhost).receive()
  expect(data).toMatch("type=dir")
  expect(data).toMatch("john")

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test MLSD message over secure connection", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
    },
  ]
  server = createServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
  })
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

  cmdSocket = new ExpectSocket(
    new tls.connect({ socket: cmdSocket.stream, rejectUnauthorized: false })
  )
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  cmdSocket.stream.once("secureConnect", function () {})

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("PBSZ 0").response()).toBe("200 PBSZ=0")

  expect(await cmdSocket.command("PROT P").response()).toBe(
    "200 Protection level is P"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let dataSocket = new ExpectSocket(
    new tls.connect(dataPort, localhost, { rejectUnauthorized: false })
  )
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  await dataSocket.stream.once("secureConnect", function () {})

  expect(await cmdSocket.command("STOR mytestfile").response()).toMatch(
    "150 Awaiting passive connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toMatch(
    '226 Successfully transferred "mytestfile"'
  )

  await cmdSocket.end()
})

test("test MLSD message with handler", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  const folderList = jest.fn().mockImplementationOnce(() => Promise.resolve([]))
  server = createServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
    store: addFactoryExtensions({ folderList }),
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

  await cmdSocket.write("MLSD")

  let dataSocket = new ExpectSocket()
  expect(await dataSocket.connect(dataPort, localhost).receive()).toBe("")

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})
