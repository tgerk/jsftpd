/* eslint-disable @typescript-eslint/no-var-requires */
const { createFtpServer } = require("../jsftpd.ts")
const {
  sleep,
  getDataPort,
  ExpectSocket,
  addFactoryExtensions,
} = require("./utils")

jest.setTimeout(5000)
let server
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

test("test RNFR message file does not exist", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
    },
  ]
  server = await createFtpServer({
    port: 50021,
    user: users,
    minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(50021, localhost).response()).toBe(
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

  expect(await cmdSocket.command("RNFR myothertestfile").response()).toBe(
    "550 File does not exist"
  )

  await cmdSocket.end()
})

test("test RNFR/RNTO message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileRename: true,
    },
  ]
  server = await createFtpServer({
    port: 50021,
    user: users,
    minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(50021, localhost).response()).toBe(
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

  expect(await cmdSocket.command("RNFR /mytestfile").response()).toBe(
    "350 File exists"
  )

  expect(await cmdSocket.command("RNTO /someotherfile").response()).toBe(
    "250 File renamed successfully"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  expect(await cmdSocket.command("MLSD").response()).toMatch(
    "150 Awaiting passive connection"
  )

  dataSocket = new ExpectSocket()
  const data = await dataSocket.connect(dataPort, localhost).receive()
  expect(data).toMatch("type=file")
  expect(data).toMatch("size=15")
  expect(data).toMatch("someotherfile")

  await sleep(100)

  expect(await cmdSocket.response()).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test RNFR/RNTO message using handlers", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileRename: true,
    },
  ]
  const fileRename = jest
    .fn()
    .mockImplementationOnce(() => Promise.resolve(true))
  server = await createFtpServer({
    port: 50021,
    user: users,
    store: addFactoryExtensions({
      fileExists(file) {
        return Promise.resolve(file === "mytestfile")
      },
      fileRename,
    }),
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(50021, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("RNFR mytestfile").response()).toBe(
    "350 File exists"
  )

  expect(await cmdSocket.command("RNTO someotherfile").response()).toBe(
    "250 File renamed successfully"
  )

  expect(fileRename).toBeCalledTimes(1)
  expect(fileRename).toHaveBeenCalledWith("mytestfile", "someotherfile")

  await cmdSocket.end()
})

test("test RNFR/RNTO message using handlers failing", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileRename: true,
    },
  ]
  const fileRename = jest
    .fn()
    .mockImplementationOnce(() => Promise.reject(Error("mock")))
  server = await createFtpServer({
    port: 50021,
    user: users,
    store: addFactoryExtensions({
      fileExists(file) {
        return Promise.resolve(file === "mytestfile")
      },
      fileRename,
    }),
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(50021, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("RNFR mytestfile").response()).toBe(
    "350 File exists"
  )

  expect(await cmdSocket.command("RNTO someotherfile").response()).toBe(
    "550 File rename failed"
  )

  expect(fileRename).toBeCalledTimes(1)
  expect(fileRename).toHaveBeenCalledWith("mytestfile", "someotherfile")

  await cmdSocket.end()
})

test("test RNFR/RNTO message file already exists", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileRename: true,
    },
  ]
  server = await createFtpServer({
    port: 50021,
    user: users,
    minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(50021, localhost).response()).toBe(
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

  expect(await cmdSocket.command("STOR mytestfile2").response()).toBe(
    "150 Awaiting passive connection"
  )

  dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost).send("OTHERTESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile2"'
  )

  expect(await cmdSocket.command("RNFR /mytestfile").response()).toBe(
    "350 File exists"
  )

  expect(await cmdSocket.command("RNTO mytestfile2").response()).toBe(
    "550 File already exists"
  )

  await cmdSocket.end()
})
