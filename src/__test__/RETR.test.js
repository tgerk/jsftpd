/* eslint-disable @typescript-eslint/no-var-requires */
const { createFtpServer: createServer } = require("../jsftpd.ts")
const {
  getCmdPortTCP,
  getDataPort,
  ExpectSocket,
  addFactoryExtensions,
} = require("./utils")
const { Readable, Writable } = require("stream")

jest.setTimeout(5000)
let server
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

test("test RETR message not allowed", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileRetrieve: false,
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

  expect(await cmdSocket.command("RETR mytestfile").response()).toBe(
    '550 Transfer failed "mytestfile"'
  )

  await cmdSocket.end()
})

test("test RETR message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileRetrieve: true,
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

  expect(await cmdSocket.command("RETR /someotherfile").response()).toBe(
    "550 File not found"
  )

  expect(await cmdSocket.command("RETR mytestfile").response()).toMatch(
    "150 Awaiting passive connection"
  )

  dataSocket = new ExpectSocket()
  expect(await dataSocket.connect(dataPort, localhost).receive()).toMatch(
    "SOMETESTCONTENT"
  )

  expect(await cmdSocket.response()).toMatch(
    '226 Successfully transferred "mytestfile"'
  )

  await cmdSocket.end()
})

test("test RETR message with ASCII", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileRetrieve: true,
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

  expect(await cmdSocket.command("TYPE A").response()).toBe(
    "200 Type set to ASCII"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost, "ascii").send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  expect(await cmdSocket.command("RETR /someotherfile").response()).toBe(
    "550 File not found"
  )

  expect(await cmdSocket.command("RETR mytestfile").response()).toMatch(
    "150 Awaiting passive connection"
  )

  dataSocket = new ExpectSocket()
  expect(
    await dataSocket.connect(dataPort, localhost, "ascii").receive()
  ).toMatch("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toMatch(
    '226 Successfully transferred "mytestfile"'
  )

  await cmdSocket.end()
})

test("test RETR message with handler", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileRetrieve: true,
    },
  ]

  let doesFileExist = false
  const fileStore = jest.fn().mockImplementationOnce(() =>
    Promise.resolve(
      new Writable({
        write: (data, enc, cb) => {
          doesFileExist = true
          cb()
        },
      })
    )
  )
  const fileRetrieve = jest.fn().mockImplementationOnce(() =>
    Promise.resolve(
      new Readable({
        read: function () {
          this.push("SOMETESTCONTENT")
          this.destroy()
        },
      })
    )
  )

  server = createServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
    store: addFactoryExtensions({
      fileExists() {
        return Promise.resolve(doesFileExist)
      },
      fileRetrieve,
      fileStore,
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

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  await cmdSocket.command("STOR mytestfile")
  expect(await cmdSocket.response()).toBe("150 Awaiting passive connection")

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost).send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  await cmdSocket.command("RETR mytestfile")

  dataSocket = new ExpectSocket()
  expect(await dataSocket.connect(dataPort, localhost).receive()).toMatch(
    "SOMETESTCONTENT"
  )

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "mytestfile"')

  expect(fileStore).toBeCalledTimes(1)
  expect(fileRetrieve).toBeCalledTimes(1)

  await cmdSocket.end()
})

test("test RETR message with handler fails", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileRetrieve: true,
    },
  ]

  let doesFileExist = false
  const fileStore = jest.fn().mockImplementationOnce(() =>
    Promise.resolve(
      new Writable({
        write: (data, enc, cb) => {
          doesFileExist = true
          cb()
        },
      })
    )
  )
  const fileRetrieve = jest.fn().mockImplementationOnce(() =>
    Promise.resolve(
      new Readable({
        read: function () {
          this.destroy(Error("mock"))
        },
      })
    )
  )
  server = createServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
    store: addFactoryExtensions({
      fileExists() {
        return Promise.resolve(doesFileExist)
      },
      fileRetrieve,
      fileStore,
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

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  await cmdSocket.command("RETR mytestfile")

  dataSocket = new ExpectSocket()
  const data = await dataSocket.connect(dataPort, localhost).receive()
  expect(data).toBe(undefined)

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('550 Transfer failed "mytestfile"')

  expect(fileStore).toBeCalledTimes(1)
  expect(fileRetrieve).toBeCalledTimes(1)

  await cmdSocket.end()
})

test("test RETR message no active or passive mode", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileRetrieve: true,
    },
  ]
  server = createServer({
    port: cmdPortTCP,
    user: users,
    store: addFactoryExtensions({
      fileExists() {
        return Promise.resolve(true)
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

  expect(await cmdSocket.command("PORT WRONG").response()).toBe(
    "501 Port command failed"
  )

  server._useHdl = true

  expect(await cmdSocket.command("RETR mytestfile").response()).toBe(
    "501 Command failed"
  )

  await cmdSocket.end()
})
