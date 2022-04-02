/* eslint-disable @typescript-eslint/no-var-requires */
const { createFtpServer } = require("../jsftpd.ts")
const {
  getDataPort,
  formatPort,
  sleep,
  ExpectSocket,
  ExpectServer,
  addFactoryExtensions,
} = require("./utils")
const { Writable } = require("stream")

jest.setTimeout(5000)
const cmdPortTCP = 50021
const dataPort = getDataPort()
const localhost = "127.0.0.1"

let server
const cleanup = function () {
  if (server) {
    server.stop()
    server.cleanup()
    server = null
  }
}
beforeEach(() => cleanup())
afterEach(() => cleanup())

test("test STOR message without permission", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: false,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
  })
  server.start()

  const cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  const dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    '550 Transfer failed "mytestfile"'
  )

  await dataSocket.stream.end()
  await cmdSocket.end()
})

test("test STOR message", async () => {
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

  expect(await cmdSocket.command("STOR ../../mytestfile").response()).toBe(
    '550 Transfer failed "../../mytestfile"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  cmdSocket.command("MLSD")

  const data = await dataSocket.receive()
  expect(data).toMatch("type=file")
  expect(data).toMatch("size=15")
  expect(data).toMatch("mytestfile")

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test STOR message failes due to socket timeout", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
    timeout: 3000,
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

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost, "ascii")

  await sleep(3500)
  expect(dataSocket.socket.destroyed).toBe(true)

  await cmdSocket.end()
})

test("test STOR message with ASCII", async () => {
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

  expect(await cmdSocket.command("TYPE A").response()).toBe(
    "200 Type set to ASCII"
  )

  expect(await cmdSocket.command("STOR ../../mytestfile").response()).toBe(
    '550 Transfer failed "../../mytestfile"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost, "ascii")

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost, "ascii")

  cmdSocket.command("MLSD")

  const data = await dataSocket.receive()
  expect(data).toMatch("type=file")
  expect(data).toMatch("size=15")
  expect(data).toMatch("mytestfile")

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test STOR message overwrite not allowed", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      allowUserFileOverwrite: false,
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

  expect(await cmdSocket.command("STOR ../../mytestfile").response()).toBe(
    '550 Transfer failed "../../mytestfile"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  cmdSocket.command("LIST")

  const data = await dataSocket.receive()
  expect(data).toMatch("-r--r--r-- 1 ? ?             15")
  expect(data).toMatch("mytestfile")

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  expect(await cmdSocket.command("STOR /mytestfile").response()).toBe(
    "550 File already exists"
  )

  await cmdSocket.end()
})

test("test STOR message with handler", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
    },
  ]
  const fileStore = jest.fn().mockImplementationOnce(() =>
    Promise.resolve(
      new Writable({
        write: (data, enc, cb) => {
          cb()
        },
      })
    )
  )

  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
    store: addFactoryExtensions({
      fileExists() {
        return Promise.resolve(false)
      },
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

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(fileStore).toBeCalledTimes(1)
  expect(fileStore).toHaveBeenCalledWith("mytestfile", 0)

  await cmdSocket.end()
})

test("test STOR message with handler fails", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
    },
  ]
  const fileStore = jest.fn().mockImplementationOnce(() =>
    Promise.resolve(
      new Writable({
        write: (data, enc, cb) => {
          cb(Error("mock write failed"))
        },
      })
    )
  )

  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
    store: addFactoryExtensions({
      fileExists() {
        return Promise.resolve(false)
      },
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

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe('550 Transfer failed "mytestfile"')

  expect(fileStore).toBeCalledTimes(1)
  expect(fileStore).toHaveBeenCalledWith("mytestfile", 0)

  await cmdSocket.end()
})

test("test STOR over secure passive connection", async () => {
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

  expect(await cmdSocket.command("AUTH TLS").response()).toBe(
    "234 Using authentication type TLS"
  )

  cmdSocket = cmdSocket.startTLS({ rejectUnauthorized: false })

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

  const dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toMatch(
    "150 Awaiting passive connection"
  )

  await dataSocket
    .startTLS({ rejectUnauthorized: false })
    .send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toMatch(
    '226 Successfully transferred "mytestfile"'
  )

  await cmdSocket.end()
})

test("test STOR over active secure connection", async () => {
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

  expect(await cmdSocket.command("AUTH TLS").response()).toBe(
    "234 Using authentication type TLS"
  )

  cmdSocket = cmdSocket.startTLS({ rejectUnauthorized: false })

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("PBSZ 0").response()).toBe("200 PBSZ=0")

  expect(await cmdSocket.command("PROT P").response()).toBe(
    "200 Protection level is P"
  )

  const dataServer = new ExpectServer().listen(dataPort, "127.0.0.1")

  const portData = formatPort("127.0.0.1", dataPort)
  expect(await cmdSocket.command(`PORT ${portData}`).response()).toBe(
    "200 Port command successful"
  )

  expect(await cmdSocket.command("STOR mytestfile").response()).toMatch(
    "150 Opening data connection"
  )

  const dataSocket = await dataServer.getConnection()
  await dataSocket
    .startTLS({ rejectUnauthorized: false })
    .send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toMatch(
    '226 Successfully transferred "mytestfile"'
  )

  await dataServer.close()
  await cmdSocket.end()
})
