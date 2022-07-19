import { jest } from "@jest/globals"

import { Readable, Writable } from "node:stream"

import createFtpServer from "./jsftpd.js"
import {
  getCmdPortTCP,
  getDataPort,
  formatPort,
  ExpectSocket,
  ExpectServer,
  addFactoryExtensions,
} from "./util/tests.js"

jest.setTimeout(5000)

let server, dataServer
const cmdPortTCP = getCmdPortTCP()
const dataPort = getDataPort()
const localhost = "127.0.0.1"

const cleanup = function () {
  if (server) {
    if (dataServer) {
      dataServer.close()
      dataServer = null
    }
    server.close()
    server = null
  }
}
beforeEach(() => cleanup())
afterEach(() => cleanup())

const john = {
  username: "john",
  allowLoginWithoutPassword: true,
  allowUserFileCreate: true,
  allowUserFileRetrieve: true,
}

test("test RETR message not allowed", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [{ ...john, allowUserFileRetrieve: false }],
    allowLoginWithoutPassword: true,
  })

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
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [john],
    allowLoginWithoutPassword: true,
  })

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
    "150 Awaiting passive connection"
  )

  dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.response()).toMatch("550 File not found")

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
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [john],
    allowLoginWithoutPassword: true,
  })

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
  await dataSocket.connect(dataPort, localhost).send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  expect(await cmdSocket.command("RETR /someotherfile").response()).toBe(
    "150 Awaiting passive connection"
  )

  dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.response()).toBe("550 File not found")

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

test("test RETR message with handler", async () => {
  const fileStore = jest.fn().mockResolvedValueOnce(
      new Writable({
        write: (data, enc, cb) => {
          cb()
        },
      })
    ),
    fileRetrieve = jest.fn().mockResolvedValueOnce(
      new Readable({
        read: function () {
          this.push("SOMETESTCONTENT")
          this.destroy()
        },
      })
    )
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [john],
    allowLoginWithoutPassword: true,
    store: addFactoryExtensions({
      fileRetrieve,
      fileStore,
    }),
  })

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

  expect(await cmdSocket.response()).toMatch("150 Awaiting passive connection")
  expect(await cmdSocket.response()).toMatch(
    '226 Successfully transferred "mytestfile"'
  )

  expect(fileStore).toBeCalledTimes(1)
  expect(fileRetrieve).toBeCalledTimes(1)

  await cmdSocket.end()
})

test("test RETR message with handler fails", async () => {
  const fileStore = jest.fn().mockResolvedValueOnce(
      new Writable({
        write: (data, enc, cb) => {
          cb()
        },
      })
    ),
    fileRetrieve = jest.fn().mockResolvedValueOnce(
      new Readable({
        read: function () {
          this.destroy(Error("mock"))
        },
      })
    )
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [john],
    allowLoginWithoutPassword: true,
    store: addFactoryExtensions({
      fileRetrieve,
      fileStore,
    }),
  })

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

  expect(await cmdSocket.command("RETR mytestfile").response()).toMatch(
    "150 Awaiting passive connection"
  )

  dataSocket = new ExpectSocket()
  const data = await dataSocket.connect(dataPort, localhost).receive()
  expect(data).toBe(undefined)

  expect(await cmdSocket.response()).toMatch('550 Transfer failed "mytestfile"')

  expect(fileStore).toBeCalledTimes(1)
  expect(fileRetrieve).toBeCalledTimes(1)

  await cmdSocket.end()
})

test("test RETR message no active or passive mode", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    user: [john],
    allowLoginWithoutPassword: true,
  })

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

test("test RETR over secure passive connection", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [john],
    allowLoginWithoutPassword: true,
  })

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

  // TODO: does this fail b/c passive port is not prepared for a second connection?
  expect(await cmdSocket.command("RETR mytestfile").response()).toMatch(
    "150 Awaiting passive connection"
  )

  expect(
    await dataSocket
      .connect(dataPort, localhost)
      .startTLS({ rejectUnauthorized: false })
      .receive()
  ).toMatch("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toMatch(
    '226 Successfully transferred "mytestfile"'
  )

  await cmdSocket.end()
})

test("test RETR over active secure connection", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [john],
    allowLoginWithoutPassword: true,
  })

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

  dataServer = new ExpectServer().listen(dataPort, "127.0.0.1")

  const portData = formatPort("127.0.0.1", dataPort)
  expect(await cmdSocket.command(`PORT ${portData}`).response()).toBe(
    "200 Port command successful"
  )

  expect(await cmdSocket.command("STOR mytestfile").response()).toMatch(
    "150 Opening data connection"
  )

  const storSocket = await dataServer.getConnection()
  await storSocket
    .startTLS({ rejectUnauthorized: false })
    .send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toMatch(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("RETR mytestfile").response()).toMatch(
    "150 Opening data connection"
  )

  const retrSocket = await dataServer.getConnection()
  expect(
    await retrSocket.startTLS({ rejectUnauthorized: false }).receive()
  ).toMatch("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toMatch(
    '226 Successfully transferred "mytestfile"'
  )

  await dataServer.close()
  await cmdSocket.end()
})
