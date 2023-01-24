import { jest } from "@jest/globals"

import { Writable } from "node:stream"

import createFtpServer from "../jsftpd.js"
import {
  getDataPort,
  formatPort,
  sleep,
  ExpectSocket,
  ExpectServer,
  addFactoryExtensions,
} from "./utils.js"

jest.setTimeout(5000)

const cmdPortTCP = 50021
const dataPort = getDataPort()
const localhost = "127.0.0.1"

let server, dataServer
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
}

test("test STOR message without permission", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [{ ...john, allowUserFileCreate: false }],
    allowLoginWithoutPassword: true,
  })
  // .on("listening", function ({ server, basefolder }) {
  //   console.log("listening", server.address(), basefolder)
  // })
  // .on("session", (session) => {
  //   session.on("command-error", console.error)
  //   session.on("port-error", console.error)
  // })
  // .on("trace", (message) => console.info(message))
  // .on("debug", (message) => console.debug(message))
  // .on("error", console.error)

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
    "550 Permission denied"
  )

  await dataSocket.end()
  await cmdSocket.end()
})

test("test STOR message OK", async () => {
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

  expect(await cmdSocket.command("STOR ../../mytestfile").response()).toBe(
    "501 Command failed"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive data connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort + 1}|)`
  )

  dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort + 1, localhost)

  cmdSocket.command("MLSD")

  const data = await dataSocket.receive()
  expect(data).toMatch("type=file")
  expect(data).toMatch("size=15")
  expect(data).toMatch("mytestfile")

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive data connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test passive data connection times out", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [john],
    allowLoginWithoutPassword: true,
    timeout: 3000,
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

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive data connection"
  )

  await sleep(3500)
  expect(dataSocket.socket.destroyed).toBe(true)

  await cmdSocket.end()
})

test("test STOR message with ASCII", async () => {
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

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive data connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort + 1}|)`
  )

  dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort + 1, localhost)

  cmdSocket.command("MLSD")

  const data = await dataSocket.receive()
  expect(data).toMatch("type=file")
  expect(data).toMatch("size=15")
  expect(data).toMatch("mytestfile")

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive data connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test STOR message overwrite not allowed", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [{ ...john, allowUserFileOverwrite: false }],
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

  let dataSocket = new ExpectSocket().connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive data connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  cmdSocket.command("LIST")

  dataSocket = new ExpectSocket()
  const data = await dataSocket.connect(dataPort, localhost).receive()
  expect(data).toMatch("-r--r--r-- 1 ? ?             15")
  expect(data).toMatch("mytestfile")

  await sleep(10)
  expect(dataSocket.stream.destroyed).toBe(true)

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive data connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  expect(await cmdSocket.command("STOR /mytestfile").response()).toBe(
    "550 File already exists"
  )

  await sleep(100)
  expect(dataSocket.stream.destroyed).toBe(true)

  await cmdSocket.end()
})

test("test STOR message with handler", async () => {
  const fileStore = jest.fn().mockResolvedValueOnce(
    new Writable({
      write: (data, enc, cb) => {
        cb()
      },
    })
  )
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [john],
    allowLoginWithoutPassword: true,
    store: addFactoryExtensions({ fileStore }),
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

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive data connection"
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
  const fileStore = jest.fn().mockResolvedValueOnce(
    new Writable({
      write: (data, enc, cb) => {
        cb(Error("mock write failed"))
      },
    })
  )
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [john],
    allowLoginWithoutPassword: true,
    store: addFactoryExtensions({ fileStore }),
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

  let dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR mytestfile").response()).toBe(
    "150 Awaiting passive data connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe("550 Transfer failed")

  expect(fileStore).toBeCalledTimes(1)
  expect(fileStore).toHaveBeenCalledWith("mytestfile", 0)

  await cmdSocket.end()
})

test("test STOR over secure passive connection", async () => {
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
    "150 Awaiting passive data connection"
  )

  await dataSocket
    .startTLS({ rejectUnauthorized: false })
    .send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toMatch(
    '226 Successfully transferred "mytestfile"'
  )

  await cmdSocket.end()
})

test("test STOR over secure active connection", async () => {
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
    "150 Opening active data connection"
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
