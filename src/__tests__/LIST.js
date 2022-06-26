import { jest } from "@jest/globals"

import createFtpServer from "../jsftpd.js"
import {
  getCmdPortTCP,
  getDataPort,
  formatPort,
  ExpectSocket,
  ExpectServer,
  addFactoryExtensions,
} from "./utils.js"

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
  allowUserFolderCreate: true,
  allowUserileCreate: true,
}

test("test LIST message", async () => {
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

  expect(await cmdSocket.command("MKD john").response()).toBe(
    "250 Folder created successfully"
  )

  const passiveModeData = formatPort("127.0.0.1", dataPort)
  expect(await cmdSocket.command("PASV").response()).toBe(
    `227 Entering passive mode (${passiveModeData})`
  )

  await cmdSocket.command("LIST")

  let dataSocket = new ExpectSocket()
  expect(await dataSocket.connect(dataPort, localhost).receive()).toMatch(
    "dr--r--r-- 1 ? ?"
  )

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test MLSD message", async () => {
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

test("test MLSD message over passive secure connection", async () => {
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

  expect(await cmdSocket.command("MLSD").response()).toMatch(
    "150 Awaiting passive connection"
  )

  const dataSocket = new ExpectSocket()
  expect(
    await dataSocket
      .connect(dataPort, localhost)
      .startTLS({ rejectUnauthorized: false })
      .receive()
  ).toBe("")

  expect(await cmdSocket.response()).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test MLSD message over secure active connection", async () => {
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

  expect(
    await cmdSocket.command(`EPRT ||127.0.0.1|${dataPort}|`).response()
  ).toBe("200 Extended Port command successful")

  expect(await cmdSocket.command("MLSD").response()).toMatch(
    "150 Opening data connection"
  )

  expect(
    await (await dataServer.getConnection())
      .startTLS({ rejectUnauthorized: false })
      .receive()
  ).toBe("")

  expect(await cmdSocket.response()).toMatch('226 Successfully transferred "/"')

  await dataServer.close()
  await cmdSocket.end()
})

test("test MLSD message with handler", async () => {
  const folderList = jest.fn().mockImplementationOnce(() => Promise.resolve([]))
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: dataPort,
    user: [john],
    allowLoginWithoutPassword: true,
    store: addFactoryExtensions({ folderList }),
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

  await cmdSocket.write("MLSD")

  let dataSocket = new ExpectSocket()
  expect(await dataSocket.connect(dataPort, localhost).receive()).toBe("")

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})
