import { jest } from "@jest/globals"

import createFtpServer from "../jsftpd.js"
import { getCmdPortTCP, formatPort, ExpectSocket } from "./utils.js"

jest.setTimeout(5000)

let server
const localhost = "127.0.0.1"
const cmdPortTCP = getCmdPortTCP()

const cleanup = function () {
  if (server) {
    server.close()
    server = null
  }
}
beforeEach(cleanup)
afterEach(cleanup)

const john = {
  username: "john",
  allowLoginWithoutPassword: true,
}

test("test PASV message takes next free port", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: cmdPortTCP + 1,
    user: [john],
    allowLoginWithoutPassword: true,
    maxConnections: 1,
  })
  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  const passiveModeData = formatPort("127.0.0.1", cmdPortTCP + 1)
  expect(await cmdSocket.command("PASV").response()).toBe(
    `227 Entering passive mode (${passiveModeData})`
  )

  expect(await cmdSocket.command("LIST").response()).toMatch(
    "150 Awaiting passive data connection"
  )

  let dataSocket = new ExpectSocket()
  expect(await dataSocket.connect(cmdPortTCP + 1, localhost).receive()).toBe("")

  expect(await cmdSocket.response()).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test PASV message fails port unavailable", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: cmdPortTCP,
    user: [john],
    allowLoginWithoutPassword: true,
    maxConnections: 0,
  })

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("PASV").response()).toBe(
    "501 Passive command failed"
  )

  await cmdSocket.end()
})

test("test PASV message fails port range fails", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: 70000,
    user: [john],
    allowLoginWithoutPassword: true,
    maxConnections: 0,
  })

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("PASV").response()).toBe(
    "501 Passive command failed"
  )

  await cmdSocket.end()
})

test("test EPSV message takes next free port", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: cmdPortTCP + 1,
    user: [john],
    allowLoginWithoutPassword: true,
    maxConnections: 1,
  })

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${cmdPortTCP + 1}|)`
  )

  expect(await cmdSocket.command("LIST").response()).toMatch(
    "150 Awaiting passive data connection"
  )

  let dataSocket = new ExpectSocket()
  expect(await dataSocket.connect(cmdPortTCP + 1, localhost).receive()).toBe("")
  expect(await cmdSocket.response()).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test EPSV message fails port unavailable", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    minDataPort: cmdPortTCP,
    user: [john],
    allowLoginWithoutPassword: true,
    maxConnections: 0,
  })

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    "501 Extended passive command failed"
  )

  await cmdSocket.end()
})
