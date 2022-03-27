/* eslint-disable @typescript-eslint/no-var-requires */
const { createFtpServer } = require("../jsftpd.ts")
const { getCmdPortTCP, formatPort, ExpectSocket } = require("./utils")

jest.setTimeout(5000)
let server
const cmdPortTCP = getCmdPortTCP()
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

test("test PASV message takes next free port", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: cmdPortTCP,
    maxConnections: 1,
  })
  server.start()

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
    "150 Awaiting passive connection"
  )

  let dataSocket = new ExpectSocket()
  const data = await dataSocket.connect(cmdPortTCP + 1, localhost).receive()
  expect(data).toBe("")

  expect(await cmdSocket.response()).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test PASV message fails port unavailable", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: cmdPortTCP,
    maxConnections: 0,
  })
  server.start()

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
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: 70000,
    maxConnections: 0,
  })
  server.start()

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
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: cmdPortTCP,
    maxConnections: 1,
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
    `229 Entering extended passive mode (|||${cmdPortTCP + 1}|)`
  )

  expect(await cmdSocket.command("LIST").response()).toMatch(
    "150 Awaiting passive connection"
  )

  let dataSocket = new ExpectSocket()
  expect(await dataSocket.connect(cmdPortTCP + 1, localhost).receive()).toBe("")
  expect(await cmdSocket.response()).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test EPSV message fails port unavailable", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: cmdPortTCP,
    maxConnections: 0,
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
    "501 Extended passive command failed"
  )

  await cmdSocket.end()
})
