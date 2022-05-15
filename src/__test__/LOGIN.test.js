/* eslint-disable @typescript-eslint/no-var-requires */
const { createFtpServer } = require("../jsftpd.ts")
const { getCmdPortTCP, ExpectSocket } = require("./utils")

jest.setTimeout(5000)
let server
const cmdPortTCP = getCmdPortTCP()
const localhost = "127.0.0.1"

const cleanup = function () {
  if (server) {
    server.close()
    server = null
  }
}
beforeEach(() => cleanup())
afterEach(() => cleanup())

test("error message when not logged in", async () => {
  server = createFtpServer({ port: cmdPortTCP })

  const cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("FEAT").response()).toBe("530 Not logged in")

  await cmdSocket.end()
})

test("login as anonymous not allowed by default", async () => {
  server = createFtpServer({ port: cmdPortTCP })

  const cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER anonymous").response()).toBe(
    "530 Not logged in"
  )

  await cmdSocket.end()
})

test("login as anonymous when enabled", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    allowAnonymousLogin: true,
  })

  const cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER anonymous").response()).toBe(
    "331 Password required for anonymous"
  )

  expect(await cmdSocket.command("PASS anonymous@local").response()).toBe(
    "230 Logged on"
  )

  await cmdSocket.end()
})

test("login with default user settings", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    username: "john",
    password: "doe",
  })

  const cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "331 Password required for john"
  )

  expect(await cmdSocket.command("PASS doe").response()).toBe("230 Logged on")

  await cmdSocket.end()
})

test("login with default user settings without password allowed", async () => {
  server = createFtpServer({
    port: cmdPortTCP,
    username: "john",
    allowLoginWithoutPassword: true,
  })

  const cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  await cmdSocket.end()
})

test("login with user settings", async () => {
  const users = [
    {
      username: "john",
      password: "doe",
    },
    {
      username: "michael",
      password: "myers",
    },
  ]
  server = createFtpServer({ port: cmdPortTCP, user: users })

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "331 Password required for john"
  )

  expect(await cmdSocket.command("PASS doe").response()).toBe("230 Logged on")

  const cmdSocket2 = new ExpectSocket()
  expect(await cmdSocket2.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket2.command("USER michael").response()).toBe(
    "331 Password required for michael"
  )

  expect(await cmdSocket2.command("PASS myers").response()).toBe(
    "230 Logged on"
  )

  await cmdSocket2.end()
  await cmdSocket.end()
})

test("login with user settings without password allowed", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
    {
      username: "michael",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createFtpServer({ port: cmdPortTCP, user: users })

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  await cmdSocket.end()

  cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER michael").response()).toBe(
    "232 User logged in"
  )

  await cmdSocket.end()
})

test("login with user settings and wrong user rejected", async () => {
  const users = [
    {
      username: "john",
      password: "doe",
    },
  ]
  server = createFtpServer({ port: cmdPortTCP, user: users })

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER michael").response()).toBe(
    "530 Not logged in"
  )

  await cmdSocket.end()
})

test("login with user settings and wrong password rejected", async () => {
  const users = [
    {
      username: "john",
      password: "doe",
    },
  ]
  server = createFtpServer({ port: cmdPortTCP, user: users })

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "331 Password required for john"
  )

  expect(await cmdSocket.command("PASS pass").response()).toBe(
    "530 Username or password incorrect"
  )

  await cmdSocket.end()
})

test("login with active reload user settings", async () => {
  const users = [
    {
      username: "john",
      password: "doe",
    },
  ]
  server = createFtpServer({ port: cmdPortTCP, user: users })

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "331 Password required for john"
  )

  expect(await cmdSocket.command("PASS doe").response()).toBe("230 Logged on")

  const cmdSocket2 = new ExpectSocket()
  expect(await cmdSocket2.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket2.command("USER michael").response()).toBe(
    "530 Not logged in"
  )

  users.push({
    username: "michael",
    password: "myers",
  })
  server.reloadAuth({ user: users })

  const cmdSocket3 = new ExpectSocket()
  expect(await cmdSocket3.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket3.command("USER michael").response()).toBe(
    "331 Password required for michael"
  )

  expect(await cmdSocket3.command("PASS myers").response()).toBe(
    "230 Logged on"
  )

  await cmdSocket3.end()
  await cmdSocket2.end()
  await cmdSocket.end()
})
