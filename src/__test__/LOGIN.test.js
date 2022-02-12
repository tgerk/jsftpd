const { createFtpServer: createServer } = require("../jsftpd.ts")
const net = require("net")
const tls = require("tls")
const { PromiseSocket, TimeoutError } = require("promise-socket")
const { getCmdPortTCP, getDataPort } = require("./utils")

jest.setTimeout(5000)
let server,
  content,
  dataContent = null
const cmdPortTCP = getCmdPortTCP()
const dataPort = getDataPort()
const localhost = "127.0.0.1"

const cleanup = function () {
  if (server) {
    server.stop()
    server.cleanup()
    server = null
  }
  content = ""
  dataContent = ""
}
beforeEach(() => cleanup())
afterEach(() => cleanup())

test("error message when not logged in", async () => {
  server = createServer({ cnf: { port: cmdPortTCP } })
  server.start()

  const promiseSocket = new PromiseSocket(new net.Socket())
  const socket = promiseSocket.stream

  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")
  await promiseSocket.write("FEAT")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("530 Not logged in")

  await promiseSocket.end()
})

test("login as anonymous not allowed by default", async () => {
  server = createServer({ cnf: { port: cmdPortTCP } })
  server.start()

  const promiseSocket = new PromiseSocket(new net.Socket())
  const socket = promiseSocket.stream

  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")
  await promiseSocket.write("USER anonymous")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("530 Not logged in")

  await promiseSocket.end()
})

test("login as anonymous when enabled", async () => {
  server = createServer({
    cnf: { port: cmdPortTCP, allowAnonymousLogin: true },
  })
  server.start()

  const promiseSocket = new PromiseSocket(new net.Socket())
  const socket = promiseSocket.stream

  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER anonymous")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("331 Password required for anonymous")

  await promiseSocket.write("PASS anonymous@anonymous")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("230 Logged on")

  await promiseSocket.end()
})

test("login with default user settings", async () => {
  server = createServer({
    cnf: { port: cmdPortTCP, username: "john", password: "doe" },
  })
  server.start()

  const promiseSocket = new PromiseSocket(new net.Socket())
  const socket = promiseSocket.stream

  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("331 Password required for john")

  await promiseSocket.write("PASS doe")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("230 Logged on")

  await promiseSocket.end()
})

test("login with default user settings without password allowed", async () => {
  server = createServer({
    cnf: {
      port: cmdPortTCP,
      username: "john",
      allowLoginWithoutPassword: true,
    },
  })
  server.start()

  const promiseSocket = new PromiseSocket(new net.Socket())
  const socket = promiseSocket.stream

  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.end()
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
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("331 Password required for john")

  await promiseSocket.write("PASS doe")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("230 Logged on")

  await promiseSocket.end()

  promiseSocket = new PromiseSocket(new net.Socket())
  socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER michael")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("331 Password required for michael")

  await promiseSocket.write("PASS myers")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("230 Logged on")

  await promiseSocket.end()
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
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.end()

  promiseSocket = new PromiseSocket(new net.Socket())
  socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER michael")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.end()
})

test("login with user settings and wrong user rejected", async () => {
  const users = [
    {
      username: "john",
      password: "doe",
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER michael")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("530 Not logged in")

  await promiseSocket.end()
})

test("login with user settings and wrong password rejected", async () => {
  const users = [
    {
      username: "john",
      password: "doe",
    },
  ]
  server = createServer({ cnf: { port: cmdPortTCP, user: users } })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(cmdPortTCP, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("331 Password required for john")

  await promiseSocket.write("PASS pass")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("530 Username or password incorrect")

  await promiseSocket.end()
})
