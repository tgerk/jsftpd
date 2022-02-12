const { createFtpServer: createServer } = require("../jsftpd.ts")
const net = require("net")
const tls = require("tls")
const path = require("path")
const fs = require("fs/promises")
const { PromiseSocket, TimeoutError } = require("promise-socket")
const { sleep, getCmdPortTCP, getDataPort } = require("./utils")
const { fstat } = require("fs")
const { Writable } = require("stream")

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

test("test STOR message without permission", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: false,
    },
  ]
  server = createServer({
    cnf: { port: 50021, user: users, minDataPort: dataPort },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(50021, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe('550 Transfer failed "mytestfile"')

  await dataSocket.end()
  await promiseSocket.end()
})

test("test STOR message", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({
    cnf: { port: 50021, user: users, minDataPort: dataPort },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(50021, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("STOR ../../mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '550 Transfer failed "../../mytestfile"'
  )

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  promiseDataSocket = new PromiseSocket(new net.Socket())
  dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("MLSD")

  dataContent = await promiseDataSocket.read()
  expect(dataContent.toString().trim()).toMatch("type=file")
  expect(dataContent.toString().trim()).toMatch("size=15")
  expect(dataContent.toString().trim()).toMatch("mytestfile")
  await promiseDataSocket.end()

  await sleep(100)

  content = await promiseSocket.read()
  expect(content.toString().trim()).toMatch("150 Opening data channel")
  expect(content.toString().trim()).toMatch('226 Successfully transferred "/"')

  await promiseSocket.end()
})

test("test STOR message with ASCII", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  server = createServer({
    cnf: { port: 50021, user: users, minDataPort: dataPort },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(50021, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("TYPE A")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("200 Type set to ASCII")

  await promiseSocket.write("STOR ../../mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '550 Transfer failed "../../mytestfile"'
  )

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  dataSocket.setEncoding("ascii")
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  promiseDataSocket = new PromiseSocket(new net.Socket())
  dataSocket = promiseDataSocket.stream
  dataSocket.setEncoding("ascii")
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("MLSD")

  dataContent = await promiseDataSocket.read()
  expect(dataContent.toString().trim()).toMatch("type=file")
  expect(dataContent.toString().trim()).toMatch("size=15")
  expect(dataContent.toString().trim()).toMatch("mytestfile")
  await promiseDataSocket.end()

  await sleep(100)

  content = await promiseSocket.read()
  expect(content.toString().trim()).toMatch("150 Opening data channel")
  expect(content.toString().trim()).toMatch('226 Successfully transferred "/"')

  await promiseSocket.end()
})

test("test STOR message overwrite not allowed", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileOverwrite: false,
    },
  ]
  server = createServer({
    cnf: { port: 50021, user: users, minDataPort: dataPort },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(50021, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("STOR ../../mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '550 Transfer failed "../../mytestfile"'
  )

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  promiseDataSocket = new PromiseSocket(new net.Socket())
  dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("MLSD")

  dataContent = await promiseDataSocket.read()
  expect(dataContent.toString().trim()).toMatch("type=file")
  expect(dataContent.toString().trim()).toMatch("size=15")
  expect(dataContent.toString().trim()).toMatch("mytestfile")
  await promiseDataSocket.end()

  await sleep(100)

  content = await promiseSocket.read()
  expect(content.toString().trim()).toMatch("150 Opening data channel")
  expect(content.toString().trim()).toMatch('226 Successfully transferred "/"')

  await promiseSocket.write("STOR /mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("550 File already exists")

  await promiseSocket.end()
})

test("test STOR message with handler", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
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

  server = createServer({
    cnf: { port: 50021, user: users, minDataPort: dataPort },
    hdl: {
      fileExists() {
        return Promise.resolve(true)
      },
      fileStore,
    },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(50021, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    '226 Successfully transferred "mytestfile"'
  )

  expect(fileStore).toBeCalledTimes(1)
  expect(fileStore).toHaveBeenCalledWith("mytestfile", 0, "binary")

  await promiseSocket.end()
})

test("test STOR message with handler fails", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
    },
  ]
  const handler = async (username, path, filename, data, offset) => {
    expect(username).toMatch("john")
    expect(filename).toMatch("mytestfile")
    expect(path).toMatch("/")
    expect(data.toString()).toMatch("SOMETESTCONTENT")
    expect(offset).toBe(0)
    return false
  }
  const fileStore = jest.fn().mockImplementationOnce(() =>
    Promise.resolve(
      new Writable({
        write: (data, enc, cb) => {
          cb(Error("mock write failed"))
        },
      })
    )
  )

  server = createServer({
    cnf: { port: 50021, user: users, minDataPort: dataPort },
    hdl: {
      fileExists() {
        return Promise.resolve(true)
      },
      fileStore,
    },
  })
  server.start()

  let promiseSocket = new PromiseSocket(new net.Socket())
  let socket = promiseSocket.stream
  await socket.connect(50021, localhost)
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("220 Welcome")

  await promiseSocket.write("USER john")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("232 User logged in")

  await promiseSocket.write("EPSV")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  let promiseDataSocket = new PromiseSocket(new net.Socket())
  let dataSocket = promiseDataSocket.stream
  await dataSocket.connect(dataPort, localhost)

  await promiseSocket.write("STOR mytestfile")
  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe("150 Opening data channel")

  await promiseDataSocket.write("SOMETESTCONTENT")
  dataSocket.end()
  await promiseDataSocket.end()

  content = await promiseSocket.read()
  expect(content.toString().trim()).toBe('550 Transfer failed "mytestfile"')

  expect(fileStore).toBeCalledTimes(1)
  expect(fileStore).toHaveBeenCalledWith("mytestfile", 0, "binary")

  await promiseSocket.end()
})
