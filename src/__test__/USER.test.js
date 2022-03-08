/* eslint-disable @typescript-eslint/no-var-requires */
const { createFtpServer } = require("../jsftpd.ts")
const { getCmdPortTCP, getDataPort, formatPort, ExpectSocket } = require("./utils")
const path = require("path")

jest.setTimeout(5000)
const cmdPortTCP = getCmdPortTCP()
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

test("test null filename transformation", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
      filenameTransform: {
        in(file) {
          return file
        },
        out(name) {
          return name
        },
      },
    },
  ]
  server = createFtpServer({
    port: cmdPortTCP, user: users, minDataPort: dataPort,
  })
  server.start()

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

  const dataSocket = new ExpectSocket()
  dataSocket.connect(dataPort, localhost)

  await cmdSocket.command("LIST")

  const data = await dataSocket.receive()
  expect(data).toMatch(/^dr--r--r-- 1 john john/)
  expect(data).toMatch(/john$/)

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test outbound filename transformation", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
      filenameTransform: {
        in(file) {  // affects lookups
          return file
        },
        out(file) { // affects listings
          const { dir, base, name } = path.parse(file)
          return path.join(
            dir,
            /^\d+.nc$/i.test(base) ? `O${name}` : base
          )
        },
      },
    },
  ]
  server = createFtpServer({
    port: cmdPortTCP, user: users, minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  expect(await cmdSocket.command("MKD 0123.nc").response()).toBe(
    "250 Folder created successfully"
  )

  const passiveModeData = formatPort("127.0.0.1", dataPort)
  expect(await cmdSocket.command("PASV").response()).toBe(
    `227 Entering passive mode (${passiveModeData})`
  )

  const dataSocket = new ExpectSocket()
  dataSocket.connect(dataPort, localhost)

  await cmdSocket.command("LIST")

  const data = await dataSocket.receive()
  expect(data).toMatch(/^dr--r--r-- 1 john john/)
  expect(data).toMatch(/O0123$/)

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test inbound filename transformation", async () => {
  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFileCreate: true,
      // filename transformation from SolidWorks form (at-rest) and DNC form (in-flight)
      // !!! files at-rest with DNC-formed names will be inaccessible !!!
      filenameTransform: {
        in(file) {  // affects file references
          const { dir, base } = path.parse(file),
            dncForm = base.match(/^O(\d+$)/)
          return path.join(dir, dncForm ? `${dncForm[1]}.nc` : base)
        },
        out(file) { // affects listings
          return file
        },
      },
    },
  ]
  server = createFtpServer({
    port: cmdPortTCP, user: users, minDataPort: dataPort,
  })
  server.start()

  let cmdSocket = new ExpectSocket()
  expect(await cmdSocket.connect(cmdPortTCP, localhost).response()).toBe(
    "220 Welcome"
  )

  expect(await cmdSocket.command("USER john").response()).toBe(
    "232 User logged in"
  )

  const passiveModeData = formatPort("127.0.0.1", dataPort)
  expect(await cmdSocket.command("PASV").response()).toBe(
    `227 Entering passive mode (${passiveModeData})`
  )

  let dataSocket = new ExpectSocket()
  dataSocket.connect(dataPort, localhost)

  expect(await cmdSocket.command("STOR O0123").response()).toBe(
    "150 Awaiting passive connection"
  )

  await dataSocket.send("SOMETESTCONTENT")

  expect(await cmdSocket.response()).toBe(
    '226 Successfully transferred "0123.nc"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  await cmdSocket.command("LIST")

  const data = await dataSocket.response()
  expect(data).toMatch(/^-r--r--r-- 1 john john/)
  expect(data).toMatch(/0123.nc$/)
  await dataSocket.end()

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})
