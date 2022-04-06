/* eslint-disable @typescript-eslint/no-var-requires */
const { createFtpServer } = require("../jsftpd.ts")
const {
  getCmdPortTCP,
  getDataPort,
  formatPort,
  ExpectSocket,
} = require("./utils")
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

test("test outbound filename transformation", async () => {
  function transformOutbound(file) {
    const { dir, base, name } = path.parse(file)
    return path.join(dir, base.match(/^\d+.nc$/i) ? `O${name}` : base)
  }

  const users = [
    {
      username: "john",
      allowLoginWithoutPassword: true,
      allowUserFolderCreate: true,
    },
  ]
  server = await createFtpServer({
    port: cmdPortTCP,
    user: users,
    minDataPort: dataPort,
    store: (factory) =>
      Object.assign((user) => {
        const backend = factory(user),
          { folderList: folderListOriginal } = backend
        return Object.assign(backend, {
          // display on-disk ####.nc files with DNC-style O#### names
          folderList: (folder) =>
            folderListOriginal(folder).then((stats) =>
              stats.map((fstat) =>
                Object.assign(fstat, {
                  name: transformOutbound(fstat.name),
                })
              )
            ),
        })
      }, factory),
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

  await cmdSocket.command("NLST")

  // displayed name actually different!
  const data = await dataSocket.receive()
  expect(data).toBe("O0123")

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})

test("test inbound filename transformation", async () => {
  function transformInbound(file) {
    const { dir, base } = path.parse(file),
      dncForm = base.match(/^O(\d+$)/)
    return path.join(dir, dncForm ? `${dncForm[1]}.nc` : base)
  }

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
    store: (factory) =>
      Object.assign((user, client, tools) => {
        return factory(user, client, {
          ...tools,
          translateFilename: transformInbound,
        })
      }, factory),
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
    '226 Successfully transferred "O0123"'
  )

  expect(await cmdSocket.command("EPSV").response()).toBe(
    `229 Entering extended passive mode (|||${dataPort}|)`
  )

  dataSocket = new ExpectSocket()
  await dataSocket.connect(dataPort, localhost)

  await cmdSocket.command("NLST")

  // name on disk actually different!
  const data = await dataSocket.response()
  expect(data).toMatch(/0123.nc$/)
  await dataSocket.end()

  const response = await cmdSocket.response()
  expect(response).toMatch("150 Awaiting passive connection")
  expect(response).toMatch('226 Successfully transferred "/"')

  await cmdSocket.end()
})
