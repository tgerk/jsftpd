/* eslint-disable @typescript-eslint/no-var-requires */
const util = require("util")
const net = require("net")
const tls = require("tls")
const { PromiseSocket } = require("promise-socket")

// eslint-disable-next-line no-undef
const NODE_MAJOR_VERSION = process.versions.node.split(".")[0]

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

function formatPort(addr, port) {
  const p1 = (port / 256) | 0
  const p2 = port % 256
  return util.format("%s,%d,%d", addr.split(".").join(","), p1, p2)
}

function getCmdPortTCP() {
  return parseInt(NODE_MAJOR_VERSION + "021")
}

function getCmdPortTLS() {
  return parseInt(NODE_MAJOR_VERSION + "990")
}

function getDataPort() {
  return parseInt(NODE_MAJOR_VERSION + "120")
}

class ExpectServer {
  constructor(server) {
    this.server = server ?? net.createServer({ backlog: 0 })
    this.server.maxConnections = 1
  }
  listen(port, address) {
    this.server.listen(port, address)
    return this
  }
  getConnection() {
    // assume server is listening
    return new Promise((resolve) => {
      // using "once" rather than "on": capture only the first connnection
      // really would like to use as a queue or an Observable
      // consider recursion?
      this.server.once("connection", (socket) => {
        resolve(new ExpectSocket(socket))
      })
    })
  }
  close() {
    return new Promise((resolve) => {
      this.server.close(resolve)
    })
  }
}

class ExpectSocket extends PromiseSocket {
  constructor(socket) {
    super(socket ?? new net.Socket())
  }
  connect(port, host) {
    this.stream.connect(port, host)
    return this
  }
  startTLS(options) {
    return new ExpectSocket(tls.connect({ socket: this.stream, ...options }))
  }
  command(cmd) {
    this.write(cmd)
    return this
  }
  async response() {
    const content = await this.read()
    return content?.toString().trim()
  }
  async send(data) {
    await this.write(data)
    this.stream.end()
    await this.end()
  }
  async receive() {
    const content = await this.read()
    await this.end()
    return content?.toString().trim()
  }
}

function addFactoryExtensions(extensions) {
  return (factory) =>
    Object.assign((opts) => Object.assign(factory(opts), extensions), factory)
}

module.exports = {
  sleep,
  formatPort,
  getCmdPortTCP,
  getCmdPortTLS,
  getDataPort,
  ExpectServer,
  ExpectSocket,
  addFactoryExtensions,
}
