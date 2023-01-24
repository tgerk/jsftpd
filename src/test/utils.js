import util from "util"
import net from "net"
import tls from "tls"
import { PromiseSocket } from "promise-socket"

// eslint-disable-next-line no-undef
const NODE_MAJOR_VERSION = process.versions.node.split(".")[0]

export function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

export function formatPort(addr, port) {
  const p1 = (port / 256) | 0
  const p2 = port % 256
  return util.format("%s,%d,%d", addr.split(".").join(","), p1, p2)
}

export function getCmdPortTCP() {
  return parseInt(NODE_MAJOR_VERSION + "021")
}

export function getCmdPortTLS() {
  return parseInt(NODE_MAJOR_VERSION + "990")
}

export function getDataPort() {
  return parseInt(
    NODE_MAJOR_VERSION +
      Math.floor(990 * Math.random())
        .toString()
        .padStart(3, "0")
  )
}

export class ExpectServer {
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

export class ExpectSocket extends PromiseSocket {
  constructor(socket) {
    super(socket ?? new net.Socket())
  }
  connect(port, host) {
    this.stream.connect(port, host)
    return this // connection is pending
  }
  async connectSync(port, host) {
    await super.connect(port, host)
    return this // connection is made
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
    const content = await this.readAll()
    await this.end()
    return content?.toString().trim()
  }
}

export function addFactoryExtensions(extensions) {
  return (factory) => (client, user, options) =>
    Object.assign(factory(client, user, options), extensions)
}
