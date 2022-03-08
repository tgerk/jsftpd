/* eslint-disable @typescript-eslint/no-var-requires */
const util = require("util")
const net = require("net")
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

class ExpectSocket extends PromiseSocket {
  constructor(socket) {
    super(socket ?? new net.Socket())
  }
  connect(port, host, encoding) {
    if (encoding) this.stream.setEncoding(encoding)
    this.stream.connect(port, host)
    return this
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

module.exports = {
  sleep,
  formatPort,
  getCmdPortTCP,
  getCmdPortTLS,
  getDataPort,
  ExpectSocket
}
