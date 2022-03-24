/**
 * a Deferred<T> is a Promise<T>:  it may be resolved, rejected, or unsettled
 * the process that leads to resolution or rejection is what is deferred
 * 
 * example:
 *  const val = new Deferred<String>()
 *  setTimeout(() => { val.resolve("Hello World") }, 200)
 *  val.then(console.log, console.error)
 */

interface IDeferred<T> extends Promise<T> {
  resolve(val: T): undefined
  reject(error: Error): undefined
}

export default class Deferred<T> implements IDeferred<T> {
  p: Promise<T>

  constructor() {
    this.p = new Promise((resolve, reject) => {
      Object.assign(this, { resolve, reject })
    })
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  resolve(val: T): undefined {
    throw new Error("Method not implemented.")
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  reject(error: Error): undefined {
    throw new Error("Method not implemented.")
  }

  get [Symbol.toStringTag]() {
    return this.p[Symbol.toStringTag]
  }

  get then() {
    return this.p.then.bind(this.p)
  }
  get catch() {
    return this.p.catch.bind(this.p)
  }
  get finally() {
    return this.p.finally.bind(this.p)
  }
}
