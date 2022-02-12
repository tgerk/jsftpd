export default class Deferred<T> {
  p: Promise<T>

  constructor() {
    this.p = new Promise((resolve, reject) => {
      Object.assign(this, { resolve, reject })
    })
  }

  resolve(socket: T) {}
  reject(error: any) {}

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
