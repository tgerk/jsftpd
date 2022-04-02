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
  resolve(val: T): void
  reject(error: Error): void
  // await(): Promise<T> // because await keyword doesn't work same on Deferred<T> as Promise<T>
}

type PromiseFunction<T> = (
  resolve: (value: T | PromiseLike<T>) => void,
  reject?: (reason?: unknown) => void
) => void

export default class Deferred<T> implements IDeferred<T> {
  deferredConstructor: PromiseFunction<T>
  p: Promise<T> = new Promise((resolve, reject) => {
    Object.assign(this, { resolve, reject })
  })

  constructor(ctor?: PromiseFunction<T>) {
    if (ctor) this.deferredConstructor = ctor
  }

  // dummy implementations
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  resolve(val: T): void {} // eslint-disable-line @typescript-eslint/no-empty-function

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  reject(error: Error): void {} // eslint-disable-line @typescript-eslint/no-empty-function

  get [Symbol.toStringTag]() {
    return this.p[Symbol.toStringTag]
  }

  get then(): Promise<T>["then"] {
    this.deferredConstructor?.(this.resolve, this.reject)
    return this.p.then.bind(this.p)
  }
  get catch(): Promise<T>["catch"] {
    return this.p.catch.bind(this.p)
  }
  get finally(): Promise<T>["finally"] {
    return this.p.finally.bind(this.p)
  }
}
