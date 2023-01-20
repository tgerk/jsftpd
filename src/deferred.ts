import type EventEmitter from "node:events"

export function Deferred<T = undefined>() {
  let resolve: (value: T | PromiseLike<T>) => void,
    reject: (reason?: unknown) => void
  return Object.assign(
    new Promise<T>((res, rej) => {
      resolve = res
      reject = rej
    }),
    { resolve, reject }
  )
}
/* export class Deferred<T = undefined> extends Promise<T> {
  // resolve: (value: T | PromiseLike<T>) => void
  // reject: (reason?: unknown) => void
  constructor() {
    let resolve, reject
    super((res, rej) => {
      resolve = res
      reject = rej
    })

    // Something about the V8 native Promise object, Object.assign and setting 
    // this.resolve = resolve
    // this.reject = reject
    return Object.assign(this, { resolve, reject })
  }
} */

// the queue is an array of Deferred promises; all items but the first are resolved
// when the queue is terminated, the first is either resolved or rejected
export function DeferredQueue<T, TFinal>() {
  let gatekeeper = Promise.resolve(),
    terminated = false

  return Object.assign([Deferred<T | TFinal>()], {
    resolve(value: T) {
      if (terminated) return // throw an error?

      const resolve = this[0].resolve
      this.unshift(Deferred<T>())
      resolve(value)
    },
    reject(reason: unknown) {
      terminated = true
      this[0].reject(reason)
    },
    finish(result: TFinal) {
      terminated = true
      this[0].resolve(result)
    },

    async next() {
      // suspend until previous call has completed
      const lastGate = gatekeeper,
        myGate = (gatekeeper = Deferred())
      await lastGate

      const value = await this[this.length - 1]
      if (this.length > 1) this.pop()
      myGate.resolve()
      return value
    },
  })
}

// should be able to infer U from the type of T[on(e: event)],
export function addDeferredIteratorOnEvent<T extends EventEmitter, U>(
  emitter: T,
  event: string
): T & AsyncIterableIterator<U> {
  const _queue = DeferredQueue<U, never>()
  return Object.assign(
    emitter.on(event, function (value: U) {
      _queue.resolve(value)
    }),
    {
      next() {
        return _queue.next().then(
          (value) => (value ? { value } : { done: true, value: undefined }),
          (error) => Promise.reject({ done: true, value: error })
        )
      },
      return(value: never) {
        _queue.finish(value)
        return this.next()
      },
      throw(error: unknown) {
        _queue.reject(error)
        return this.next()
      },

      [Symbol.asyncIterator]() {
        return this
      },
    }
  )
}
