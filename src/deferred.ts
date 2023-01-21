import type EventEmitter from "node:events"

// Typescript does not provide
type PromiseTask<T> = (
  resolve: (value: T | PromiseLike<T>) => void,
  reject: (reason?: unknown) => void
) => void

export class Deferred<T = undefined> extends Promise<T> {
  // should not clobber the static methods Promise.resolve and Promise.reject on Promise prototype
  // could use Object.assign to set Promise object's own properties, but that's Typescript un-friendly
  settle: (reason?: unknown, value?: T | PromiseLike<T>) => this
  constructor(
    executor?: PromiseTask<T>,
    { signal }: { signal?: AbortSignal } = {}
  ) {
    let settle: (reason?: unknown, value?: T | PromiseLike<T>) => this
    super((res, rej) => {
      settle = (reason, value) => {
        reason ? rej(reason) : res(value)
        return this
      }
      signal && (signal.onabort = rej)
      executor?.(res, rej)
    })

    this.settle = settle
  }
}

// when using Object.assign, succeeded when providing iterator methods as closure & not with an equivalent object
export function getDeferredIterator<T, TFinal>(): AsyncIterator<T, TFinal> & {
  inject(value: T): void // used by another control-flow to produce iterated values
} {
  // This queue is an array of Deferred objects, all but first item are resolved.  The iterator
  //  is terminated when first item is either rejected or resolved, indicating the final value
  const queue = [new Deferred<T | TFinal>()]
  let gatekeeper = new Deferred().settle(),
    done = false

  function next() {
    // suspend until previous call has completed, block following call until this is complete
    return new Promise<IteratorResult<T, TFinal>>((resolve, reject) => {
      const gate = new Deferred()
      gatekeeper.then(
        () =>
          queue[queue.length - 1].then(
            (value: T | TFinal) => {
              if (!done) queue.pop()

              // continue with next iteration after synchronous propagation of this one
              process.nextTick(gate.settle)
              resolve({ done, value } as IteratorResult<T, TFinal>)
            },
            (error: unknown) => Promise.reject({ done: true, value: error })
          ),
        reject
      )

      gatekeeper = gate // replace prior gatekeeper
    })
  }

  return {
    next,
    return(result: TFinal) {
      done = true
      queue[0].settle(null, result)
      return next()
    },
    throw(reason: unknown) {
      done = true
      queue[0].settle(reason)
      return next()
    },
    inject(value: T) {
      if (done) return // throw an error?

      queue.unshift(new Deferred<T | TFinal>())
      queue[1].settle(null, value)
    },
  }
}

// TODO: infer U from T and the event name:
// T[on(e: "event", listener: (arg: infer U) => void)]
export function addDeferredIteratorOnEvent<T extends EventEmitter, U>(
  emitter: T,
  eventName: string
): T & AsyncIterableIterator<U> {
  const iterator = getDeferredIterator<U, never>()
  return Object.assign(
    emitter.on(eventName, function (value: U) {
      iterator.inject(value)
    }),
    iterator,
    {
      [Symbol.asyncIterator]() {
        return this
      },
    }
  )
}
