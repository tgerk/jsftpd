import { Server, Socket } from "net"
import tls from "tls"

// Taking guidance from Deno, extend Server as an async iteratable for incoming connections
// Support syntax "for const sock in await srvr { ... }", or "const { value: sock } = await srvr.next()"
export type ConnectionSource = Server &
  AsyncIterator<Socket> &
  AsyncIterable<Socket>

/**
 * inject a net.Server
 * make server iterable (for connections)
 *  bind connection, close, error events
 *
 */
export default function createConnectionSource(
  server: Server
): ConnectionSource {
  // implement async queue
  // maintain pair of lists that start with one entry each
  //  neither list will be empty unless the iterator is finished
  const iterableQueue = [] as Promise<IteratorResult<Socket>>[],
    resolverQueue = [] as ((
      value: IteratorResult<Socket> | PromiseLike<IteratorResult<Socket>>
    ) => void)[]

  function pushNext(init = false) {
    if (resolverQueue.length || init) {
      iterableQueue.push(
        new Promise<IteratorResult<Socket>>((resolve) => {
          resolverQueue.push(resolve)
        })
      )
    }
  }

  function resolveNext(socket: Socket) {
    resolverQueue.length > 1 || pushNext()
    resolverQueue.shift()?.({ value: socket })
  }

  function popNext() {
    iterableQueue.length > 1 || pushNext()
    return (
      iterableQueue.shift() ?? Promise.resolve({ done: true, value: undefined })
    )
  }

  function stop() {
    // leave resolver queue empty when finished:
    //  pushNext, resolveNext become no-op
    //  popNext will spend down previous resolved connections
    //  previous unresolved iterations will immediately resolve to done
    while (resolverQueue.length) {
      resolverQueue.shift()({ done: true, value: undefined })
    }
  }

  pushNext(true)
  return Object.assign(server, {
    next: popNext,
    [Symbol.asyncIterator]() {
      return this
    },
  })
    .on(
      server instanceof tls.Server ? "secureConnection" : "connection",
      function resolveConnection(socket) {
        resolveNext(socket)
      }
    )
    .on("error", function () {
      stop()
    })
    .on("close", function () {
      stop()
    })
}
