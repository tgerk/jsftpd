/**
 * this module provided as an example of decorating backend storage handler methods
 *  use one hook and override one interface method of base factory
 *
 * TODO: make behavior contingent on user's credential or remote client
 */

import path from "path"
import { Socket } from "net"
import { Credential } from "../auth"
import { StoreFactory, Store, StoreOptions, Path } from "../store"

// present names in on-disk ####.nc format as DNC-style O####
function transformOutbound(file: Path): typeof file {
  const { dir, base, name } = path.parse(file)
  return path.join(dir, base.match(/^\d+.nc$/i) ? `O${name}` : base) as Path
}

// resolve names from DNC-style O#### to on-disk ####.nc format
function transformInbound(file: Path): typeof file {
  const { dir, base } = path.parse(file),
    [matched, name] = base.match(/^O(\d+$)/)
  return path.join(dir, matched ? `${name}.nc` : base)
}

export default function composableFactory(
  baseFactory: StoreFactory
): StoreFactory {
  return function dncTranslatingFactory(
    user: Credential,
    client: Socket,
    options: StoreOptions = {}
  ): Store {
    const handlers = baseFactory(user, client, {
      ...options,
      resolveFilename: transformInbound,
    })

    return Object.assign(handlers, {
      folderList: function folderList(folder: string) {
        return handlers.folderList(folder).then((stats) =>
          stats.map((fstat) =>
            Object.assign(fstat, {
              name: transformOutbound(fstat.name),
            })
          )
        )
      },
    })
  }
}
