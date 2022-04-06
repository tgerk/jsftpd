/**
 * this module provided as an example of decorating backend storage handler methods
 */

import path from "path"
import { Socket } from "net"
import { TLSSocket } from "tls"
import { Credential } from "../auth"
import { StoreFactory, Store } from "../store"

// present names in on-disk ####.nc format as DNC-style O####
function transformOutbound(file: string): string {
  const { dir, base, name } = path.parse(file)
  return path.join(dir, base.match(/^\d+.nc$/i) ? `O${name}` : base)
}

// resolve names from DNC-style O#### to on-disk ####.nc format
function transformInbound(file: string): string {
  const { dir, base } = path.parse(file),
    dncForm = base.match(/^O(\d+$)/)
  return path.join(dir, dncForm ? `${dncForm[1]}.nc` : base)
}

export default function composableFactory(factory: StoreFactory): StoreFactory {
  // TODO: munge static base-folder functions of the factory

  return Object.assign(function composeDncTranslateFactory(
    user: Credential,
    client: Socket | TLSSocket
  ): Store {
    // TODO: munge the user's credential here

    const handlers = factory(user, client, {
        translateFilename: transformInbound,
      }),
      {
        // decorate these functions:
        folderList: origListFolder,
      } = handlers

    // display on-disk ####.nc files with DNC-style O#### names
    function folderList(folder: string) {
      return origListFolder(folder).then((stats) =>
        stats.map((fstat) =>
          Object.assign(fstat, {
            name: transformOutbound(fstat.name),
          })
        )
      )
    }

    // replace the decorated functions
    return Object.assign(handlers, { folderList })
  },
  factory)
}
