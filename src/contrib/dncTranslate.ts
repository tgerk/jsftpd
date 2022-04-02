/**
 * this module provided as an example of decorating backend storage handler methods
 */

import path from "path"
import { Credential } from "../auth"
import { StoreHandlersFactory, StoreHandlers } from "../store"

function transformOutbound(file: string): string {
  const { dir, base, name } = path.parse(file)
  return path.join(dir, base.match(/^\d+.nc$/i) ? `O${name}` : base)
}

function transformInbound(file: string): string {
  const { dir, base } = path.parse(file),
    dncForm = base.match(/^O(\d+$)/)
  return path.join(dir, dncForm ? `${dncForm[1]}.nc` : base)
}

export default function composableFactory(
  factory: StoreHandlersFactory
): StoreHandlersFactory {
  function composedFactory(user: Credential): StoreHandlers {
    // TODO: munge the user's credential here

    const handlers = factory(user),
      {
        // planning to decorate these functions:
        folderList: origListFolder,
        resolveFile: origResolveFile,
      } = handlers

    // display on-disk ####.nc files with DNC-style O#### names
    function folderList(folder: string) {
      return origListFolder(folder).then((stats) =>
        stats.map((fstat) =>
          Object.assign(fstat, {
            fname: transformOutbound(fstat.fname),
          })
        )
      )
    }

    // resolve name from DNC-style O#### to on-disk ####.nc format
    function resolveFile(file: string) {
      return origResolveFile(transformInbound(file))
    }

    // replace the decorated functions
    return Object.assign(handlers, { folderList, resolveFile })
  }

  // TODO: munge static base-folder functions of the factory

  return Object.assign(composedFactory, factory)
}
