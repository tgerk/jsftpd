import path from "path"
import { Socket } from "net"
import fs from "fs/promises"
import {
  existsSync,
  mkdirSync,
  rmSync,
  Stats as FsStats,
  createReadStream,
  createWriteStream,
} from "fs"
import { Readable, Writable } from "stream"

import { Credential } from "./auth"

export type AbsolutePath = `/${string}`
export type RelativePath = string
export type Stats = Partial<FsStats> & { name: string }

export enum Errors {
  EEXIST = "EEXIST",
  ENOENT = "ENOENT",
  ENOTDIR = "ENOTDIR",
  ENOTFILE = "ENOTFILE",
}

// FTP protocol assumes storage has a tree structure
//  PWD / CWD indicate a state of traversing the tree, i.e. "context"
//  file and folder manipulating commands require context
export interface Store {
  // control PWD state,implicit in other accessors/operations
  getFolder(): AbsolutePath
  setFolder(folder: RelativePath): Promise<AbsolutePath>

  // operations on folders/buckets/nodes, arg is relative to PWD
  folderDelete(folder: RelativePath): Promise<void>
  folderCreate(folder: RelativePath): Promise<void>
  folderList(folder?: RelativePath): Promise<Stats[]>

  // operations on files/objects/leaves, arg is relative to PWD
  fileDelete(file: RelativePath): Promise<void>
  fileStats(file: RelativePath): Promise<Stats>
  fileRetrieve(file: RelativePath, seek?: number): Promise<Readable>
  fileStore(
    file: RelativePath,
    allowReplace: boolean,
    seek?: number
  ): Promise<Writable>
  fileRename(
    fromFile: RelativePath
  ): Promise<((toFile: RelativePath) => Promise<void>) & { fromFile: RelativePath }>
  fileSetTimes(file: RelativePath, mtime: Date, atime?: Date): Promise<void>
}

export type StoreOptions = {
  resolveFoldername?: (x: AbsolutePath) => AbsolutePath
  resolveFilename?: (x: AbsolutePath) => AbsolutePath
}

export type StoreFactory = (
  user: Credential,
  client: Socket,
  options?: StoreOptions
) => Store

// module state
let defaultBaseFolder = path.join(process.cwd(), "__ftproot__") as AbsolutePath,
  cleanupBaseFolder: () => void

// export accessor and cleanup util
export function getBaseFolder() {
  return defaultBaseFolder
}

export function cleanup() {
  cleanupBaseFolder?.()
}

export default localStoreFactoryInit
export function localStoreFactoryInit(baseFolder: AbsolutePath) {
  if (!baseFolder) {
    if (!existsSync(defaultBaseFolder)) {
      mkdirSync(defaultBaseFolder)
      cleanupBaseFolder = function () {
        rmSync(defaultBaseFolder, { force: true, recursive: true })
      }
    }
  } else if (!existsSync(baseFolder)) {
    throw Object.assign(Error(`Base folder must exist`), {
      code: Errors.ENOTDIR,
    })
  } else {
    defaultBaseFolder = baseFolder
  }

  return function localStoreFactory(
    user: Credential,
    client: Socket,
    { resolveFoldername, resolveFilename }: StoreOptions = {}
  ) {
    let currentFolder: AbsolutePath = "/"

    const { basefolder: baseFolder = defaultBaseFolder } = user
    if (baseFolder != defaultBaseFolder && !existsSync(baseFolder)) {
      throw Object.assign(Error(`User's base folder must exist`), {
        code: Errors.ENOTDIR,
      })
    }

    const absJoin = (pathname: RelativePath): AbsolutePath =>
        path.isAbsolute(pathname ?? "")
          ? (path.join(baseFolder, pathname) as AbsolutePath)
          : (path.join(
              baseFolder,
              currentFolder,
              pathname ?? ""
            ) as AbsolutePath),
      resolveFolder = (folder: RelativePath): Promise<AbsolutePath> =>
        new Promise((resolve) => {
          let pathname = absJoin(folder)
          pathname = resolveFoldername?.(pathname) ?? pathname
          if (!pathname.startsWith(baseFolder)) {
            resolve(baseFolder) // no jailbreak!
          }
          resolve(pathname)
        }),
      resolveFile = (filename: RelativePath): Promise<AbsolutePath> =>
        new Promise((resolve, reject) => {
          let pathname = absJoin(filename)
          pathname = resolveFilename?.(pathname) ?? pathname
          if (!pathname.startsWith(baseFolder)) {
            reject() // no jailbreak!
          }
          resolve(pathname)
        }),
      folderExists = (folder: RelativePath): Promise<void> =>
        fs.stat(folder).then((fstat) => {
          if (!fstat.isDirectory()) {
            throw Object.assign(new Error("not directory"), {
              code: Errors.ENOTDIR,
            })
          }
        }),
      fileExists = (file: RelativePath): Promise<void> =>
        fs.stat(file).then((fstat) => {
          if (!fstat.isFile()) {
            throw Object.assign(new Error("not file"), {
              code: Errors.ENOTFILE,
            })
          }
        })

    return {
      getFolder(): AbsolutePath {
        return currentFolder
      },

      setFolder(folder: RelativePath) {
        return resolveFolder(folder).then((folder) =>
          folderExists(folder).then(
            () => (currentFolder = "/" + path.relative(baseFolder, folder) as AbsolutePath)
          )
        )
      },

      folderDelete(folder: RelativePath) {
        // advance existence check is inconclusive, should skip & check error condition later
        // should not allow removing any path containing currentFolder?
        return resolveFolder(folder).then((folder) =>
          folderExists(folder).then(() =>
            fs.rm(folder, {
              force: true,
              recursive: true,
            })
          )
        )
      },

      folderCreate(folder: RelativePath) {
        // advance existence check is inconclusive, should skip & check error condition later
        return resolveFolder(folder).then((folder) =>
          folderExists(folder).then(
            () => {
              throw Object.assign(Error(folder), {
                code: Errors.EEXIST,
              })
            },
            () =>
              fs
                .mkdir(folder, {
                  recursive: true,
                })
                .then((folder) => {
                  if (!folder) {
                    throw Object.assign(Error(folder), {
                      code: Errors.EEXIST,
                    })
                  }
                })
          )
        )
      },

      folderList(folder: RelativePath) {
        return resolveFolder(folder).then((folder) =>
          fs
            .readdir(folder, {
              withFileTypes: true,
            })
            .then((dirents) =>
              Promise.all(
                dirents
                  .filter((dirent) => dirent.isDirectory() || dirent.isFile())
                  .map(({ name }) =>
                    fs
                      .stat(path.join(folder, name))
                      .then((fstat) => Object.assign(fstat, { name }))
                  )
              )
            )
        )
      },

      fileDelete(file: RelativePath) {
        return resolveFile(file).then((file) => fs.unlink(file))
      },

      fileStats(file: RelativePath) {
        return resolveFile(file)
          .then((file) => fs.stat(file))
          .then((fstat) => Object.assign(fstat, { name: file }))
      },

      fileRetrieve(file: RelativePath, seek?: number) {
        return resolveFile(file).then((file) =>
          createReadStream(file, {
            start: seek,
            autoClose: true,
            emitClose: true,
            // Use highWaterMark that might hold the whole file in process memory
            // -mitigate chance of corruption due to overwriting file on disk between chunked reads
            // -actual memory consumption determined by file size and difference of read and write speeds
            highWaterMark:
              parseInt(process.env["RETRIEVE_FILE_BUFFER"]) || 100 << 20, // 100MB
          })
        )
      },

      fileStore(file: RelativePath, allowReplace: boolean, seek = 0) {
        const flags = (() => {
          if (seek) {
            if (!allowReplace) {
              return "wx+"
            }
            return "w+"
          } else if (!allowReplace) {
            return "wx"
          }
          return "w"
        })()
        return resolveFile(file).then((file) =>
          createWriteStream(file, {
            flags,
            start: seek,
            autoClose: true,
            emitClose: true,
          })
        )
      },

      fileRename(fromFile: RelativePath) {
        // advance existence check is inconclusive, should skip & check error condition later
        return resolveFile(fromFile).then((fromFile) =>
          fileExists(fromFile).then(async () => {
            return Object.assign(
              function fileRenameTo(toFile: RelativePath) {
                return resolveFile(toFile).then((toFile) =>
                  fileExists(toFile).then(
                    () => {
                      // what if allowed to replace/overwrite?
                      throw Object.assign(Error(toFile), {
                        code: Errors.EEXIST,
                      })
                    },
                    () => fs.rename(fromFile, toFile)
                  )
                )
              },
              { fromFile }
            )
          })
        )
      },

      fileSetTimes(file: RelativePath, mtime: Date, atime: Date) {
        return resolveFile(file).then((file) =>
          fs.utimes(file, atime ?? mtime, mtime)
        )
      },
    }
  }
}
