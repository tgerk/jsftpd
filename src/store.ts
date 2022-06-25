import {
  join as joinPath,
  relative as relativePath,
  resolve as resolvePath,
} from "path"
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

// TODO: PathNode is a string with no directory separators
export type PathNode = string

// TODO: a string with optional directory separators, but not in first position
//  or recursively (illegal) `${RelativePath}/${PathNode}` | PathNode
export type RelativePath = string | PathNode

export type AbsolutePath = `/${RelativePath}`
export type Path = AbsolutePath | RelativePath
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
  // control PWD state, implicit in other accessors/operations
  getFolder(): AbsolutePath
  setFolder(folder: Path): Promise<AbsolutePath>

  // operations on folders/buckets/nodes, arg is relative to PWD
  folderDelete(folder: Path): Promise<void>
  folderCreate(folder: Path): Promise<void>
  folderList(folder?: Path): Promise<Stats[]>

  // operations on files/objects/leaves, arg is relative to PWD
  fileDelete(file: Path): Promise<void>
  fileStats(file: Path): Promise<Stats>
  fileRetrieve(file: Path, seek?: number): Promise<Readable>
  fileStore(file: Path, allowReplace: boolean, seek?: number): Promise<Writable>
  fileRename(
    fromFile: Path
  ): Promise<((toFile: Path) => Promise<void>) & { fromFile: Path }>
  fileSetTimes(file: Path, mtime: Date, atime?: Date): Promise<void>
}

export type StoreOptions = {
  resolveFoldername?: (x: Path) => typeof x
  resolveFilename?: (x: Path) => typeof x
}

export type StoreFactory = (
  user: Credential,
  client: Socket,
  options?: StoreOptions
) => Store

export default localStoreFactoryInit
export function localStoreFactoryInit(basefolder?: Path) {
  let cleanup: () => void
  if (basefolder) {
    if (!existsSync(basefolder)) {
      throw Object.assign(Error(`Base folder must exist`), {
        code: Errors.ENOTDIR,
        value: basefolder,
      })
    }
  } else {
    basefolder = resolvePath("__ftproot__") as AbsolutePath
    if (!existsSync(basefolder)) {
      mkdirSync(basefolder)
      cleanup = function () {
        rmSync(basefolder, { force: true, recursive: true })
      }
    }
  }

  return Object.assign(
    function localStoreFactory(
      user: Credential,
      client: Socket,
      options: StoreOptions = {}
    ): Store {
      const rootFolder = resolvePath(basefolder, user.basefolder ?? "") as AbsolutePath,
        { resolveFoldername, resolveFilename } = options
      if (user.basefolder) {
        if (!existsSync(rootFolder)) {
          throw Object.assign(Error(`User's base folder must exist`), {
            code: Errors.ENOTDIR,
            value: rootFolder,
          })
        }
      }

      let currentFolder: AbsolutePath = "/"

      const resolveFolder = (folder: Path = ""): Promise<AbsolutePath> =>
          new Promise((resolve) => {
            folder = joinPath(rootFolder, resolvePath(currentFolder, folder))
            folder = resolveFoldername?.(folder) ?? folder
            if (!folder.startsWith(rootFolder)) {
              resolve(rootFolder) // no jailbreak!
            }

            resolve(folder as AbsolutePath)
          }),
        resolveFile = (file: Path = ""): Promise<AbsolutePath> =>
          new Promise((resolve, reject) => {
            file = joinPath(rootFolder, resolvePath(currentFolder, file))
            file = resolveFilename?.(file) ?? file
            if (!file.startsWith(rootFolder)) {
              reject() // no jailbreak!
            }

            resolve(file as AbsolutePath)
          })

      return {
        getFolder(): AbsolutePath {
          return currentFolder
        },

        setFolder(folder: Path) {
          return resolveFolder(folder).then((folder) =>
            fs
              .stat(folder)
              .then((fstat) => {
                if (!fstat.isDirectory()) {
                  throw Object.assign(new Error("not directory"), {
                    code: Errors.ENOTDIR,
                  })
                }
                
                return (currentFolder = joinPath(
                  "/",
                  relativePath(rootFolder, folder)
                ) as AbsolutePath)
              })
          )
        },

        folderDelete(folder: Path) {
          // should not allow removing any path containing currentFolder?
          return resolveFolder(folder).then((folder) =>
            fs.rm(folder, {
              force: true,
              recursive: true,
            })
          )
        },

        folderCreate(folder: Path) {
          return resolveFolder(folder).then((folder) =>
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
        },

        folderList(folder: Path) {
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
                        .stat(joinPath(folder, name))
                        .then((fstat) => Object.assign(fstat, { name }))
                    )
                )
              )
          )
        },

        fileDelete(file: Path) {
          return resolveFile(file).then((file) => fs.unlink(file))
        },

        fileStats(file: Path) {
          return resolveFile(file)
            .then((file) => fs.stat(file))
            .then((fstat) => Object.assign(fstat, { name: file }))
        },

        fileRetrieve(file: Path, seek?: number) {
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

        fileStore(file: Path, allowReplace: boolean, seek = 0) {
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

        fileRename(fromFile: Path) {
          const fileExists = (file: Path): Promise<void> =>
          fs.stat(file).then((fstat) => {
            if (!fstat.isFile()) {
              throw Object.assign(new Error("not file"), {
                code: Errors.ENOTFILE,
              })
            }
          })

          // advance existence check is inconclusive, should skip & check error condition later
          return resolveFile(fromFile).then((fromFile) =>
            fileExists(fromFile).then(async () => {
              return Object.assign(
                function fileRenameTo(toFile: Path) {
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

        fileSetTimes(file: Path, mtime: Date, atime: Date) {
          return resolveFile(file).then((file) =>
            fs.utimes(file, atime ?? mtime, mtime)
          )
        },
      }
    },
    {
      basefolder,
      cleanup,
    }
  )
}
