import path from "path"
import { Socket } from "net"
import { TLSSocket } from "tls"
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
  getFolder(): string
  setFolder(folder: string): Promise<string>

  // operations on folders/buckets/nodes, arg is relative to PWD
  folderDelete(folder: string): Promise<void>
  folderCreate(folder: string): Promise<void>
  folderList(folder?: string): Promise<Stats[]>

  // operations on files/objects/leaves, arg is relative to PWD
  fileDelete(file: string): Promise<void>
  fileStats(file: string): Promise<Stats>
  fileRetrieve(file: string, seek?: number): Promise<Readable>
  fileStore(
    file: string,
    allowReplace: boolean,
    seek?: number
  ): Promise<Writable>
  fileRename(
    fromFile: string
  ): Promise<((toFile: string) => Promise<void>) & { fromFile: string }>
  fileSetTimes(file: string, mtime: Date, atime?: Date): Promise<void>
}

export type StoreOptions = {
  resolveFoldername?: (x: string) => string
  resolveFilename?: (x: string) => string
}

export type StoreFactory = (
  user: Credential,
  client: Socket | TLSSocket,
  options?: StoreOptions
) => Store

// module state
let defaultBaseFolder = path.join(process.cwd(), "__ftproot__"),
  cleanupBaseFolder: () => void

// export accessor and cleanup util
export function getBaseFolder() {
  return defaultBaseFolder
}

export function cleanup() {
  cleanupBaseFolder?.()
}

export default function localStoreFactoryInit(baseFolder: string) {
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
    client: Socket | TLSSocket,
    { resolveFoldername, resolveFilename }: StoreOptions = {}
  ) {
    let currentFolder = "/"

    const { basefolder: baseFolder = defaultBaseFolder } = user
    if (baseFolder != defaultBaseFolder && !existsSync(baseFolder)) {
      throw Object.assign(Error(`User's base folder must exist`), {
        code: Errors.ENOTDIR,
      })
    }

    function resolveFolder(folder: string): Promise<string> {
      folder =
        folder?.charAt(0) === "/"
          ? path.join(baseFolder, folder)
          : path.join(baseFolder, currentFolder, folder ?? "")
      folder = resolveFoldername?.(folder) ?? folder
      return new Promise((resolve) => {
        if (folder.startsWith(baseFolder)) {
          resolve(folder)
        }
        resolve(baseFolder) // no jailbreak!
      })
    }

    function resolveFile(filename: string): Promise<string> {
      filename = resolveFilename?.(filename) ?? filename
      const filepath =
        filename.charAt(0) === "/"
          ? path.join(baseFolder, filename)
          : path.join(baseFolder, currentFolder, filename ?? "")
      return new Promise((resolve, reject) => {
        if (filename && filepath.startsWith(baseFolder)) {
          resolve(filepath)
        }
        reject() // no jailbreak!
      })
    }

    function folderExists(folder: string): Promise<boolean> {
      // advance status check is inconclusive, check error condition later
      return fs.stat(folder).then((fstat) => {
        if (fstat.isDirectory()) {
          return true
        }

        throw Object.assign(new Error("not directory"), {
          code: Errors.ENOTDIR,
        })
      })
    }

    function fileExists(file: string): Promise<boolean> {
      // input checked relative to current folder
      // advance status check is inconclusive, check error condition later
      return fs.stat(file).then((fstat) => {
        if (fstat.isFile()) {
          return true
        }

        throw Object.assign(new Error("not file"), {
          code: Errors.ENOTFILE,
        })
      })
    }

    return {
      setFolder(folder: string): Promise<string> {
        return resolveFolder(folder).then((folder) =>
          folderExists(folder).then(
            () => (currentFolder = "/" + path.relative(baseFolder, folder))
          )
        )
      },

      getFolder(): string {
        return currentFolder
      },

      folderDelete(folder: string): Promise<void> {
        // should not allow removing any path containing currentFolder?
        // try to remove without checking existence, let it raise error?
        return resolveFolder(folder)
          .then((folder) => folderExists(folder))
          .then(() =>
            fs.rm(folder, {
              force: true,
              recursive: true,
            })
          )
      },

      folderCreate(folder: string): Promise<void> {
        return resolveFolder(folder).then((folder) =>
          // try to create without checking, let it raise error?
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

      folderList(folder: string): Promise<Stats[]> {
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

      fileDelete(file: string): Promise<void> {
        return resolveFile(file).then((file) => fs.unlink(file))
      },

      fileStats(file: string): Promise<Stats> {
        return resolveFile(file)
          .then((file) => fs.stat(file))
          .then((fstat) => Object.assign(fstat, { name: file }))
      },

      fileRetrieve(file: string, seek?: number): Promise<Readable> {
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

      fileStore(file: string, allowReplace: boolean, seek = 0) {
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

      fileRename(fromFile: string) {
        // TODO: try to rename without checking, let it raise error
        return resolveFile(fromFile).then((fromFile) =>
          fileExists(fromFile).then(async () => {
            return Object.assign(
              function fileRenameTo(toFile: string) {
                return resolveFile(toFile).then((toFile) =>
                  fileExists(toFile).then(
                    () => {
                      // but what if allowed to replace?
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

      fileSetTimes(file: string, mtime: Date, atime: Date): Promise<void> {
        return resolveFile(file).then((file) =>
          fs.utimes(file, atime ?? mtime, mtime)
        )
      },
    }
  }
}
