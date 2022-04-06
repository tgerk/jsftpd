import path from "path"
import { Socket } from "net"
import { TLSSocket } from "tls"
import fs from "fs/promises"
import { existsSync, mkdirSync, rmSync, Stats as FStats } from "fs"
import { Readable, Writable } from "stream"

import { Credential } from "./auth"

export type Stats = FStats & { name: string }

export enum Errors {
  EEXIST = "EEXIST",
  ENOENT = "ENOENT",
  ENOTDIR = "ENOTDIR",
  ENOTFILE = "ENOTFILE",
}

const defaultBaseFolder = path.join(process.cwd(), "__ftproot__")

function baseFolder(baseFolder: string = defaultBaseFolder): string {
  return baseFolder
}

function baseFolderExists(baseFolder: string = defaultBaseFolder): boolean {
  if (!existsSync(baseFolder)) {
    if (baseFolder !== defaultBaseFolder) {
      return false
    }

    mkdirSync(defaultBaseFolder) // may throw
  }

  return true
}

function baseFolderCleanup(baseFolder: string = defaultBaseFolder): void {
  if (baseFolder === defaultBaseFolder) {
    rmSync(defaultBaseFolder, { force: true, recursive: true })
  }
}

// FTP protocol assumes storage has a tree structure
//  PWD / CWD indicate a state of traversing the tree
//  file and folder manipulating commands implicitly refer to PWD state
export interface Store {
  // control PWD state, "current node" implicit in other manipulations
  getFolder(): string
  setFolder(folder: string): Promise<string>

  // operations on folders/buckets/nodes, arg is relative to PWD
  folderDelete(folder: string): Promise<void>
  folderCreate(folder: string): Promise<void>
  folderList(folder?: string): Promise<Stats[]>

  // operations on files/objects/leaves, arg is relative to PWD
  fileDelete(file: string): Promise<void>
  fileSize(file: string): Promise<number>
  fileSetTimes(file: string, mtime: number): Promise<void>
  fileRename(
    fromFile: string
  ): Promise<((toFile: string) => Promise<void>) & { fromFile: string }>
  fileStore(
    file: string,
    allowReplace?: boolean,
    seek?: number
  ): Promise<Writable>
  fileRetrieve(file: string, seek?: number): Promise<Readable>
}

type StoreOptions = {
  translateFilename?: (x: string) => string
}
export type StoreFactory = ((
  user: Credential,
  client: Socket | TLSSocket,
  tools?: StoreOptions
) => Store) & {
  // control context
  baseFolder(baseFolder?: string): string
  baseFolderExists(baseFolder?: string): boolean
  baseFolderCleanup(baseFolder?: string): void
}

function localStoreFactory(
  { basefolder: baseFolder = defaultBaseFolder }: Credential,
  _client: Socket | TLSSocket,
  { translateFilename }: StoreOptions = {}
) {
  if (!baseFolderExists(baseFolder)) {
    throw Object.assign(Error(`base folder "${baseFolder}" does not exist`), {
      code: Errors.ENOTDIR,
    })
  }

  let currentFolder = "/"

  function resolveFolder(folder: string): Promise<string> {
    // result relative to base folder
    folder =
      folder.charAt(0) === "/"
        ? path.join(baseFolder, folder)
        : path.join(baseFolder, currentFolder, folder)
    return new Promise((resolve) => {
      if (folder.startsWith(baseFolder)) {
        resolve("/" + path.relative(baseFolder, folder))
      }
      resolve("/") // no jailbreak!
    })
  }

  function resolveFile(file: string): Promise<string> {
    // result relative to current folder
    file =
      file.charAt(0) === "/"
        ? path.join(baseFolder, file)
        : path.join(baseFolder, currentFolder, file)
    file = translateFilename?.(file) ?? file
    return new Promise((resolve, reject) => {
      if (file.startsWith(baseFolder)) {
        file = path.relative(path.join(baseFolder, currentFolder), file)
        resolve(file)
      }
      reject() // no jailbreak!
    })
  }

  function folderExists(folder: string): Promise<boolean> {
    // advance status check is inconclusive, check error condition later
    return fs.stat(path.join(baseFolder, folder)).then((fstat) => {
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
    return fs.stat(path.join(baseFolder, currentFolder, file)).then((fstat) => {
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
        folderExists(folder).then(() => (currentFolder = folder))
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
          fs.rm(path.join(baseFolder, folder), {
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
            throw Object.assign(Error(path.join(baseFolder, folder)), {
              code: Errors.EEXIST,
            })
          },
          () =>
            fs
              .mkdir(path.join(baseFolder, folder), {
                recursive: true,
              })
              .then((folder) => {
                if (!folder) {
                  throw Object.assign(Error(path.join(baseFolder, folder)), {
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
          .readdir(path.join(baseFolder, folder), {
            withFileTypes: true,
          })
          .then((dirents) =>
            Promise.all(
              dirents
                .filter((dirent) => dirent.isDirectory() || dirent.isFile())
                .map(({ name }) =>
                  fs
                    .stat(path.join(baseFolder, folder, name))
                    .then((fstat) => Object.assign(fstat, { name }))
                )
            )
          )
      )
    },

    fileSize(file: string): Promise<number> {
      return resolveFile(file).then((file) =>
        fs
          .stat(path.join(baseFolder, currentFolder, file))
          .then((fstat) => fstat.size)
      )
    },

    fileSetTimes(file: string, mtime: number): Promise<void> {
      return resolveFile(file).then((file) =>
        fs.utimes(path.join(baseFolder, currentFolder, file), mtime, mtime)
      )
    },

    fileRename(fromFile: string) {
      return resolveFile(fromFile).then((file) =>
        fileExists(file).then(async () => {
          const fromFile = await resolveFolder(file) // filename relative to base folder
          return Object.assign(
            function fileRenameTo(toFile: string) {
              return resolveFile(toFile).then((toFile) =>
                // TODO: try to rename without checking, let it raise error
                fileExists(toFile).then(
                  () => {
                    // what if allowed to replace?
                    throw Object.assign(
                      Error(path.join(baseFolder, currentFolder, toFile)),
                      {
                        code: Errors.EEXIST,
                      }
                    )
                  },
                  () =>
                    fs.rename(
                      path.join(baseFolder, fromFile), // NOTE:  fromFile is relative to baseFolder, not currentFolder
                      path.join(baseFolder, currentFolder, toFile)
                    )
                )
              )
            },
            { fromFile }
          )
        })
      )
    },

    fileDelete(file: string): Promise<void> {
      return resolveFile(file).then((file) =>
        fs.unlink(path.join(baseFolder, currentFolder, file))
      )
    },

    fileStore(file: string, allowReplace: boolean, seek?: number) {
      // try to open the file without checking, let it raise error?
      return resolveFile(file).then((file) =>
        fileExists(file)
          .then(() => {
            if (allowReplace) {
              throw "allow file replacement"
            }
          })
          .then(
            () => {
              throw Object.assign(
                new Error(path.join(baseFolder, currentFolder, file)),
                {
                  code: Errors.EEXIST,
                }
              )
            },
            () =>
              // file does not exist or replacement is allowed, assuming allowCreate
              fs
                .open(
                  path.join(baseFolder, currentFolder, file),
                  seek > 0 ? "a+" : "w"
                )
                .then((fd) =>
                  fd.createWriteStream({
                    start: seek,
                    autoClose: true,
                    emitClose: true,
                  })
                )
          )
      )
    },

    fileRetrieve(file: string, seek?: number): Promise<Readable> {
      return resolveFile(file).then((file) =>
        // try to open the file without checking, let it raise error?
        fileExists(file).then(() =>
          fs.open(path.join(baseFolder, currentFolder, file), "r").then((fd) =>
            fd.createReadStream({
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
        )
      )
    },
  }
}

export default Object.assign(localStoreFactory, {
  baseFolder,
  baseFolderExists,
  baseFolderCleanup,
})
