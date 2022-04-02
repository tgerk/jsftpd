import path from "path"
import { Socket } from "net"
import { TLSSocket } from "tls"
import fs from "fs/promises"
import { existsSync, mkdirSync, rmSync, Stats } from "fs"
import { Readable, Writable } from "stream"

import { Credential } from "./auth"

export type FStats = Stats & { fname: string }

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

export interface StoreHandlers {
  setFolder(folder: string): Promise<string>
  getFolder(): string
  resolveFolder(folder: string): Promise<string>
  folderExists: (folder?: string) => Promise<boolean>
  folderDelete(folder: string): Promise<void>
  folderCreate(folder: string): Promise<void>
  folderList(folder?: string): Promise<FStats[]>
  resolveFile(file: string): Promise<string>
  fileExists(file: string): Promise<boolean>
  fileSize(file: string): Promise<number>
  fileDelete(file: string): Promise<void>
  fileRetrieve(file: string, seek?: number): Promise<Readable>
  fileStore(file: string, seek?: number): Promise<Writable>
  fileRename(fromFile: string, toFile: string): Promise<void>
  fileSetTimes(file: string, mtime: number): Promise<void>
}

export type StoreHandlersFactory = ((
  user: Credential,
  client: Socket | TLSSocket
) => StoreHandlers) & {
  baseFolder(folder: string): string
  baseFolderExists(folder: string): boolean
  baseFolderCleanup(folder: string): void
}

function localStoreFactory(
  { basefolder: baseFolder = defaultBaseFolder }: Credential,
  _client: Socket | TLSSocket
): StoreHandlers {
  baseFolder = path.join(baseFolder)

  let currentFolder = "/"

  // advance status check is inconclusive, check error condition later
  function folderExists(folder = ""): Promise<boolean> {
    return fs.stat(path.join(baseFolder, folder)).then(
      (fstat) => fstat.isDirectory(),
      () => false
    )
  }

  return {
    setFolder(folder: string): Promise<string> {
      return folderExists(folder).then((isDirectory) => {
        if (isDirectory) {
          // check user access?
          currentFolder = folder
          return folder
        } else {
          throw Object.assign(new Error("not directory"), { code: "ENOTDIR" })
        }
      })
    },

    getFolder(): string {
      return currentFolder
    },

    resolveFolder(folder: string): Promise<string> {
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
    },

    folderExists,

    folderDelete(folder: string): Promise<void> {
      return fs.rm(path.join(baseFolder, folder), {
        force: true,
        recursive: true,
      })
    },

    folderCreate(folder: string): Promise<void> {
      return fs
        .mkdir(path.join(baseFolder, folder), {
          recursive: true,
        })
        .then((folder) => {
          if (!folder) {
            throw Object.assign(Error(path.join(baseFolder, folder)), {
              code: "EEXIST",
            })
          }
        })
    },

    folderList(folder = ""): Promise<FStats[]> {
      return fs
        .readdir(path.join(baseFolder, currentFolder, folder), {
          withFileTypes: true,
        })
        .then((dirents) =>
          Promise.all(
            dirents
              .filter((dirent) => dirent.isDirectory() || dirent.isFile())
              .map(({ name }) =>
                fs
                  .stat(path.join(baseFolder, currentFolder, folder, name))
                  .then((fstat) => Object.assign(fstat, { fname: name }))
              )
          )
        )
    },

    resolveFile(file: string): Promise<string> {
      file =
        file.charAt(0) === "/"
          ? path.join(baseFolder, file)
          : path.join(baseFolder, currentFolder, file)
      return new Promise((resolve, reject) => {
        if (file.startsWith(baseFolder)) {
          file = path.relative(path.join(baseFolder, currentFolder), file)
          resolve(file)
        }
        reject() // no jailbreak!
      })
    },

    // advance status check is inconclusive, check error condition later
    fileExists(file: string): Promise<boolean> {
      return fs.stat(path.join(baseFolder, currentFolder, file)).then(
        (fstat) => fstat.isFile(),
        () => false
      )
    },

    fileSize(file: string): Promise<number> {
      return fs
        .stat(path.join(baseFolder, currentFolder, file))
        .then((fstat) => fstat.size)
    },

    fileDelete(file: string): Promise<void> {
      return fs.unlink(path.join(baseFolder, currentFolder, file))
    },

    fileRetrieve(file: string, seek?: number): Promise<Readable> {
      return fs
        .open(path.join(baseFolder, currentFolder, file), "r")
        .then((fd) =>
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
    },

    fileStore(file: string, seek?: number): Promise<Writable> {
      return fs
        .open(path.join(baseFolder, currentFolder, file), seek > 0 ? "a+" : "w")
        .then((fd) =>
          fd.createWriteStream({
            start: seek,
            autoClose: true,
            emitClose: true,
          })
        )
    },

    fileRename(fromFile: string, toFile: string): Promise<void> {
      return fs.rename(
        path.join(baseFolder, fromFile), // NOTE:  fromFile is relative to baseFolder, not currentFolder
        path.join(baseFolder, currentFolder, toFile)
      )
    },

    fileSetTimes(file: string, mtime: number): Promise<void> {
      return fs.utimes(path.join(baseFolder, currentFolder, file), mtime, mtime)
    },
  }
}

export default Object.assign(localStoreFactory, {
  baseFolder,
  baseFolderExists,
  baseFolderCleanup,
})
