import path from "path"
import fs from "fs/promises"
import { existsSync, mkdirSync, rmSync, Stats } from "fs"

import { UserCredential } from "../jsftpd"

export type FStat = { fname: string } & Stats

const defaultBaseFolder = path.join(process.cwd(), "__ftproot__")

export default Object.assign(
  function ({
    basefolder: baseFolder = defaultBaseFolder,
  }: UserCredential & {
    username?: string
  }) {
    baseFolder = path.join(baseFolder)
    
    let currentFolder = "/"

    // beware of a possible race conditions--advance status check is ambiguous, expect error condition later
    function folderExists(folder = "") {
      return fs.stat(path.join(baseFolder, folder)).then(
        (fstat) => fstat.isDirectory(),
        () => false
      )
    }

    return {
      setFolder(folder: string) {
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

      getFolder() {
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

      folderDelete(folder: string) {
        return fs.rm(path.join(baseFolder, folder), {
          force: true,
          recursive: true,
        })
      },

      folderCreate(folder: string) {
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

      folderList(folder = "") {
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

      // beware of a possible race conditions--advance status check is ambiguous, expect error condition later
      fileExists(file: string) {
        return fs.stat(path.join(baseFolder, currentFolder, file)).then(
          (fstat) => fstat.isFile(),
          () => false
        )
      },

      fileSize(file: string) {
        return fs
          .stat(path.join(baseFolder, currentFolder, file))
          .then((fstat) => fstat.size)
      },

      fileDelete(file: string) {
        return fs.unlink(path.join(baseFolder, currentFolder, file))
      },

      fileRetrieve(file: string, seek: number) {
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

      fileStore(file: string, seek: number) {
        return fs
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
      },

      fileRename(fromFile: string, toFile: string) {
        return fs.rename(
          path.join(baseFolder, fromFile), // NOTE:  fromFile is relative to baseFolder, not currentFolder
          path.join(baseFolder, currentFolder, toFile)
        )
      },

      fileSetTimes(file: string, mtime: number) {
        return fs.utimes(
          path.join(baseFolder, currentFolder, file),
          mtime,
          mtime
        )
      },
    }
  },
  {
    defaultBaseFolder,

    baseFolderExists(baseFolder: string = defaultBaseFolder) {
      if (!existsSync(baseFolder)) {
        if (baseFolder !== defaultBaseFolder) {
          return false
        }

        mkdirSync(defaultBaseFolder) // may throw
      }

      return true
    },

    baseFolderCleanup(baseFolder: string = defaultBaseFolder) {
      if (baseFolder === defaultBaseFolder) {
        rmSync(defaultBaseFolder, { force: true, recursive: true })
      }
    },
  }
)
