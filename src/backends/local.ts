import util from "util"
import path from "path"
import fs from "fs/promises"

import {
  FolderListFormat,
  getDateForLIST,
  getDateForMLSD,
  UserCredential,
} from "../jsftpd"

export default function ({
  basefolder: baseFolder,
  username = "nobody",
  filenameTransform,
}: {
  username?: string
} & UserCredential) {
  baseFolder = path.join(baseFolder)

  function resolveFolder(folder: string): Promise<string> {
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
    file =
      file.charAt(0) === "/"
        ? path.join(baseFolder, file)
        : path.join(baseFolder, currentFolder, file)
    return new Promise((resolve, reject) => {
      if (file.startsWith(baseFolder)) {
        file = path.relative(path.join(baseFolder, currentFolder), file)
        file = filenameTransform?.in?.(file) ?? file
        resolve(file)
      }
      reject() // no jailbreak!
    })
  }

  let currentFolder = "/"
  function setFolder(folder: string) {
    return folderExists(folder).then((isDirectory) => {
      if (isDirectory) {
        // check user access?
        currentFolder = folder
        return folder
      } else {
        throw Object.assign(new Error("not directory"), { code: "ENOTDIR" })
      }
    })
  }

  function getFolder() {
    return currentFolder
  }

  // beware of a possible race conditions--when possible avoid status check in advance, respond to the specific rejection later
  function folderExists(folder: string) {
    return fs.stat(path.join(baseFolder, folder)).then(
      (fstat) => fstat.isDirectory(),
      () => false
    )
  }

  function folderDelete(folder: string) {
    return fs.rm(path.join(baseFolder, folder), {
      force: true,
      recursive: true,
    })
  }

  function folderCreate(folder: string) {
    return fs
      .mkdir(path.join(baseFolder, folder), {
        recursive: true,
      })
      .then((folder) => {
        if (!folder) throw Object.assign(Error(""), { code: "EEXIST" })
      })
  }

  function folderList(format: FolderListFormat, folder = "") {
    return fs
      .readdir(path.join(baseFolder, currentFolder, folder), {
        withFileTypes: true,
      })
      .then((dirents) =>
        // skip other node types: sym-links, pipes, etc.
        dirents.filter((dirent) => dirent.isDirectory() || dirent.isFile())
      )
      .then((dirents) =>
        Promise.all(
          dirents.map(({ name }) =>
            fs.stat(path.join(baseFolder, currentFolder, name))
          )
        ).then((stats) =>
          dirents.map(({ name }, i) => {
            name = filenameTransform?.out?.(name) ?? name
            const fstat = stats[i]
            switch (format) {
              case "NLST":
                return name
              case "MLSD":
                return util.format(
                  "type=%s;modify=%s;%s %s",
                  fstat.isDirectory() ? "dir" : "file",
                  getDateForMLSD(fstat.mtime),
                  fstat.isDirectory()
                    ? ""
                    : "size=" + fstat.size.toString() + ";",
                  name
                )
              case "LIST":
              default:
                return util.format(
                  "%s 1 %s %s %s %s %s", // showing link-count = 1
                  fstat.isDirectory() ? "dr--r--r--" : "-r--r--r--",
                  username,
                  username, // don't expose uid, gid
                  String(fstat.isDirectory() ? "0" : fstat.size).padStart(
                    14,
                    " "
                  ),
                  getDateForLIST(fstat.mtime),
                  name
                )
            }
          })
        )
      )
  }

  // beware of a possible race conditions--when possible avoid status check in advance, respond to the specific rejection later
  function fileExists(file: string) {
    return fs.stat(path.join(baseFolder, currentFolder, file)).then(
      (fstat) => fstat.isFile(),
      () => false
    )
  }

  function fileSize(file: string) {
    return fs
      .stat(path.join(baseFolder, currentFolder, file))
      .then((fstat) => fstat.size)
  }

  function fileDelete(file: string) {
    return fs.unlink(path.join(baseFolder, currentFolder, file))
  }

  function fileRetrieve(file: string, restOffset: number) {
    return fs.open(path.join(baseFolder, currentFolder, file), "r").then((fd) =>
      fd.createReadStream({
        start: restOffset,
        autoClose: true,
        emitClose: true,
      })
    )
  }

  function fileStore(
    file: string,
    restOffset: number,
    encoding?: BufferEncoding
  ) {
    return fs
      .open(
        path.join(baseFolder, currentFolder, file),
        restOffset > 0 ? "a+" : "w"
      )
      .then((fd) =>
        fd.createWriteStream({
          start: restOffset,
          autoClose: true,
          emitClose: true,
          encoding,
        })
      )
  }

  function fileRename(fromFile: string, toFile: string) {
    return fs.rename(
      path.join(baseFolder, fromFile), // NOTE:  fromFile is relative to baseFolder, not currentFolder
      path.join(baseFolder, currentFolder, toFile)
    )
  }

  function fileSetTimes(file: string, mtime: number) {
    return fs.utimes(path.join(baseFolder, currentFolder, file), mtime, mtime)
  }

  return {
    resolveFolder,
    resolveFile,

    setFolder,
    getFolder,

    folderExists,
    folderDelete,
    folderCreate,
    folderList,

    fileExists,
    fileSize,
    fileDelete,
    fileRetrieve,
    fileStore,
    fileRename,
    fileSetTimes,
  }
}
