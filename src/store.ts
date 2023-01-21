import {
  basename,
  dirname,
  join as joinPath,
  parse as parsePath,
  relative as relativePath,
  resolve as resolvePath,
} from "node:path"
import {
  createReadStream,
  createWriteStream,
  mkdtempSync,
  rmSync,
  statSync,
} from "node:fs"
import fs from "node:fs/promises"
import type { Stats as FsStats } from "node:fs"
import type { Socket } from "node:net"
import { PassThrough, Readable, Writable } from "node:stream"

import type { Credential } from "./auth.js"

// TODO: PathSegment excludes url & directory separators
export type PathSegment = string
// TODO: RelativePath may have any number of path segments
//  (Typescript does not support circular reference)
// export type RelativePath = PathSegment | `${PathSegment}/${RelativePath}`
export type RelativePath = PathSegment | `${PathSegment}/${PathSegment}`
export type AbsolutePath = `/${RelativePath}`
export type Path = AbsolutePath | RelativePath

declare module "path" {
  interface PlatformPath {
    isAbsolute(p: string): p is AbsolutePath // extends boolean return value
    join(arg: AbsolutePath, ...args: string[]): AbsolutePath
    resolve(...pathSegments: string[]): AbsolutePath
    dirname(arg: AbsolutePath): AbsolutePath
  }
}

export type Stats = Partial<FsStats> & { name: string }

export enum Errors {
  EEXIST = "EEXIST",
  ENOENT = "ENOENT",
  ENOTDIR = "ENOTDIR",
  ENOTFILE = "ENOTFILE",
  EPERM = "EPERM",
}

// FTP protocol assumes storage has a tree structure
//  PWD / CWD indicate a state of traversing the tree, i.e. "context"
//  file and folder manipulating commands require context
export interface Store {
  // control PWD state, implicit in other accessors/operations
  readonly folder: AbsolutePath
  setFolder(folder: Path): Promise<AbsolutePath>

  // operations on folders/buckets/nodes, arg is relative to PWD
  folderDelete(folder: Path): Promise<void>
  folderCreate(folder: Path): Promise<void>
  folderList(folder?: Path): Promise<Stats[]>

  // operations on files/objects/leaves, arg is relative to PWD
  fileDelete(file: Path): Promise<void>
  fileStats(file: Path): Promise<Stats>
  fileRetrieve(file: Path, seek?: number): Promise<Readable>
  fileStore(file: Path, seek?: number): Promise<Writable>
  fileRename(fromFile: Path): Promise<
    ((toFile: Path) => Promise<void>) & {
      fromFile: AbsolutePath
    }
  >
  fileSetAttributes(
    file: Path,
    attributes: Record<string, unknown>
  ): Promise<[FsStats, FsStats]>
}

export type LocalStoreOptions = {
  resolveFoldername?: (x: Path) => typeof x
  resolveFilename?: (x: Path) => typeof x
}

export type StoreFactory = (
  client: Socket,
  user: Credential,
  options?: LocalStoreOptions
) => Store

// filesystem access is performed by server's effective user
// only minimal user-capability authorization are enforced:
//  NOT conditional on file / folder permissions or attributes
export default ({ basefolder }: { basefolder: AbsolutePath }) =>
  function localStoreFactory(
    client: Socket,
    user: Credential,
    { resolveFoldername, resolveFilename }: LocalStoreOptions = {}
  ): Store {
    if (user.basefolder) {
      // user.basefolder relative to basefolder
      basefolder = validateBaseFolder(resolvePath(basefolder, user.basefolder))
    }

    const noPermission = () =>
        Promise.reject(
          Object.assign(Error("unauthorized"), { code: Errors.EPERM })
        ),
      notFolder = (path: AbsolutePath) =>
        Promise.reject(
          Object.assign(Error("not folder"), { path, code: Errors.ENOTDIR })
        ),
      notFile = (path: AbsolutePath) =>
        Promise.reject(
          Object.assign(Error("not file"), { path, code: Errors.ENOTFILE })
        ),
      fileExists = () =>
        Promise.reject(
          Object.assign(Error("file exists"), { code: Errors.EEXIST })
        )

    let currentFolder: AbsolutePath = "/"

    function resolveFolder(folder: Path = ""): Promise<AbsolutePath> {
      return new Promise((resolve) => {
        folder = joinPath(
          String(basefolder),
          resolvePath(currentFolder, String(folder))
        )
        folder = resolveFoldername?.(folder) ?? folder
        if (!folder.startsWith(basefolder)) {
          resolve(basefolder) // no jailbreak!
        }

        resolve(folder as AbsolutePath)
      })
    }

    function resolveFile(file: Path): Promise<AbsolutePath> {
      return new Promise((resolve, reject) => {
        file = joinPath(
          String(basefolder),
          resolvePath(currentFolder, String(file))
        )
        file = resolveFilename?.(file) ?? file
        if (!file.startsWith(basefolder)) {
          reject() // no jailbreak!
        }

        resolve(file as AbsolutePath)
      })
    }

    function isFolder(file: AbsolutePath, required?: true): Promise<FsStats>
    function isFolder(
      file: AbsolutePath,
      required = false
    ): Promise<FsStats | false> {
      return fs.stat(file).then(
        (fstat) => (fstat.isDirectory() ? fstat : notFolder(file)),
        (error) =>
          error.code === "ENOENT"
            ? required && notFolder(file)
            : Promise.reject(error)
      )
    }

    function isFile(file: AbsolutePath, required?: true): Promise<FsStats>
    function isFile(
      file: AbsolutePath,
      required = false
    ): Promise<FsStats | false> {
      return fs.stat(file).then(
        (fstat) => (fstat.isFile() ? fstat : notFile(file)),
        (error) =>
          error.code === "ENOENT"
            ? required && notFile(file)
            : Promise.reject(error)
      )
    }

    return {
      get folder(): AbsolutePath {
        return currentFolder
      },

      setFolder(folder: Path) {
        return resolveFolder(folder).then((folder) =>
          isFolder(folder, true).then(
            () =>
              (currentFolder = joinPath(
                "/",
                relativePath(String(basefolder), folder)
              ) as AbsolutePath)
          )
        )
      },

      folderDelete(folder: Path) {
        // should not allow removing any path containing currentFolder?
        if (!user.allowFolderDelete) return noPermission()

        return resolveFolder(folder).then((folder) =>
          isFolder(folder, true).then(() => {
            if (folder === basefolder) return noPermission()

            return
            fs.rm(folder, {
              force: true,
              recursive: true,
            })
          })
        )
      },

      folderCreate(folder: Path) {
        if (!user.allowFolderCreate) return noPermission()

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
          isFolder(folder, true).then(() =>
            fs
              .readdir(folder, {
                withFileTypes: true,
              })
              .then(
                (dirents) =>
                  Promise.all(
                    dirents
                      .filter(
                        (dirent) => dirent.isDirectory() || dirent.isFile()
                      )
                      .map(({ name }) =>
                        fs
                          .stat(joinPath(folder, name))
                          .then((fstat) => Object.assign(fstat, { name }))
                      )
                  ),
                () =>
                  fs.stat(folder).then((fstat) => {
                    const { base: name } = parsePath(folder)
                    return [Object.assign(fstat, { name })]
                  })
              )
          )
        )
      },

      fileDelete(file: Path) {
        if (!user.allowFileDelete) return noPermission()

        return resolveFile(file).then((file) =>
          isFile(file, true).then(() => fs.unlink(file))
        )
      },

      fileStats(file: Path) {
        return resolveFile(file).then((file) =>
          fs.stat(file).then((fstat) => {
            if (!fstat.isFile()) return notFile(file)

            return Object.assign(fstat, { name: basename(file) })
          })
        )
      },

      fileRetrieve(file: Path, start = 0) {
        if (!user.allowFileRetrieve) return noPermission()

        return resolveFile(file).then((file) =>
          isFile(file, true).then(() =>
            createReadStream(file, {
              start,

              // Use highWaterMark that might buffer the whole file in process memory
              // -mitigate chance of corruption due to overwriting file on disk between chunked reads
              // -actual memory consumption determined by file size and difference of read and write speeds
              highWaterMark:
                parseInt(process.env["RETRIEVE_FILE_BUFFER"]) || 100 << 20, // 100MB
            })
          )
        )
      },

      fileStore(file: Path, seek = 0) {
        if (!user.allowFileOverwrite && !user.allowFileCreate)
          return noPermission()

        return resolveFile(file).then((file) =>
          isFile(file)
            .then((isFile) => {
              if (isFile) {
                if (!user.allowFileOverwrite) return fileExists()
              } else if (seek) return notFile(file)

              if (!user.allowFileCreate) return noPermission()

              return isFile
            })
            .then((overwrite) =>
              isFolder(dirname(file), true).then(() => {
                // write stream to a temp location and on success rename/replace named file, drop temp file on failure
                const tmpFile = `${file}+${new Date().getMilliseconds()}`,
                  innerStream = createWriteStream(tmpFile, {
                    flags: "wx",
                  }).on("open", function () {
                    function onCleanup() {
                      fs.unlink(tmpFile)
                    }

                    async function onFinish() {
                      this.off("close", onCleanup)

                      // rename temp file to final location
                      try {
                        if (overwrite) await fs.unlink(file)
                        await fs
                          .link(tmpFile, file)
                          .then(() => fs.unlink(tmpFile))
                        innerStream.emit("complete")
                      } catch (error) {
                        innerStream.emit("error", error)
                      }
                    }

                    this.once("close", onCleanup).once("finish", onFinish)
                  })

                // innerStream rename should be complete before wrapper's "finish" event is emitted
                const wrapper = new PassThrough({
                  // intercept end of input, end the inner stream & continue when temp file has been renamed
                  flush(next) {
                    innerStream.on("complete", next).on("error", next)
                    this.push(null)
                  },
                })

                Object.assign(wrapper, { overwrite })
                  .pipe(innerStream)

                if (seek) {
                  // copy offset bytes from source file
                  return new Promise((resolve) =>
                    createReadStream(file, { end: seek })
                      .on("end", () => resolve(wrapper))
                      .pipe(innerStream, { end: false })
                  )
                }

                return wrapper
              })
            )
        )
      },

      fileRename(fromFile: Path) {
        if (!user.allowFileRename) return noPermission()

        return resolveFile(fromFile).then((fromFile) =>
          isFile(fromFile, true).then(() =>
            Object.assign(
              function fileRenameTo(toFile: Path) {
                return resolveFile(toFile).then((toFile) =>
                  isFile(toFile)
                    .then((isFile) => {
                      if (isFile) {
                        if (!user.allowFileOverwrite) return fileExists()
                      }

                      if (!user.allowFileCreate) return noPermission()
                    })
                    .then(() =>
                      isFolder(dirname(toFile), true).then(() => {
                        fs.rename(fromFile, toFile)
                      })
                    )
                )
              },
              { fromFile }
            )
          )
        )
      },

      fileSetAttributes(
        file: Path,
        {
          mtime,
          atime,
        }: { mtime?: Date; atime?: Date } & Record<string, unknown>
      ) {
        if (!user.allowFileSetAttributes) return noPermission()

        if (mtime || atime) {
          return resolveFile(file).then((file) =>
            isFile(file, true).then((fstat) =>
              fs
                .utimes(file, atime ?? fstat.atime, mtime ?? fstat.mtime)
                .then(() => fs.stat(file).then((fstatNew) => [fstat, fstatNew]))
            )
          )
        }

        return Promise.reject()
      },
    }
  }

export function validateBaseFolder(
  folder: AbsolutePath | RelativePath
): AbsolutePath & { cleanup?: () => void } {
  if (!folder) {
    const folder = mkdtempSync(resolvePath("ftproot-")) as AbsolutePath
    return Object.assign(folder, {
      cleanup() {
        rmSync(folder.toString(), { force: true, recursive: true })
      },
    })
  }

  const absFolder = resolvePath(folder) as AbsolutePath, // resolve relative to process.cwd()
    folderStats = statSync(absFolder, { throwIfNoEntry: false })
  if (!folderStats) {
    throw Object.assign(Error(`Base folder must exist`), {
      code: Errors.ENOTDIR,
      value: absFolder,
    })
  }

  if (!folderStats.isDirectory()) {
    throw Object.assign(Error(`Base folder must be directory`), {
      code: Errors.ENOTDIR,
      value: absFolder,
    })
  }

  return absFolder
}
