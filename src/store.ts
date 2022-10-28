import {
  join as joinPath,
  parse as parsePath,
  relative as relativePath,
  resolve as resolvePath,
} from "node:path"
import { createReadStream, createWriteStream, statSync } from "node:fs"
import fs from "node:fs/promises"
import type { Stats as FsStats } from "node:fs"
import type { Socket } from "node:net"
import type { Readable, Writable } from "node:stream"

import type { Credential } from "./auth.js"

// TODO: PathSegment excludes url & directory separators
export type PathSegment = string
// TODO: RelativePath may have any number of path segments
//  (Typescript does not support recursive type-defintion)
// export type RelativePath = PathSegment | `${PathSegment}/${RelativePath}`
export type RelativePath = PathSegment | `${PathSegment}/${PathSegment}`
export type AbsolutePath = `/${RelativePath}`
export type Path = AbsolutePath | RelativePath

// TODO: need more type assertions
declare module "path" {
  interface PlatformPath {
    isAbsolute(p: string): p is AbsolutePath // extends boolean return value
    join(arg: AbsolutePath, ...args: string[]): AbsolutePath
    resolve(...pathSegments: string[]): AbsolutePath
  }
}

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
  fileRename(fromFile: Path): Promise<
    ((toFile: Path, allowOverwrite: boolean) => Promise<void>) & {
      fromFile: Path
    }
  >
  fileSetAttributes(
    file: Path,
    attributes: Record<string, unknown>
  ): Promise<void>
}

export type LocalStoreOptions = {
  basefolder: string
  resolveFoldername?: (x: Path) => typeof x
  resolveFilename?: (x: Path) => typeof x
}

export type StoreFactory = (
  client: Socket,
  user: Credential,
  options?: LocalStoreOptions
) => Store

export default function localStoreFactory(
  client: Socket,
  user: Credential,
  { basefolder, resolveFoldername, resolveFilename }: LocalStoreOptions
): Store {
  const rootFolder = resolvePath(
    basefolder,
    user.basefolder ?? ""
  ) as AbsolutePath
  if (user.basefolder) {
    if (!statSync(rootFolder)?.isDirectory()) {
      throw Object.assign(Error(`User's base folder must exist`), {
        code: Errors.ENOTDIR,
        value: rootFolder,
      })
    }
  }

  let currentFolder: AbsolutePath = "/"

  const resolveFolder = (folder: Path = ""): Promise<AbsolutePath> =>
      new Promise((resolve) => {
        folder = joinPath(
          rootFolder,
          resolvePath(currentFolder, String(folder))
        )
        folder = resolveFoldername?.(folder) ?? folder
        if (!folder.startsWith(rootFolder)) {
          resolve(rootFolder) // no jailbreak!
        }

        resolve(folder as AbsolutePath)
      }),
    resolveFile = (file: Path = ""): Promise<AbsolutePath> =>
      new Promise((resolve, reject) => {
        file = joinPath(rootFolder, resolvePath(currentFolder, String(file)))
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
        fs.stat(folder).then((fstat) => {
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

    folderList(path: Path) {
      return resolveFolder(path).then((path) =>
        fs
          .readdir(path, {
            withFileTypes: true,
          })
          .then(
            (dirents) =>
              Promise.all(
                dirents
                  .filter((dirent) => dirent.isDirectory() || dirent.isFile())
                  .map(({ name }) =>
                    fs
                      .stat(joinPath(path, name))
                      .then((fstat) => Object.assign(fstat, { name }))
                  )
              ),
            () =>
              fs.stat(path).then((fstat) => {
                const { base: name } = parsePath(path)
                return [Object.assign(fstat, { name })]
              })
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
      const isFile = (file: Path): Promise<void> =>
        fs.stat(file).then((fstat) => {
          if (!fstat.isFile()) {
            throw Object.assign(new Error("not file"), {
              code: Errors.ENOTFILE,
            })
          }
        })

      return resolveFile(fromFile).then((fromFile) =>
        isFile(fromFile).then(async () => {
          return Object.assign(
            function fileRenameTo(toFile: Path, allowOverwrite: boolean) {
              return resolveFile(toFile).then((toFile) =>
                isFile(toFile).then(
                  () => {
                    if (allowOverwrite) {
                      return fs.rename(fromFile, toFile)
                    }

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

    fileSetAttributes(
      file: Path,
      attributes: { atime?: Date; mtime?: Date } & Record<string, unknown>
    ) {
      return resolveFile(file).then((file) => {
        const { atime, mtime } = attributes
        if (mtime || atime) {
          return fs.utimes(file, atime ?? new Date(), mtime)
        }
      })
    },
  }
}
