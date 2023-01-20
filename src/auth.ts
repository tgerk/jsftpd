import type { Socket } from "node:net"
import type { AbsolutePath, RelativePath } from "./store.js"

enum permissions {
  FileCreate = "FileCreate",
  FileRetrieve = "FileRetrieve",
  FileOverwrite = "FileOverwrite",
  FileDelete = "FileDelete",
  FileRename = "FileRename",
  FileSetAttributes = "FileSetAttributes",
  FolderDelete = "FolderDelete",
  FolderCreate = "FolderCreate",
  // access to set folder, folder listing, and file attributes are uncontrolled
}

type Permissions = {
  -readonly [k in keyof typeof permissions as `allow${k & string}`]: boolean
}

export type Credential = {
  username: string
  basefolder?: AbsolutePath | RelativePath | string
} & Permissions

type AnonymousPermissions = {
  -readonly [k in keyof typeof permissions as `allowAnonymous${k &
    string}`]?: boolean
}

type UserPermissions = {
  -readonly [k in keyof typeof permissions as `allowUser${k &
    string}`]?: boolean
}

type UserOptions = {
  username: string
  password?: string
  requireSecure?: boolean
  trustedClientAddr?: string | RegExp
  allowLoginWithoutPassword?: boolean

  basefolder?: AbsolutePath | RelativePath | string
} & UserPermissions

export type AuthOptions = {
  allowAnonymousLogin?: boolean
  requireAnonymousSecure?: boolean

  requireSecure?: boolean
  trustClientAddr?: boolean

  username?: string
  password?: string
  allowLoginWithoutPassword?: boolean
  trustedClientAddr?: string | RegExp

  user?: UserOptions[] // why iterate an array when could map {[username]: credential}
} & AnonymousPermissions &
  UserPermissions

export type AuthFactory = (options: AuthOptions) => AuthFunction

export type AuthFunction = (
  client: Socket,
  user: string
) => Promise<Credential | ((token: string) => Promise<Credential>)>

export enum LoginError {
  None,
  Secure,
  Password,
}

export default function internalAuthFactory({
  allowAnonymousLogin,
  requireAnonymousSecure,
  user: users,
  ...defaults
}: AuthOptions): AuthFunction {
  const defaultUserPermissions = Object.fromEntries(
    Object.keys(permissions).map((k) => [
      `allow${k}`,
      defaults[`allowUser${k}` as keyof typeof defaults] ?? false,
    ])
  ) as Permissions

  function getUser(username: string) {
    if (users) {
      return users.find((user) => user.username === username)
    }

    if (defaults.username === username) {
      return defaults as UserOptions
    }
  }

  function getUserCredential({ username, basefolder, ...user }: UserOptions) {
    return {
      ...defaultUserPermissions,
      ...Object.fromEntries(
        Object.entries({ ...defaults, ...user })
          .filter(([key]) => key.startsWith("allowUser"))
          .map(([key, value]) => [key.replace(/^allowUser/, "allow"), value])
      ),
      username,
      ...(basefolder && { basefolder }),
    } as Credential
  }

  function getAnonCredential(email: string) {
    return Promise.resolve({
      ...defaultUserPermissions,
      ...Object.fromEntries(
        Object.entries(defaults)
          .filter(([key]) => key.startsWith("allowAnonymous"))
          .map(([key, value]) => [
            key.replace(/^allowAnonymous/, "allow"),
            value,
          ])
      ),
      username: `anon(${email})`,
    } as Credential)
  }

  return function authenticate(client: Socket, username: string) {
    const user = getUser(username)
    if (user) {
      if (
        (defaults.requireSecure || user.requireSecure) &&
        !("encrypted" in client)
      ) {
        return Promise.reject(LoginError.Secure)
      }

      if (
        (defaults.allowLoginWithoutPassword &&
          user.allowLoginWithoutPassword) ||
        (defaults.trustClientAddr &&
          client.remoteAddress.match(user.trustedClientAddr))
      ) {
        return Promise.resolve(getUserCredential(user))
      }

      return Promise.resolve(function authenticate(token: string) {
        if (token && token === user.password) {
          return Promise.resolve(getUserCredential(user))
        }

        return Promise.reject(LoginError.Password)
      })
    }

    if (allowAnonymousLogin && username === "anonymous") {
      if (
        (defaults.requireSecure || requireAnonymousSecure) &&
        !("encrypted" in client)
      ) {
        return Promise.reject(LoginError.Secure)
      }

      return Promise.resolve(getAnonCredential)
    }

    return Promise.reject(LoginError.None)
  }
}
