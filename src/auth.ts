import { Socket } from "node:net"
import { AbsolutePath, RelativePath } from "./store.js"

export enum LoginType {
  None,
  Anonymous,
  Password,
  NoPassword,
}

export enum permissions {
  FileCreate = "FileCreate",
  FileRetrieve = "FileRetrieve",
  FileOverwrite = "FileOverwrite",
  FileDelete = "FileDelete",
  FileRename = "FileRename",
  FolderDelete = "FolderDelete",
  FolderCreate = "FolderCreate",
}

type AnonymousPermissions = {
  -readonly [k in keyof typeof permissions as `allowAnonymous${k &
    string}`]?: boolean
}

type UserPermissions = {
  -readonly [k in keyof typeof permissions as `allowUser${k &
    string}`]?: boolean
}
type UserBaseFolder = AbsolutePath | RelativePath | string
type UserOptions = {
  username: string
  password?: string
  allowLoginWithoutPassword?: boolean
  allowFromAddrWithoutPassword?: string
  basefolder?: UserBaseFolder
} & UserPermissions

export type AuthOptions = {
  allowAnonymousLogin?: boolean
  username?: string
  password?: string
  allowLoginWithoutPassword?: boolean
  allowFromAddrWithoutPassword?: boolean
  user?: UserOptions[] // why iterate an array when could map {[username]: credential}
} & AnonymousPermissions &
  UserPermissions

export type Permissions = {
  -readonly [k in keyof typeof permissions as `allow${k & string}`]: boolean
}

export type Credential = {
  username: string
  basefolder?: UserBaseFolder
} & Permissions

export type AuthFunction = (
  client: Socket,
  user: string,
  pass?: string
) => Promise<Credential>

export type AuthFactory = (options: AuthOptions) => AuthFunction

export default function authScheme({
  user: users,
  allowAnonymousLogin,
  username: defaultUsername,
  password: defaultPassword,
  allowLoginWithoutPassword,
  allowFromAddrWithoutPassword,
  ...defaults
}: AuthOptions): AuthFunction {
  const defaultPrivilege = Object.fromEntries(
      Object.keys(permissions).map((k) => [
        `allow${k}`,
        defaults[`allow${k}` as keyof typeof defaults] ?? false,
      ])
    ) as Permissions,
    getCredentialForAnon = (password: string) =>
      ({
        ...defaultPrivilege,
        ...Object.fromEntries(
          Object.entries({ ...defaults, username: `anon(${password})` })
            .filter(([key]) => !key.startsWith("allowUser"))
            .map(([key, value]) => [
              key.replace(/^allowAnonymous/, "allow"),
              value,
            ])
        ),
      } as Credential),
    getCredentialForUser = ({
      password: _,
      allowLoginWithoutPassword: __,
      allowFromAddrWithoutPassword: ___,
      ...user
    }: UserOptions) =>
      ({
        ...defaultPrivilege,
        ...Object.fromEntries(
          Object.entries({ ...defaults, ...user })
            .filter(([key]) => !key.startsWith("allowAnonymous"))
            .map(([key, value]) => [key.replace(/^allowUser/, "allow"), value])
        ),
      } as Credential)

  return function userAuthenticate(
    client: Socket,
    username: string,
    password?: string
  ) {
    return new Promise((resolve, reject) => {
      if (username === "anonymous") {
        if (allowAnonymousLogin) {
          if (password) {
            resolve(getCredentialForAnon(password))
          } else {
            reject(LoginType.Anonymous)
          }
        }
      } else if (users?.length > 0) {
        const user = users.find((user) => user.username === username)
        if (user) {
          if (
            (allowLoginWithoutPassword && user.allowLoginWithoutPassword) ||
            (allowFromAddrWithoutPassword &&
              client.remoteAddress.match(user.allowFromAddrWithoutPassword))
          ) {
            resolve(getCredentialForUser(user))
          } else if (password) {
            if (password === user.password) {
              resolve(getCredentialForUser(user))
            }
          } else {
            reject(LoginType.Password)
          }
        }
      } else if (username === defaultUsername) {
        if (allowLoginWithoutPassword === true) {
          resolve(getCredentialForUser({ username }))
        } else if (password) {
          if (password === defaultPassword) {
            resolve(getCredentialForUser({ username }))
          }
        } else {
          reject(LoginType.Password)
        }
      }

      reject(LoginType.None)
    })
  }
}

/** OAuth authentication for FTP:
 * most sensible is the Password grant (FTP does not provide redirect, e.g. the auth-code grant)
 */
