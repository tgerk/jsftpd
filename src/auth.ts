import { Socket } from "net"
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

export interface OnAuthHandler {
  (cred: Credential): void
}

export interface AuthHandlers {
  userLoginType(client: Socket, user: string, onAuth: OnAuthHandler): LoginType
  userAuthenticate(
    client: Socket,
    user: string,
    pass: string,
    onAuth: OnAuthHandler
  ): LoginType
}

export type AuthHandlersFactory = (options: AuthOptions) => AuthHandlers

export default function ({
  user: users,
  username: defaultUsername,
  password: defaultPassword,
  allowFromAddrWithoutPassword,
  allowLoginWithoutPassword,
  allowAnonymousLogin,
  ...defaults
}: AuthOptions): AuthHandlers {
  const defaultPrivilege = Object.fromEntries(
    Object.keys(permissions).map((k) => [
      `allow${k}`,
      defaults[`allow${k}` as keyof typeof defaults] ?? false,
    ])
  ) as Permissions

  const getCredentialForAnon = (password: string) =>
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

  return {
    userLoginType(
      client: Socket,
      username: string,
      onAuthenticated: (credential: Credential) => void
    ): LoginType {
      if (username === "anonymous") {
        if (allowAnonymousLogin) {
          return LoginType.Anonymous
        }

        return LoginType.None
      }

      if (users?.length > 0) {
        const user = users.find((user) => user.username === username)
        if (user) {
          if (
            (allowLoginWithoutPassword && user.allowLoginWithoutPassword) ||
            (allowFromAddrWithoutPassword &&
              client.remoteAddress.match(user.allowFromAddrWithoutPassword))
          ) {
            onAuthenticated(getCredentialForUser(user))
            return LoginType.NoPassword
          }

          return LoginType.Password
        }

        return LoginType.None
      } else if (username === defaultUsername) {
        if (allowLoginWithoutPassword === true) {
          onAuthenticated(getCredentialForUser({ username }))
          return LoginType.NoPassword
        }

        return LoginType.Password
      }

      return LoginType.None
    },

    userAuthenticate(
      client: Socket,
      username: string,
      password: string,
      onAuthenticated: (credential: Credential) => void
    ): LoginType {
      if (username === "anonymous") {
        if (allowAnonymousLogin) {
          onAuthenticated(getCredentialForAnon(password))
          return LoginType.Anonymous
        }

        return LoginType.None
      }

      if (users?.length > 0) {
        const user = users.find((user) => user.username === username)
        if (user && user.password === password) {
          onAuthenticated(getCredentialForUser(user))
          return LoginType.Password
        }

        return LoginType.None
      } else if (username === defaultUsername && password === defaultPassword) {
        onAuthenticated(getCredentialForUser({ username }))
        return LoginType.Password
      }

      return LoginType.None
    },
  }
}
