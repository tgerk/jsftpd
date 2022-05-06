import { Socket } from "net"
import { TLSSocket } from "tls"

enum permissions {
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
export type Permissions = {
  -readonly [k in keyof typeof permissions as `allow${k & string}`]: boolean
}

export type Credential = {
  username: string
  basefolder?: string
} & Permissions

type UserOptions = {
  username: string
  password?: string
  allowLoginWithoutPassword?: boolean
  basefolder?: string
} & UserPermissions
export type AuthOptions = {
  allowAnonymousLogin?: boolean
  username?: string
  password?: string
  allowLoginWithoutPassword?: boolean
  user?: UserOptions[] // why iterate an array when could map {[username]: credential}
} & AnonymousPermissions &
  UserPermissions

export enum LoginType {
  None,
  Anonymous,
  Password,
  NoPassword,
}

export type OnAuthHandler = (cred: Credential) => void

export interface AuthHandlers {
  userLoginType(
    client: Socket | TLSSocket,
    user: string,
    onAuth: OnAuthHandler
  ): LoginType
  userAuthenticate(
    client: Socket | TLSSocket,
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
  allowLoginWithoutPassword,
  allowAnonymousLogin,
  ...config
}: AuthOptions): AuthHandlers {
  const leastPrivilege = Object.fromEntries(
    Object.keys(permissions).map((k) => [`allow${k}`, false])
  ) as Permissions

  function getCredentialForAnon(password: string): Credential {
    return {
      ...leastPrivilege,
      ...Object.fromEntries(
        Object.entries({ ...config, username: `anon(${password})` })
          .filter(([key]) => !key.startsWith("allowUser"))
          .map(([key, value]) => [
            key.replace(/^allowAnonymous/, "allow"),
            value,
          ])
      ),
    } as Credential
  }

  function getCredentialForUser({
    password: _,
    allowLoginWithoutPassword: __,
    ...user
  }: UserOptions): Credential {
    return {
      ...leastPrivilege,
      ...Object.fromEntries(
        Object.entries({ ...config, ...user })
          .filter(([key]) => !key.startsWith("allowAnonymous"))
          .map(([key, value]) => [key.replace(/^allowUser/, "allow"), value])
      ),
    } as Credential
  }

  return {
    userLoginType(
      _client: Socket | TLSSocket,
      username: string,
      onAuthenticated: (credential: Credential) => void
    ): LoginType {
      if (username === "anonymous") {
        if (allowAnonymousLogin) {
          return LoginType.Anonymous
        }
      } else if (users?.length > 0) {
        const user = users.find(({ username: user }) => user === username)
        if (user) {
          if (user.allowLoginWithoutPassword) {
            onAuthenticated(getCredentialForUser(user))
            return LoginType.NoPassword
          } else {
            return LoginType.Password
          }
        }
      } else if (username === defaultUsername) {
        if (allowLoginWithoutPassword === true) {
          onAuthenticated(getCredentialForUser({ username }))
          return LoginType.NoPassword
        } else {
          return LoginType.Password
        }
      }
      return LoginType.None
    },

    userAuthenticate(
      _client: Socket | TLSSocket,
      username: string,
      password: string,
      onAuthenticated: (credential: Credential) => void
    ): LoginType {
      if (username === "anonymous") {
        if (allowAnonymousLogin) {
          onAuthenticated(getCredentialForAnon(password))
          return LoginType.Anonymous
        }
      } else if (users?.length > 0) {
        const user = users.find(
          ({ username: user, password: pass, allowLoginWithoutPassword }) =>
            user === username &&
            (pass === password || allowLoginWithoutPassword)
        )
        if (user) {
          onAuthenticated(getCredentialForUser(user))
          return user.allowLoginWithoutPassword
            ? LoginType.NoPassword
            : LoginType.Password
        }
      } else if (
        username === defaultUsername &&
        (password === defaultPassword || allowLoginWithoutPassword)
      ) {
        onAuthenticated(getCredentialForUser({ username }))
        return allowLoginWithoutPassword
          ? LoginType.NoPassword
          : LoginType.Password
      }
      return LoginType.None
    },
  }
}
