enum permissions {
  FileCreate,
  FileRetrieve,
  FileOverwrite,
  FileDelete,
  FileRename,
  FolderDelete,
  FolderCreate,
}
type AnonymousPermissions = {
  -readonly [k in keyof typeof permissions as `allowAnonymous${k &
    string}`]?: boolean
}
type UserPermissions = {
  -readonly [k in keyof typeof permissions as `allowUser${k &
    string}`]?: boolean
}
type UserCredential = {
  password?: string
  allowLoginWithoutPassword?: boolean
  basefolder?: string
} & UserPermissions

export type AuthOptions = {
  allowAnonymousLogin?: boolean
  username?: string
  user?: ({ username: string } & UserCredential)[] // why iterate an array when could map {[username]: credential}
} & AnonymousPermissions &
  UserCredential

export type Permissions = {
  -readonly [k in keyof typeof permissions as `allow${k & string}`]: boolean
}

export type Credential = {
  username: string
  basefolder?: string
} & Permissions

const leastPrivilege = Object.fromEntries(
  Object.keys(permissions).map((k) => [`allow${k}`, false])
) as Permissions

function getCredentialForAnon(
  password: string,
  anonPermissions: AnonymousPermissions
): Credential {
  const credential: Credential = Object.assign(
    { username: `anon(${password})` },
    leastPrivilege
  )
  for (const k in permissions) {
    const ak = `allowAnonymous${k}` as keyof AnonymousPermissions
    if (ak in anonPermissions) {
      credential[`allow${k}` as keyof Permissions] = anonPermissions[ak]
    }
  }
  return credential
}

function getCredentialForUser(
  username: string,
  { basefolder, ...userPermissions }: UserCredential,
  config: UserCredential = {}
): Credential {
  // apply top-level allowUser* permissions as default for all users
  if (config) userPermissions = Object.assign({}, config, userPermissions)

  const credential: Credential = Object.assign({ username }, leastPrivilege)
  if (basefolder) credential.basefolder = basefolder
  for (const k in permissions) {
    const ak = `allowUser${k}` as keyof UserPermissions
    if (ak in userPermissions) {
      credential[`allow${k}` as keyof Permissions] = userPermissions[ak]
    }
  }
  return credential
}

export enum LoginType {
  None,
  Anonymous,
  Password,
  NoPassword,
}

export type OnAuthHandler = (cred: Credential) => void

export interface AuthHandlers {
  userLoginType(user: string, onAuth: OnAuthHandler): LoginType
  userAuthenticate(user: string, pass: string, onAuth: OnAuthHandler): LoginType
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
  return {
    userLoginType(
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
            onAuthenticated(getCredentialForUser(username, user, config))
            return LoginType.NoPassword
          } else {
            return LoginType.Password
          }
        }
      } else if (username === defaultUsername) {
        if (allowLoginWithoutPassword === true) {
          onAuthenticated(getCredentialForUser(defaultUsername, config))
          return LoginType.NoPassword
        } else {
          return LoginType.Password
        }
      }
      return LoginType.None
    },

    userAuthenticate(
      username: string,
      password: string,
      onAuthenticated: (credential: Credential) => void
    ): LoginType {
      if (username === "anonymous") {
        if (allowAnonymousLogin) {
          onAuthenticated(getCredentialForAnon(password, config))
          return LoginType.Anonymous
        }
      } else if (users?.length > 0) {
        const user = users.find(
          ({ username: user, password: pass, allowLoginWithoutPassword }) =>
            user === username && (pass === password || allowLoginWithoutPassword)
        )
        if (user) {
          onAuthenticated(getCredentialForUser(username, user, config))
          return user.allowLoginWithoutPassword
            ? LoginType.NoPassword
            : LoginType.Password
        }
      } else if (
        username === defaultUsername &&
        (password === defaultPassword || allowLoginWithoutPassword)
      ) {
        onAuthenticated(getCredentialForUser(defaultUsername, config))
        return allowLoginWithoutPassword
          ? LoginType.NoPassword
          : LoginType.Password
      }
      return LoginType.None
    },
  }
}
