import {
  LoginType,
  AnonymousPermissions,
  UserPermissions,
  UserCredential,
  anonPermissions,
  userPermissions,
} from "../jsftpd"

const defaults: UserPermissions = {
  allowUserFileCreate: false,
  allowUserFileRetrieve: false,
  allowUserFileOverwrite: false,
  allowUserFileDelete: false,
  allowUserFileRename: false,
  allowUserFolderDelete: false,
  allowUserFolderCreate: false,
}

function getAnonPermissions(permissions: AnonymousPermissions) {
  const credential: UserCredential = { ...defaults }
  for (const k in permissions) {
    const ak = k.replace("allowUser", "allowAnonymous") as anonPermissions
    if (ak in permissions) {
      credential[k as userPermissions] = permissions[ak]
    }
  }
  return credential
}

function getUserPermissions({ basefolder, ...permissions }: UserCredential) {
  const credential: UserCredential = { ...defaults }
  if (basefolder) credential.basefolder = basefolder
  for (const k in credential) {
    if (k in permissions) {
      credential[k as userPermissions] = permissions[k as userPermissions]
    }
  }
  return credential
}

export default ({
  allowAnonymousLogin,
  username: defaultUser,
  password: defaultPassword,
  allowLoginWithoutPassword,
  user: users,
  ...defaultUserCredential
}: {
  allowAnonymousLogin?: boolean
  username?: string
  user?: ({
    username: string
  } & UserCredential)[]
} & UserCredential &
  AnonymousPermissions) => ({
  userLoginType(username: string): [LoginType, UserCredential?] {
    if (username === "anonymous") {
      if (allowAnonymousLogin) {
        return [LoginType.Anonymous]
      }
    } else if (users?.length > 0) {
      const user = users.find(({ username: user }) => username === user)
      if (user) {
        if (user.allowLoginWithoutPassword) {
          return [LoginType.NoPassword, getUserPermissions(user)]
        } else {
          return [LoginType.Password]
        }
      }
    } else if (username === defaultUser) {
      if (allowLoginWithoutPassword === true) {
        return [LoginType.NoPassword, getUserPermissions(defaultUserCredential)]
      } else {
        return [LoginType.Password]
      }
    }
    return [LoginType.None]
  },

  userAuthenticate(
    username: string,
    password: string
  ): [LoginType, UserCredential?] {
    if (username === "anonymous") {
      if (allowAnonymousLogin) {
        return [LoginType.Anonymous, getAnonPermissions(defaultUserCredential)]
      }
    } else if (users?.length > 0) {
      const user = users.find(({ username: user }) => username === user)
      if (
        user &&
        (user.allowLoginWithoutPassword || password === user.password)
      ) {
        return [
          user.allowLoginWithoutPassword
            ? LoginType.NoPassword
            : LoginType.Password,
          getUserPermissions(user),
        ]
      }
    } else if (
      username === defaultUser &&
      (allowLoginWithoutPassword || password === defaultPassword)
    ) {
      return [
        allowLoginWithoutPassword ? LoginType.NoPassword : LoginType.Password,
        getUserPermissions(defaultUserCredential),
      ]
    }
    return [LoginType.None]
  },
})
