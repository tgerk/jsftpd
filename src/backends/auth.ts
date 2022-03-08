import {
  LoginType,
  anonPermissions,
  AnonymousPermissions,
  userPermissions,
  UserPermissions,
  UserCredential,
  AuthOptions,
} from "../jsftpd"

const defaults: UserPermissions = {
  // TODO: construct by interation on values of enum userPermissions
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

function getUserPermissions({
  basefolder,
  filenameTransform,
  ...permissions
}: UserCredential) {
  const credential: UserCredential = { ...defaults }
  if (basefolder) credential.basefolder = basefolder
  if (filenameTransform) credential.filenameTransform = filenameTransform
  for (const k in credential) {
    if (k in permissions) {
      credential[k as userPermissions] = permissions[k as userPermissions]
    }
  }
  return credential
}

export default ({
  user: users,
  allowAnonymousLogin,
  username: defaultUser,
  password: defaultPassword,
  allowLoginWithoutPassword,
  ...config
}: AuthOptions) => ({
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
        return [LoginType.NoPassword, getUserPermissions(config)]
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
        return [LoginType.Anonymous, getAnonPermissions(config)]
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
        getUserPermissions(config),
      ]
    }
    return [LoginType.None]
  },
})
