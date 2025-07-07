export function createAuthCookies({ accessToken, refreshToken }) {
  return {
    accessToken: {
      value: accessToken,
      options: {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 15 * 60 * 1000,
        path: "/",
      },
    },
    refreshToken: {
      value: refreshToken,
      options: {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: "/auth",
      },
    },
  };
}

export function clearAuthCookies() {
  const expired = {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    expires: new Date(0),
    path: "/",
  };
  return {
    accessToken: { value: "", options: expired },
    refreshToken: { value: "", options: { ...expired, path: "/auth" } },
  };
}
