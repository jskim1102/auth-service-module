// Minimal access-token holder for the demo. The refresh token lives in an httpOnly
// cookie (spec F4/F5) and is never touched by JS. The access token is short-lived;
// for the demo we keep it in sessionStorage so a page refresh keeps you logged in
// while the flow is shown. A production host would hold it in memory.

const KEY = 'auth_demo_access_token'

export const getToken = () => sessionStorage.getItem(KEY)
export const setToken = (t) => sessionStorage.setItem(KEY, t)
export const clearToken = () => sessionStorage.removeItem(KEY)
