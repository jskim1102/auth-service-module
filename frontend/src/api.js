// Demo API client for the auth-service. The pages (phase8.ckpt4) consume these
// against the live backend: login/signup/reset handle responses, OAuthCallback
// exchanges the one-time code, Me reads the profile. Signatures are locked from
// specs/spec.md + tasks.md.
//
// API base: defaults to same-origin "/auth" (nginx proxies /auth/* to BACKEND_PORT).
// Override with VITE_API_BASE only for direct-to-backend (e.g. http://localhost:8003).

const BASE = (import.meta.env.VITE_API_BASE ?? '').replace(/\/$/, '')

async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include', // refresh cookie is httpOnly (spec F4/F5)
    body: JSON.stringify(body),
  })
  return res
}

async function get(path, token) {
  const res = await fetch(`${BASE}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    credentials: 'include',
  })
  return res
}

// POST /auth/signup {username,email,password} -> 201
export const signup = (username, email, password) =>
  post('/auth/signup', { username, email, password })

// POST /auth/login {identifier,password} -> {access_token} (+ refresh httpOnly cookie & body)
export const login = (identifier, password) =>
  post('/auth/login', { identifier, password })

// POST /auth/logout -> 204 (revokes refresh)
export const logout = () => post('/auth/logout', {})

// POST /auth/password/reset-request {identifier} -> 202 (masked-email hint when an
// emailed account matches, else generic). identifier = username OR email (#31).
export const requestPasswordReset = (identifier) =>
  post('/auth/password/reset-request', { identifier })

// POST /auth/password/reset {token,new_password} -> 204
export const resetPassword = (token, new_password) =>
  post('/auth/password/reset', { token, new_password })

// GET /auth/me (Bearer) -> {id,email,username,identities}
export const me = (token) => get('/auth/me', token)

// SNS login: full-page redirect to the provider consent screen.
// GET /auth/oauth/{provider}/authorize -> 302 to provider (state + PKCE).
export const oauthAuthorizeUrl = (provider) => `${BASE}/auth/oauth/${provider}/authorize`

// After the callback redirects back to /auth/callback?code=..., exchange the
// short-lived single-use code for tokens. POST /auth/oauth/exchange {code} ->
// {access_token, refresh_token} (spec F8, dev tasks #68/#69).
export const exchangeOAuthCode = (code) => post('/auth/oauth/exchange', { code })
