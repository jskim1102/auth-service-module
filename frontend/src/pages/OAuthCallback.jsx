import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { exchangeOAuthCode } from '../api.js'
import { setToken } from '../auth-store.js'
import { Notice } from '../components.jsx'

// The one-time code is single-use: the backend burns it on first exchange. React
// StrictMode (dev) mounts effects twice — naively that fires two exchanges and the
// 2nd 400s on the already-consumed code. Cache the exchange PROMISE by code at
// module scope (survives the StrictMode remount, unlike a ref) so the code is
// exchanged exactly ONCE; whichever mounted instance is still alive reads the
// shared response and navigates.
const exchangeByCode = new Map()

function exchangeOnce(code) {
  let p = exchangeByCode.get(code)
  if (!p) {
    p = exchangeOAuthCode(code)
    exchangeByCode.set(code, p)
  }
  return p
}

// SNS callback landing (whitelisted in .env ALLOWED_REDIRECT_URIS).
// The backend redirected here carrying a short-lived single-use one-time code in
// the query (raw tokens are never put in the URL — spec F8). Exchange it for tokens.
export default function OAuthCallback() {
  const [params] = useSearchParams()
  const [notice, setNotice] = useState({ status: 'info', text: 'SNS 로그인 처리 중…' })
  const navigate = useNavigate()

  useEffect(() => {
    const code = params.get('code')
    const error = params.get('error')
    if (error) {
      setNotice({ status: 'error', text: `SNS 로그인 실패: ${error}` })
      return
    }
    if (!code) {
      setNotice({ status: 'error', text: '인증 코드가 없습니다.' })
      return
    }
    let active = true
    exchangeOnce(code)
      .then(async (res) => {
        if (!active) return // a superseded StrictMode mount — let the live one handle it
        if (res.ok) {
          const data = await res.json()
          if (data.access_token) setToken(data.access_token)
          navigate('/me', { replace: true })
        } else {
          setNotice({ status: 'error', text: '코드 교환 실패 — 코드가 만료되었거나 이미 사용되었습니다.' })
        }
      })
      .catch(() => {
        if (active) setNotice({ status: 'error', text: '서버에 연결할 수 없습니다.' })
      })
    return () => {
      active = false
    }
  }, [params, navigate])

  return (
    <section className="card">
      <h1>SNS 로그인</h1>
      <Notice status={notice.status}>{notice.text}</Notice>
      <p className="card-links">
        <Link to="/">로그인으로 돌아가기</Link>
      </p>
    </section>
  )
}
