import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { exchangeOAuthCode } from '../api.js'
import { setToken } from '../auth-store.js'
import { Notice } from '../components.jsx'

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
    let cancelled = false
    ;(async () => {
      try {
        const res = await exchangeOAuthCode(code)
        if (cancelled) return
        if (res.ok) {
          const data = await res.json()
          if (data.access_token) setToken(data.access_token)
          navigate('/me', { replace: true })
        } else {
          setNotice({ status: 'error', text: '코드 교환 실패 — 코드가 만료되었거나 이미 사용되었습니다.' })
        }
      } catch {
        if (!cancelled) setNotice({ status: 'error', text: '서버에 연결할 수 없습니다.' })
      }
    })()
    return () => {
      cancelled = true
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
