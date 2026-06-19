import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { me, logout } from '../api.js'
import { getToken, clearToken } from '../auth-store.js'
import { Notice } from '../components.jsx'

// Authed landing: proves the access token works against GET /auth/me and lets the
// user log out (revokes the refresh token). The whole point is to show the flow end
// to end — login/SNS -> token -> protected call.
export default function Me() {
  const [user, setUser] = useState(null)
  const [notice, setNotice] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    const token = getToken()
    if (!token) {
      setNotice({ status: 'error', text: '로그인이 필요합니다.' })
      return
    }
    let cancelled = false
    ;(async () => {
      try {
        const res = await me(token)
        if (cancelled) return
        if (res.ok) {
          setUser(await res.json())
        } else {
          setNotice({ status: 'error', text: '세션이 만료되었습니다. 다시 로그인하세요.' })
        }
      } catch {
        if (!cancelled) setNotice({ status: 'error', text: '서버에 연결할 수 없습니다.' })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  async function onLogout() {
    try {
      await logout()
    } finally {
      clearToken()
      navigate('/', { replace: true })
    }
  }

  return (
    <section className="card">
      <h1>내 정보</h1>
      <Notice status={notice?.status}>{notice?.text}</Notice>

      {user && (
        <>
          <dl className="user-info">
            <dt>ID</dt>
            <dd>{user.id}</dd>
            <dt>이메일</dt>
            <dd>{user.email}</dd>
            <dt>아이디</dt>
            <dd>{user.username ?? '— (SNS 전용 계정)'}</dd>
            <dt>연결된 로그인</dt>
            <dd>
              {Array.isArray(user.identities) && user.identities.length > 0
                ? user.identities.map((i) => i.provider ?? i).join(', ')
                : '—'}
            </dd>
          </dl>
          <button className="btn-primary" type="button" onClick={onLogout}>
            로그아웃
          </button>
        </>
      )}

      {!user && (
        <p className="card-links">
          <Link to="/">로그인하러 가기</Link>
        </p>
      )}
    </section>
  )
}
