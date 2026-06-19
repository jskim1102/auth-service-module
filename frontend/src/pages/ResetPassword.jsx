import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { resetPassword } from '../api.js'
import { Field, Notice } from '../components.jsx'

export default function ResetPassword() {
  const [params] = useSearchParams()
  // Reset link from the email lands here as /reset?token=... — prefill it.
  const [token, setToken] = useState(params.get('token') ?? '')
  const [newPassword, setNewPassword] = useState('')
  const [notice, setNotice] = useState(null)
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  async function onSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setNotice(null)
    try {
      const res = await resetPassword(token, newPassword)
      if (res.status === 204) {
        setNotice({ status: 'ok', text: '비밀번호가 변경되었습니다. 로그인하세요.' })
        setTimeout(() => navigate('/'), 800)
      } else {
        setNotice({ status: 'error', text: '재설정 실패 — 토큰이 만료되었거나 이미 사용되었습니다.' })
      }
    } catch {
      setNotice({ status: 'error', text: '서버에 연결할 수 없습니다.' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h1>비밀번호 재설정</h1>
      <form onSubmit={onSubmit}>
        <Field label="재설정 토큰" value={token} onChange={setToken} autoComplete="off" />
        <Field
          label="새 비밀번호"
          type="password"
          value={newPassword}
          onChange={setNewPassword}
          autoComplete="new-password"
        />
        <button className="btn-primary" type="submit" disabled={busy}>
          {busy ? '변경 중…' : '비밀번호 변경'}
        </button>
      </form>
      <Notice status={notice?.status}>{notice?.text}</Notice>

      <p className="card-links">
        <Link to="/forgot">재설정 링크 다시 받기</Link>
        <Link to="/">로그인으로 돌아가기</Link>
      </p>
    </section>
  )
}
