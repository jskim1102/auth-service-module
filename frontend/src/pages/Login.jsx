import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { login } from '../api.js'
import { setToken } from '../auth-store.js'
import { Field, Notice } from '../components.jsx'
import SnsButtons from '../SnsButtons.jsx'

export default function Login() {
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [notice, setNotice] = useState(null)
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  async function onSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setNotice(null)
    try {
      const res = await login(identifier, password)
      if (res.ok) {
        const data = await res.json()
        if (data.access_token) setToken(data.access_token)
        navigate('/me')
      } else {
        setNotice({ status: 'error', text: '로그인 실패 — 아이디/이메일 또는 비밀번호를 확인하세요.' })
      }
    } catch {
      setNotice({ status: 'error', text: '서버에 연결할 수 없습니다.' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h1>로그인</h1>
      <form onSubmit={onSubmit}>
        <Field
          label="아이디 또는 이메일"
          value={identifier}
          onChange={setIdentifier}
          autoComplete="username"
        />
        <Field
          label="비밀번호"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
        />
        <button className="btn-primary" type="submit" disabled={busy}>
          {busy ? '로그인 중…' : '로그인'}
        </button>
      </form>
      <Notice status={notice?.status}>{notice?.text}</Notice>

      <SnsButtons />

      <p className="card-links">
        <Link to="/signup">회원가입</Link>
        <Link to="/find-id">아이디 찾기</Link>
        <Link to="/forgot">비밀번호 찾기</Link>
      </p>
    </section>
  )
}
