import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { signup } from '../api.js'
import { Field, Notice } from '../components.jsx'

export default function Signup() {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [notice, setNotice] = useState(null)
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  async function onSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setNotice(null)
    try {
      const res = await signup(username, email, password)
      if (res.status === 201) {
        setNotice({ status: 'ok', text: '가입 완료. 로그인하세요.' })
        setTimeout(() => navigate('/'), 800)
      } else {
        setNotice({ status: 'error', text: '가입 실패 — 아이디/이메일이 이미 사용 중일 수 있습니다.' })
      }
    } catch {
      setNotice({ status: 'error', text: '서버에 연결할 수 없습니다.' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h1>회원가입</h1>
      <form onSubmit={onSubmit}>
        <Field label="아이디" value={username} onChange={setUsername} autoComplete="username" />
        <Field label="이메일" type="email" value={email} onChange={setEmail} autoComplete="email" />
        <Field
          label="비밀번호"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="new-password"
        />
        <button className="btn-primary" type="submit" disabled={busy}>
          {busy ? '가입 중…' : '가입하기'}
        </button>
      </form>
      <Notice status={notice?.status}>{notice?.text}</Notice>

      <p className="card-links">
        <Link to="/">로그인으로 돌아가기</Link>
      </p>
    </section>
  )
}
