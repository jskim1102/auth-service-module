import { useState } from 'react'
import { Link } from 'react-router-dom'
import { findUsername } from '../api.js'
import { Field, Notice } from '../components.jsx'

export default function FindUsername() {
  const [email, setEmail] = useState('')
  const [notice, setNotice] = useState(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setNotice(null)
    try {
      const res = await findUsername(email)
      // 202 carries an identical generic message whether or not the email exists
      // (no enumeration) — the username itself arrives by email, not in this response.
      const data = await res.json().catch(() => ({}))
      setNotice({
        status: 'ok',
        text: data.message || '해당 이메일로 가입된 계정이 있으면 아이디를 메일로 보냈습니다.',
      })
    } catch {
      setNotice({ status: 'error', text: '서버에 연결할 수 없습니다.' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h1>아이디 찾기</h1>
      <p className="card-help">가입한 이메일을 입력하면 아이디(사용자명)를 메일로 보냅니다.</p>
      <form onSubmit={onSubmit}>
        <Field
          label="가입 이메일"
          type="email"
          value={email}
          onChange={setEmail}
          autoComplete="email"
        />
        <button className="btn-primary" type="submit" disabled={busy}>
          {busy ? '전송 중…' : '아이디 메일로 받기'}
        </button>
      </form>
      <Notice status={notice?.status}>{notice?.text}</Notice>

      <p className="card-links">
        <Link to="/">로그인으로 돌아가기</Link>
      </p>
    </section>
  )
}
