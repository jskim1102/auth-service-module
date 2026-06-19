import { useState } from 'react'
import { Link } from 'react-router-dom'
import { requestPasswordReset } from '../api.js'
import { Field, Notice } from '../components.jsx'

export default function ForgotPassword() {
  const [identifier, setIdentifier] = useState('')
  const [notice, setNotice] = useState(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setNotice(null)
    try {
      const res = await requestPasswordReset(identifier)
      // #31: the 202 body carries a masked-email hint when an emailed account
      // matched (e.g. "...sent to j**********@gmail.com."), else a generic message.
      // Show the server's message directly so the hint reaches the user.
      const data = await res.json().catch(() => ({}))
      setNotice({
        status: 'ok',
        text: data.message || '재설정 링크를 보냈습니다. 메일을 확인하세요.',
      })
    } catch {
      setNotice({ status: 'error', text: '서버에 연결할 수 없습니다.' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h1>비밀번호 찾기</h1>
      <p className="card-help">아이디 또는 가입 이메일을 입력하면 재설정 링크를 보냅니다.</p>
      <form onSubmit={onSubmit}>
        <Field
          label="아이디 또는 이메일"
          value={identifier}
          onChange={setIdentifier}
          autoComplete="username"
        />
        <button className="btn-primary" type="submit" disabled={busy}>
          {busy ? '전송 중…' : '재설정 링크 받기'}
        </button>
      </form>
      <Notice status={notice?.status}>{notice?.text}</Notice>

      <p className="card-links">
        <Link to="/">로그인으로 돌아가기</Link>
      </p>
    </section>
  )
}
