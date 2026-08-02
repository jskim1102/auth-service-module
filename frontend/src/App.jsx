import { Routes, Route, Navigate, NavLink } from 'react-router-dom'
import Login from './pages/Login.jsx'
import Signup from './pages/Signup.jsx'
import ForgotPassword from './pages/ForgotPassword.jsx'
import FindUsername from './pages/FindUsername.jsx'
import ResetPassword from './pages/ResetPassword.jsx'
import OAuthCallback from './pages/OAuthCallback.jsx'
import Me from './pages/Me.jsx'

export default function App() {
  return (
    <div className="app">
      <header className="app-header">
        <span className="brand">auth-service</span>
        <span className="brand-tag">demo</span>
      </header>

      <main className="app-main">
        <Routes>
          <Route path="/" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/forgot" element={<ForgotPassword />} />
          <Route path="/find-id" element={<FindUsername />} />
          <Route path="/reset" element={<ResetPassword />} />
          {/* Whitelisted OAuth landing — must match ALLOWED_REDIRECT_URIS in .env */}
          <Route path="/auth/callback" element={<OAuthCallback />} />
          <Route path="/me" element={<Me />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>

      <footer className="app-footer">
        <NavLink to="/">로그인</NavLink>
        <NavLink to="/signup">회원가입</NavLink>
        <NavLink to="/find-id">아이디 찾기</NavLink>
        <NavLink to="/forgot">비밀번호 찾기</NavLink>
        <NavLink to="/me">내 정보</NavLink>
      </footer>
    </div>
  )
}
