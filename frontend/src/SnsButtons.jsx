import { oauthAuthorizeUrl } from './api.js'

// Zero-friction SNS login: a click is a full-page navigation to the provider's
// authorize endpoint (spec F8). First login auto-provisions the account on callback.
// Brand colors are the recognizable convention, not decoration — users must spot
// the right provider at a glance.
const PROVIDERS = [
  { id: 'naver', label: 'Naver 로그인', className: 'sns-naver', mark: 'N' },
  { id: 'kakao', label: 'Kakao 로그인', className: 'sns-kakao', mark: 'K' },
  { id: 'google', label: 'Google 로그인', className: 'sns-google', mark: 'G' },
]

export default function SnsButtons() {
  return (
    <div className="sns">
      <div className="sns-divider"><span>SNS 계정으로 계속</span></div>
      <div className="sns-buttons">
        {PROVIDERS.map((p) => (
          <a
            key={p.id}
            className={`sns-btn ${p.className}`}
            href={oauthAuthorizeUrl(p.id)}
            aria-label={p.label}
          >
            <span className="sns-mark" aria-hidden="true">{p.mark}</span>
            <span className="sns-text">{p.label}</span>
          </a>
        ))}
      </div>
    </div>
  )
}
