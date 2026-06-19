// Tiny shared building blocks so each page stays short. Plain markup, no abstractions
// beyond a labeled input and a status line.

export function Field({ label, type = 'text', value, onChange, autoComplete, required = true }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={autoComplete}
        required={required}
      />
    </label>
  )
}

// status: null | 'ok' | 'error'
export function Notice({ status, children }) {
  if (!children) return null
  return <p className={`notice notice-${status ?? 'info'}`}>{children}</p>
}
