import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'
import type { AuthUser } from '../../App'

type PlatformUser = {
  id: string
  username: string
  display_name: string
  role_id: string
  role: string
  is_active: boolean
  must_change_password: boolean
  last_login_at?: string | null
  permissions: string[]
}

type PlatformRole = {
  id: string
  name: string
  description: string
  is_system: boolean
  permissions: string[]
}

type PlatformPermission = { key: string; description: string }

const AUDIT_ROLE_ID = 'role-audit'

async function readApi<T>(path: string): Promise<T> {
  const response = await apiFetch(path)
  const payload = await response.json() as { success?: boolean; data?: T; error?: string }
  if (!payload.success) throw new Error(payload.error || 'request failed')
  return payload.data as T
}

function formatLastLogin(value: string | null | undefined, language: string, neverLabel: string) {
  if (!value) return neverLabel
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return neverLabel
  return new Intl.DateTimeFormat(language.startsWith('zh') ? 'zh-CN' : 'en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function initials(value: string) {
  return value.trim().slice(0, 2).toUpperCase() || '?'
}

export default function PlatformAccessSettings({ authUser }: { authUser: AuthUser }) {
  const { t, i18n } = useTranslation()
  const [users, setUsers] = useState<PlatformUser[]>([])
  const [roles, setRoles] = useState<PlatformRole[]>([])
  const [permissions, setPermissions] = useState<PlatformPermission[]>([])
  const [selectedRole, setSelectedRole] = useState<string>('')
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)
  const [newUser, setNewUser] = useState({ username: '', display_name: '', password: '', role_id: '' })
  const [newRole, setNewRole] = useState({ name: '', description: '', permissions: [] as string[] })
  const [loading, setLoading] = useState(true)
  const [busyAction, setBusyAction] = useState<string | null>(null)
  const canManageRoles = authUser.permissions.includes('platform.roles.manage')
  const isAdmin = authUser.role.toLowerCase() === 'admin'
  const assignableRoles = useMemo(
    () => isAdmin ? roles : roles.filter(role => role.id !== AUDIT_ROLE_ID),
    [isAdmin, roles],
  )
  const selected = useMemo(() => roles.find(role => role.id === selectedRole), [roles, selectedRole])
  const activeUsers = users.filter(user => user.is_active).length
  const permissionCount = canManageRoles ? permissions.length : authUser.permissions.length
  const busy = busyAction !== null

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [loadedUsers, loadedRoles, loadedPermissions] = await Promise.all([
        readApi<PlatformUser[]>('/api/admin/users'),
        readApi<PlatformRole[]>('/api/admin/roles'),
        canManageRoles
          ? readApi<PlatformPermission[]>('/api/admin/permissions')
          : Promise.resolve([] as PlatformPermission[]),
      ])
      setUsers(loadedUsers)
      setRoles(loadedRoles)
      setPermissions(loadedPermissions)
      setSelectedRole(current => current && loadedRoles.some(role => role.id === current) ? current : loadedRoles[0]?.id || '')
      setNewUser(current => ({
        ...current,
        role_id: current.role_id && loadedRoles.some(role => role.id === current.role_id)
          ? current.role_id
          : loadedRoles.find(role => role.name === 'viewer')?.id || loadedRoles[0]?.id || '',
      }))
    } finally {
      setLoading(false)
    }
  }, [canManageRoles])

  useEffect(() => {
    void load().catch(error => setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformLoadFailed') }))
  }, [load, t])

  const createUser = async () => {
    if (!newUser.username || !newUser.password || !newUser.role_id) return
    setBusyAction('create-user')
    try {
      await apiFetch('/api/admin/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newUser) })
      setNewUser(current => ({ ...current, username: '', display_name: '', password: '' }))
      setMessage({ ok: true, text: t('settings.platformUserCreated') })
      await load()
    } catch (error) {
      setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformSaveFailed') })
    } finally {
      setBusyAction(null)
    }
  }

  const saveUser = async (user: PlatformUser) => {
    setBusyAction(`save-user:${user.id}`)
    try {
      await apiFetch(`/api/admin/users/${user.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ display_name: user.display_name, role_id: user.role_id, is_active: user.is_active, password: null }) })
      setMessage({ ok: true, text: t('settings.platformSaved') })
      await load()
    } catch (error) {
      setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformSaveFailed') })
    } finally {
      setBusyAction(null)
    }
  }

  const disableUser = async (id: string) => {
    setBusyAction(`disable-user:${id}`)
    try {
      await apiFetch(`/api/admin/users/${id}`, { method: 'DELETE' })
      setMessage({ ok: true, text: t('settings.platformSaved') })
      await load()
    } catch (error) {
      setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformSaveFailed') })
    } finally {
      setBusyAction(null)
    }
  }

  const createRole = async () => {
    if (!newRole.name) return
    setBusyAction('create-role')
    try {
      await apiFetch('/api/admin/roles', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newRole) })
      setNewRole({ name: '', description: '', permissions: [] })
      setMessage({ ok: true, text: t('settings.platformRoleCreated') })
      await load()
    } catch (error) {
      setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformSaveFailed') })
    } finally {
      setBusyAction(null)
    }
  }

  const saveRole = async () => {
    if (!selected || selected.is_system) return
    setBusyAction(`save-role:${selected.id}`)
    try {
      await apiFetch(`/api/admin/roles/${selected.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: selected.name, description: selected.description, permissions: selected.permissions }) })
      setMessage({ ok: true, text: t('settings.platformSaved') })
      await load()
    } catch (error) {
      setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformSaveFailed') })
    } finally {
      setBusyAction(null)
    }
  }

  const updateSelected = (update: Partial<PlatformRole>) => setRoles(current => current.map(role => role.id === selectedRole ? { ...role, ...update } : role))

  return (
    <div className="s-section-content s-platform-content" aria-busy={loading || busy}>
      <header className="s-platform-hero">
        <div className="s-platform-hero-icon" aria-hidden="true">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="9" cy="7" r="4"/><path d="M3 21v-2a6 6 0 0 1 12 0v2"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/><path d="M21 21v-2a6 6 0 0 0-4-5.65"/>
          </svg>
        </div>
        <div className="s-platform-hero-copy">
          <span className="s-platform-eyebrow">{t('settings.platformEyebrow')}</span>
          <h2>{t('settings.platformAccess')}</h2>
          <p>{t('settings.platformAccessSubtitle')}</p>
        </div>
        <div className="s-platform-session">
          <span className="s-platform-session-status"><i />{t('settings.platformSessionActive')}</span>
          <strong>{authUser.display_name || authUser.username}</strong>
          <small>@{authUser.username} · {authUser.role}</small>
        </div>
      </header>

      {message && (
        <div className={`s-platform-alert ${message.ok ? 'is-success' : 'is-error'}`} role="status" aria-live="polite">
          <span className="s-platform-alert-icon" aria-hidden="true">{message.ok ? '✓' : '!'}</span>
          <span>{message.text}</span>
          <button type="button" className="s-platform-alert-dismiss" onClick={() => setMessage(null)} aria-label={t('settings.platformDismiss')}>×</button>
        </div>
      )}

      <div className="s-platform-metrics" aria-label={t('settings.platformOverview')}>
        <article className="s-platform-metric s-platform-metric--cyan">
          <span>{t('settings.platformActiveUsers')}</span>
          <strong>{loading && users.length === 0 ? '—' : activeUsers}</strong>
          <small>{t('settings.platformActiveUsersHint')}</small>
        </article>
        <article className="s-platform-metric s-platform-metric--purple">
          <span>{t('settings.platformRoleCount')}</span>
          <strong>{loading && roles.length === 0 ? '—' : roles.length}</strong>
          <small>{t('settings.platformRoleCountHint')}</small>
        </article>
        <article className="s-platform-metric s-platform-metric--blue">
          <span>{t('settings.platformPermissionCount')}</span>
          <strong>{loading && permissions.length === 0 && !authUser.permissions.length ? '—' : permissionCount}</strong>
          <small>{t('settings.platformPermissionCountHint')}</small>
        </article>
      </div>

      <section className="s-platform-card s-platform-card--users">
        <div className="s-platform-card-head">
          <div>
            <span className="s-platform-section-kicker">01 / {t('settings.platformUsers')}</span>
            <h3>{t('settings.platformUsers')}</h3>
            <p>{t('settings.platformUsersDesc')}</p>
          </div>
          <span className="s-platform-card-badge is-cyan">{activeUsers}/{users.length} {t('settings.platformActive')}</span>
        </div>

        <div className="s-platform-create-panel">
          <div className="s-platform-subhead">
            <div>
              <h4>{t('settings.platformCreateUser')}</h4>
              <p>{t('settings.platformCreateUserHint')}</p>
            </div>
            <span className="s-platform-subhead-index">NEW</span>
          </div>
          <div className="s-platform-form-grid s-platform-form-grid--user">
            <label className="s-platform-field">
              <span>{t('settings.platformUsername')}</span>
              <input className="s-input" autoComplete="off" value={newUser.username} onChange={event => setNewUser({ ...newUser, username: event.target.value })} placeholder={t('settings.platformUsernamePlaceholder')} />
            </label>
            <label className="s-platform-field">
              <span>{t('settings.platformDisplayName')}</span>
              <input className="s-input" value={newUser.display_name} onChange={event => setNewUser({ ...newUser, display_name: event.target.value })} placeholder={t('settings.platformDisplayNamePlaceholder')} />
            </label>
            <label className="s-platform-field">
              <span>{t('settings.platformInitialPassword')}</span>
              <input className="s-input" type="password" autoComplete="new-password" value={newUser.password} onChange={event => setNewUser({ ...newUser, password: event.target.value })} placeholder={t('settings.platformPasswordPlaceholder')} />
            </label>
            <label className="s-platform-field">
              <span>{t('settings.platformRole')}</span>
              <select className="s-input" value={newUser.role_id} onChange={event => setNewUser({ ...newUser, role_id: event.target.value })} disabled={!assignableRoles.length}>
                <option value="" disabled>{t('settings.platformSelectRole')}</option>
                {assignableRoles.map(role => <option key={role.id} value={role.id}>{role.name}</option>)}
              </select>
            </label>
          </div>
          <div className="s-platform-form-actions">
            <span>{t('settings.platformPasswordHint')}</span>
            <button type="button" className="s-platform-btn s-platform-btn--primary" onClick={() => void createUser()} disabled={busy || loading || !newUser.username || !newUser.password || !newUser.role_id}>
              <span aria-hidden="true">＋</span>{busyAction === 'create-user' ? t('settings.platformSaving') : t('settings.platformCreateUser')}
            </button>
          </div>
        </div>

        <div className="s-platform-list-head">
          <div>
            <h4>{t('settings.platformUserList')}</h4>
            <span>{t('settings.platformUserListHint')}</span>
          </div>
          <span className="s-platform-count">{users.length}</span>
        </div>

        <div className="s-platform-table-wrap">
          {loading && users.length === 0 ? (
            <div className="s-platform-loading"><span className="s-platform-spinner" />{t('settings.platformLoading')}</div>
          ) : users.length === 0 ? (
            <div className="s-platform-empty"><span className="s-platform-empty-icon">⌁</span><strong>{t('settings.platformNoUsers')}</strong><span>{t('settings.platformNoUsersHint')}</span></div>
          ) : (
            <table className="s-platform-table">
              <thead><tr><th>{t('settings.platformUsername')}</th><th>{t('settings.platformDisplayName')}</th><th>{t('settings.platformRole')}</th><th>{t('settings.platformStatus')}</th><th>{t('settings.platformLastLogin')}</th><th aria-label={t('settings.platformActions')} /></tr></thead>
              <tbody>{users.map(user => {
                const locked = !isAdmin && user.role_id === AUDIT_ROLE_ID
                const saving = busyAction === `save-user:${user.id}`
                const disabling = busyAction === `disable-user:${user.id}`
                return (
                  <tr key={user.id}>
                    <td data-label={t('settings.platformUsername')}>
                      <div className="s-platform-user-cell">
                        <span className="s-platform-avatar">{initials(user.display_name || user.username)}</span>
                        <div><strong>{user.username}</strong><small>{user.id === authUser.id ? t('settings.platformCurrentUser') : user.role}</small></div>
                      </div>
                    </td>
                    <td data-label={t('settings.platformDisplayName')}><input className="s-input" aria-label={`${t('settings.platformDisplayName')} ${user.username}`} value={user.display_name} onChange={event => setUsers(current => current.map(item => item.id === user.id ? { ...item, display_name: event.target.value } : item))} disabled={locked || busy} /></td>
                    <td data-label={t('settings.platformRole')}><select className="s-input" aria-label={`${t('settings.platformRole')} ${user.username}`} disabled={locked || busy} value={user.role_id} onChange={event => setUsers(current => current.map(item => item.id === user.id ? { ...item, role_id: event.target.value } : item))}>{roles.filter(role => isAdmin || role.id !== AUDIT_ROLE_ID || role.id === user.role_id).map(role => <option key={role.id} value={role.id}>{role.name}</option>)}</select></td>
                    <td data-label={t('settings.platformStatus')}>
                      <label className={`s-platform-switch ${user.is_active ? 'is-on' : ''} ${locked || busy ? 'is-disabled' : ''}`}>
                        <input type="checkbox" disabled={locked || busy} checked={user.is_active} onChange={event => setUsers(current => current.map(item => item.id === user.id ? { ...item, is_active: event.target.checked } : item))} />
                        <span className="s-platform-switch-track" aria-hidden="true"><i /></span>
                        <span className="s-platform-status-label">{user.is_active ? t('settings.platformActive') : t('settings.platformDisabled')}</span>
                      </label>
                    </td>
                    <td data-label={t('settings.platformLastLogin')}><span className="s-platform-last-login">{formatLastLogin(user.last_login_at, i18n.language, t('settings.platformNeverLoggedIn'))}</span></td>
                    <td data-label={t('settings.platformActions')}>
                      <div className="s-platform-row-actions">
                        <button type="button" className="s-platform-btn s-platform-btn--quiet" disabled={locked || busy} onClick={() => void saveUser(user)}>{saving ? t('settings.platformSaving') : t('settings.saveChanges')}</button>
                        {user.is_active && <button type="button" className="s-platform-btn s-platform-btn--danger" disabled={locked || busy} onClick={() => void disableUser(user.id)}>{disabling ? t('settings.platformDisabling') : t('settings.platformDisable')}</button>}
                      </div>
                    </td>
                  </tr>
                )
              })}</tbody>
            </table>
          )}
        </div>
      </section>

      {canManageRoles && <section className="s-platform-card s-platform-card--roles">
        <div className="s-platform-card-head">
          <div>
            <span className="s-platform-section-kicker">02 / {t('settings.platformRoles')}</span>
            <h3>{t('settings.platformRoles')}</h3>
            <p>{t('settings.platformRolesDesc')}</p>
          </div>
          <span className="s-platform-card-badge is-purple">{roles.length} {t('settings.platformRoleCount')}</span>
        </div>

        <div className="s-platform-create-panel s-platform-create-panel--role">
          <div className="s-platform-subhead">
            <div><h4>{t('settings.platformCreateRole')}</h4><p>{t('settings.platformCreateRoleHint')}</p></div>
            <span className="s-platform-subhead-index">ROLE</span>
          </div>
          <div className="s-platform-form-grid s-platform-form-grid--role">
            <label className="s-platform-field"><span>{t('settings.platformRoleNameLabel')}</span><input className="s-input" value={newRole.name} onChange={event => setNewRole({ ...newRole, name: event.target.value })} placeholder={t('settings.platformRoleName')} /></label>
            <label className="s-platform-field"><span>{t('settings.platformRoleDescriptionLabel')}</span><input className="s-input" value={newRole.description} onChange={event => setNewRole({ ...newRole, description: event.target.value })} placeholder={t('settings.platformRoleDescription')} /></label>
            <div className="s-platform-form-action"><button type="button" className="s-platform-btn s-platform-btn--primary" onClick={() => void createRole()} disabled={busy || loading || !newRole.name}><span aria-hidden="true">＋</span>{busyAction === 'create-role' ? t('settings.platformSaving') : t('settings.platformCreateRole')}</button></div>
          </div>
        </div>

        {loading && roles.length === 0 ? (
          <div className="s-platform-loading"><span className="s-platform-spinner" />{t('settings.platformLoading')}</div>
        ) : roles.length === 0 ? (
          <div className="s-platform-empty"><span className="s-platform-empty-icon">⌘</span><strong>{t('settings.platformNoRoles')}</strong><span>{t('settings.platformNoRolesHint')}</span></div>
        ) : (
          <div className="s-platform-role-workspace">
            <aside className="s-platform-role-list">
              <div className="s-platform-role-list-head"><span>{t('settings.platformRoleSelect')}</span><strong>{roles.length}</strong></div>
              <div className="s-platform-role-options">
                {roles.map(role => <button key={role.id} type="button" className={`s-platform-role-option ${role.id === selectedRole ? 'is-selected' : ''}`} onClick={() => setSelectedRole(role.id)} aria-pressed={role.id === selectedRole}>
                  <span className="s-platform-role-option-icon">{role.is_system ? '◇' : '○'}</span><span><strong>{role.name}</strong><small>{role.is_system ? t('settings.platformSystemRole') : t('settings.platformCustomRole')}</small></span><b>{role.permissions.length}</b>
                </button>)}
              </div>
            </aside>
            <div className="s-platform-role-editor">
              {selected ? <>
                <div className="s-platform-editor-head"><div><span className="s-platform-section-kicker">{t('settings.platformRoleEditor')}</span><h4>{selected.name}</h4><p>{selected.is_system ? t('settings.platformSystemRoleHint') : t('settings.platformRoleEditorHint')}</p></div><span className="s-platform-permission-count">{t('settings.platformPermissionSelected', { count: selected.permissions.length })}</span></div>
                <div className="s-platform-form-grid s-platform-form-grid--role-editor">
                  <label className="s-platform-field"><span>{t('settings.platformRoleNameLabel')}</span><input className="s-input" value={selected.name} disabled={selected.is_system || busy} onChange={event => updateSelected({ name: event.target.value })} /></label>
                  <label className="s-platform-field"><span>{t('settings.platformRoleDescriptionLabel')}</span><input className="s-input" value={selected.description} disabled={selected.is_system || busy} onChange={event => updateSelected({ description: event.target.value })} /></label>
                </div>
                <div className="s-platform-permission-head"><div><h5>{t('settings.platformPermissionCatalog')}</h5><span>{t('settings.platformRoleEditorHint')}</span></div><code>{selected.permissions.length}/{permissions.length}</code></div>
                <div className="s-platform-permission-grid">{permissions.map(permission => <label key={permission.key} className={`s-platform-permission ${selected.is_system || busy ? 'is-disabled' : ''}`}><input type="checkbox" disabled={selected.is_system || busy} checked={selected.permissions.includes(permission.key)} onChange={event => updateSelected({ permissions: event.target.checked ? [...selected.permissions, permission.key] : selected.permissions.filter(key => key !== permission.key) })} /><span className="s-platform-permission-box" aria-hidden="true">✓</span><span className="s-platform-permission-copy"><strong>{permission.description}</strong><code>{permission.key}</code></span></label>)}</div>
                {!selected.is_system && <div className="s-platform-editor-actions"><span>{t('settings.platformPermissionSelected', { count: selected.permissions.length })}</span><button type="button" className="s-platform-btn s-platform-btn--primary" disabled={busy} onClick={() => void saveRole()}>{busyAction === `save-role:${selected.id}` ? t('settings.platformSaving') : t('settings.platformSaveRole')}</button></div>}
              </> : <div className="s-platform-empty"><strong>{t('settings.platformNoRoles')}</strong><span>{t('settings.platformNoRolesHint')}</span></div>}
            </div>
          </div>
        )}
      </section>}
    </div>
  )
}
