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

async function readApi<T>(path: string): Promise<T> {
  const response = await apiFetch(path)
  const payload = await response.json() as { success?: boolean; data?: T; error?: string }
  if (!payload.success) throw new Error(payload.error || 'request failed')
  return payload.data as T
}

export default function PlatformAccessSettings({ authUser }: { authUser: AuthUser }) {
  const { t } = useTranslation()
  const [users, setUsers] = useState<PlatformUser[]>([])
  const [roles, setRoles] = useState<PlatformRole[]>([])
  const [permissions, setPermissions] = useState<PlatformPermission[]>([])
  const [selectedRole, setSelectedRole] = useState<string>('')
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)
  const [newUser, setNewUser] = useState({ username: '', display_name: '', password: '', role_id: '' })
  const [newRole, setNewRole] = useState({ name: '', description: '', permissions: [] as string[] })
  const canManageRoles = authUser.permissions.includes('platform.roles.manage')

  const load = useCallback(async () => {
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
    setSelectedRole(current => current || loadedRoles[0]?.id || '')
    setNewUser(current => ({ ...current, role_id: current.role_id || loadedRoles.find(role => role.name === 'viewer')?.id || loadedRoles[0]?.id || '' }))
  }, [canManageRoles])

  useEffect(() => { void load().catch(error => setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformLoadFailed') })) }, [load, t])

  const selected = useMemo(() => roles.find(role => role.id === selectedRole), [roles, selectedRole])
  const createUser = async () => {
    try {
      await apiFetch('/api/admin/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newUser) })
      setNewUser(current => ({ ...current, username: '', display_name: '', password: '' }))
      setMessage({ ok: true, text: t('settings.platformSaved') })
      await load()
    } catch (error) { setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformSaveFailed') }) }
  }

  const saveUser = async (user: PlatformUser) => {
    try {
      await apiFetch(`/api/admin/users/${user.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ display_name: user.display_name, role_id: user.role_id, is_active: user.is_active, password: null }) })
      setMessage({ ok: true, text: t('settings.platformSaved') })
      await load()
    } catch (error) { setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformSaveFailed') }) }
  }

  const disableUser = async (id: string) => {
    try {
      await apiFetch(`/api/admin/users/${id}`, { method: 'DELETE' })
      setMessage({ ok: true, text: t('settings.platformSaved') })
      await load()
    } catch (error) { setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformSaveFailed') }) }
  }

  const createRole = async () => {
    try {
      await apiFetch('/api/admin/roles', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newRole) })
      setNewRole({ name: '', description: '', permissions: [] })
      setMessage({ ok: true, text: t('settings.platformSaved') })
      await load()
    } catch (error) { setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformSaveFailed') }) }
  }

  const saveRole = async () => {
    if (!selected || selected.is_system) return
    try {
      await apiFetch(`/api/admin/roles/${selected.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: selected.name, description: selected.description, permissions: selected.permissions }) })
      setMessage({ ok: true, text: t('settings.platformSaved') })
      await load()
    } catch (error) { setMessage({ ok: false, text: error instanceof Error ? error.message : t('settings.platformSaveFailed') }) }
  }

  const updateSelected = (update: Partial<PlatformRole>) => setRoles(current => current.map(role => role.id === selectedRole ? { ...role, ...update } : role))

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row"><span className="s-section-icon account">⌘</span>{t('settings.platformAccess')}</h2>
        <p className="s-section-subtitle">{t('settings.platformAccessSubtitle')}</p>
      </div>
      {message && <div className={`s-alert ${message.ok ? 'success' : 'error'} in-form`} role="status">{message.text}</div>}

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.platformUsers')}</div>
        <div className="s-form-grid" style={{ gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}>
          <input className="s-input" placeholder={t('settings.platformUsername')} value={newUser.username} onChange={event => setNewUser({ ...newUser, username: event.target.value })} />
          <input className="s-input" placeholder={t('settings.platformDisplayName')} value={newUser.display_name} onChange={event => setNewUser({ ...newUser, display_name: event.target.value })} />
          <input className="s-input" type="password" placeholder={t('settings.platformInitialPassword')} value={newUser.password} onChange={event => setNewUser({ ...newUser, password: event.target.value })} />
          <select className="s-input" value={newUser.role_id} onChange={event => setNewUser({ ...newUser, role_id: event.target.value })}>{roles.map(role => <option key={role.id} value={role.id}>{role.name}</option>)}</select>
        </div>
        <button type="button" className="s-btn primary" onClick={() => void createUser()} disabled={!newUser.username || !newUser.password}>{t('settings.platformCreateUser')}</button>
        <div style={{ overflowX: 'auto', marginTop: 18 }}>
          <table className="s-data-table"><thead><tr><th>{t('settings.platformUsername')}</th><th>{t('settings.platformDisplayName')}</th><th>{t('settings.platformRole')}</th><th>{t('settings.platformStatus')}</th><th /></tr></thead>
            <tbody>{users.map(user => <tr key={user.id}>
              <td>{user.username}{user.id === authUser.id && <small> ({t('settings.platformCurrentUser')})</small>}</td>
              <td><input className="s-input" value={user.display_name} onChange={event => setUsers(current => current.map(item => item.id === user.id ? { ...item, display_name: event.target.value } : item))} /></td>
              <td><select className="s-input" value={user.role_id} onChange={event => setUsers(current => current.map(item => item.id === user.id ? { ...item, role_id: event.target.value } : item))}>{roles.map(role => <option key={role.id} value={role.id}>{role.name}</option>)}</select></td>
              <td><label><input type="checkbox" checked={user.is_active} onChange={event => setUsers(current => current.map(item => item.id === user.id ? { ...item, is_active: event.target.checked } : item))} /> {user.is_active ? t('settings.platformActive') : t('settings.platformDisabled')}</label></td>
              <td><button type="button" className="s-btn" onClick={() => void saveUser(user)}>{t('settings.saveChanges')}</button>{user.is_active && <button type="button" className="s-btn danger" onClick={() => void disableUser(user.id)}>{t('settings.platformDisable')}</button>}</td>
            </tr>)}</tbody>
          </table>
        </div>
      </div>

      {canManageRoles && <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.platformRoles')}</div>
        <div className="s-form-grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}>
          <input className="s-input" placeholder={t('settings.platformRoleName')} value={newRole.name} onChange={event => setNewRole({ ...newRole, name: event.target.value })} />
          <input className="s-input" placeholder={t('settings.platformRoleDescription')} value={newRole.description} onChange={event => setNewRole({ ...newRole, description: event.target.value })} />
          <button type="button" className="s-btn primary" onClick={() => void createRole()} disabled={!newRole.name}>{t('settings.platformCreateRole')}</button>
        </div>
        <select className="s-input" style={{ marginTop: 14 }} value={selectedRole} onChange={event => setSelectedRole(event.target.value)}>{roles.map(role => <option key={role.id} value={role.id}>{role.name}{role.is_system ? ` (${t('settings.platformSystemRole')})` : ''}</option>)}</select>
        {selected && <>
          <input className="s-input" style={{ marginTop: 10 }} value={selected.description} disabled={selected.is_system} onChange={event => updateSelected({ description: event.target.value })} />
          <div className="s-permission-grid">{permissions.map(permission => <label key={permission.key}><input type="checkbox" disabled={selected.is_system} checked={selected.permissions.includes(permission.key)} onChange={event => updateSelected({ permissions: event.target.checked ? [...selected.permissions, permission.key] : selected.permissions.filter(key => key !== permission.key) })} /> <span>{permission.description}</span><small>{permission.key}</small></label>)}</div>
          {!selected.is_system && <button type="button" className="s-btn primary" onClick={() => void saveRole()}>{t('settings.platformSaveRole')}</button>}
        </>}
      </div>}
    </div>
  )
}
