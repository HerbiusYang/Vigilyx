/**
 * Centralized custom window event names.
 * All vigilyx:* events used for cross-component communication are defined here.
 * This prevents typos in event names from causing silent failures.
 */
export const EVENTS = {
  /** Triggers dashboard/traffic/data-security data refresh */
  DASHBOARD_REFRESH: 'vigilyx:dashboard-refresh',
  /** Fired when WebSocket reconnects after a disconnection */
  WS_RECONNECTED: 'vigilyx:ws-reconnected',
  /** Carries real-time stats update payload */
  STATS_UPDATE: 'vigilyx:stats-update',
  /** Notifies WS connection state change */
  CONNECTION_CHANGE: 'vigilyx:connection-change',
  /** Fired when display settings (column visibility, etc.) change */
  DISPLAY_SETTINGS_CHANGED: 'vigilyx:display-settings-changed',
  /** Fired when UI preferences (theme, etc.) change */
  UI_PREFERENCES_CHANGED: 'vigilyx:ui-preferences-changed',
  /** Fired when deployment mode changes (mirror/mta) */
  DEPLOY_MODE_CHANGED: 'vigilyx:deploy-mode-changed',
  /** Navigate to a specific settings tab */
  NAVIGATE_SETTINGS: 'vigilyx:navigate-settings',
  /** Fired after database stats/data is cleared */
  STATS_CLEARED: 'vigilyx:stats-cleared',
} as const;
