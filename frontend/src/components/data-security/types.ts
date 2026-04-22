export type TabKey = 'overview' | 'policy' | 'incidents' | 'http-sessions' | 'settings'

export type SyslogConfig = {
  enabled: boolean
  server_address: string
  port: number
  protocol: string
  facility: number
  format: string
  min_severity: string
}

export type TimePolicyConfig = {
  enabled: boolean
  work_hour_start: number
  work_hour_end: number
  utc_offset_hours: number
  weekend_is_off_hours: boolean
}
