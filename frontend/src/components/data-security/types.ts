export type TabKey = 'overview' | 'outbound-emails' | 'incidents' | 'http-sessions' | 'policy' | 'privacy' | 'settings'

export type SyslogConfig = {
  enabled: boolean
  server_address: string
  port: number
  protocol: string
  facility: number
  format: string
  min_severity: string
}
