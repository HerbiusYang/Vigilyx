import { useTranslation } from 'react-i18next'
import { DATA_SECURITY_LEVEL_COLOR, FINANCIAL_POLICY } from './constants'

export function PolicyTab() {
  const { t } = useTranslation()
  const fields = Object.entries(FINANCIAL_POLICY.field_levels)
  return (
    <div className="ds3-policy">
      <div className="pol-hero">
        <div className="pol-hero-left">
          <div className="pol-hero-badge">JR/T 0197-2020 · JR/T 0171-2020</div>
          <h2 className="pol-hero-title">{t('dataSecurity.financialPolicyTitle')}</h2>
          <p className="pol-hero-sub">{t('dataSecurity.financialPolicySubtitle')}</p>
        </div>
        <div className="pol-hero-params">
          <div className="pol-hero-param"><span className="pol-hero-param-val sec-mono">{FINANCIAL_POLICY.single_event_min_items}</span><span className="pol-hero-param-label">{t('dataSecurity.singleItemAlert')}</span></div>
        </div>
      </div>
      <div className="pol-thresh-row">
        {[{ level: 4, severity: 'Critical', key: 'singleAuthRisk' }, { level: 3, severity: 'High', key: 'singleSensitiveRisk' }].map(rule => (
          <div className="pol-thresh" key={rule.level} style={{ '--c': DATA_SECURITY_LEVEL_COLOR[rule.level] } as React.CSSProperties}>
            <div className="pol-thresh-head"><span className="pol-thresh-badge">{t(`dataSecurity.${rule.key}`)}</span><span className="pol-thresh-arrow">→</span><span className="pol-thresh-result">{rule.severity}</span></div>
            <div className="pol-thresh-body"><div className="pol-thresh-num sec-mono">≥{FINANCIAL_POLICY.single_event_min_items}<span className="pol-thresh-unit">{t('dataSecurity.protectedItem')}</span></div><div className="pol-thresh-desc">{t('dataSecurity.singleTransferScope')}</div></div>
            <div className="pol-thresh-tags">{fields.filter(([, level]) => level === rule.level).map(([name]) => <span className="pol-tag" key={name}>{t(`dataSecurity.dlpMatch_${name}`)}</span>)}</div>
          </div>
        ))}
      </div>
      <div className="pol-tower">
        <div className="pol-tower-title">{t('dataSecurity.candidateClassification')}</div>
        <p className="pol-detect-desc">{t('dataSecurity.classificationBoundary')}</p>
        {[5, 4, 3, 2, 1].map(level => (
          <div className="pol-tower-row" key={level}>
            <div className="pol-tower-side" style={{ borderRight: `3px solid ${DATA_SECURITY_LEVEL_COLOR[level]}` }}><span className="sec-mono" style={{ color: DATA_SECURITY_LEVEL_COLOR[level] }}>{t('dataSecurity.levelNumber', { level })}</span></div>
            <div className="pol-tower-main"><span className="pol-tower-desc">{t(`dataSecurity.candidateLevel${level}`)}</span><div className="pol-tower-tags">{fields.filter(([, value]) => value === level).map(([name]) => <span className="pol-tag" key={name}>{t(`dataSecurity.dlpMatch_${name}`)}</span>)}</div></div>
          </div>
        ))}
      </div>
      <div className="pol-detect">
        <div className="pol-detect-title">{t('dataSecurity.bulkEscalationTitle')}</div>
        <p className="pol-detect-desc">{t('dataSecurity.bulkEscalationDesc', { hours: FINANCIAL_POLICY.bulk_window_hours, high: FINANCIAL_POLICY.bulk_high_sensitive_items, sensitive: FINANCIAL_POLICY.bulk_sensitive_items, cooldown: FINANCIAL_POLICY.bulk_cooldown_minutes })}</p>
        <div className="pol-detect-grid">
          {['submission', 'draft', 'publicReference'].map(key => <div className="pol-detect-lane" key={key}><div className="pol-detect-head">{t(`dataSecurity.policyScenario_${key}`)}</div><p className="pol-detect-desc">{t(`dataSecurity.policyScenarioDesc_${key}`)}</p></div>)}
        </div>
        <p className="pol-detect-footer">{t('dataSecurity.authorizationPolicyNotice')}</p>
      </div>
      <div className="pol-aux-row">
        <div className="pol-aux"><div><strong>{t('dataSecurity.regulatoryRequirements')}</strong><p>{t('dataSecurity.regulatoryRequirementsDesc')}</p><a href="https://app.www.gov.cn/govdata/gov/202412/29/523120/article.html" target="_blank" rel="noreferrer">{t('dataSecurity.bankInsuranceRules')}</a></div></div>
        <div className="pol-aux"><div><strong>{t('dataSecurity.observationBoundary')}</strong><p>{t('dataSecurity.observationBoundaryDesc')}</p></div></div>
      </div>
    </div>
  )
}
