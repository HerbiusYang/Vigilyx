import { useTranslation } from 'react-i18next'
import { INCIDENT_TYPE_ICON } from './constants'

export function PolicyTab() {
  const { t } = useTranslation()
  return (
    <div className="ds3-policy">
      {/* 1) Top hero - large title + 3 parameters */}
      <div className="pol-hero">
        <div className="pol-hero-left">
          <div className="pol-hero-badge">JR/T 0197-2020</div>
          <h2 className="pol-hero-title">{t('dataSecurity.policyTitle')}</h2>
          <p className="pol-hero-sub">{t('dataSecurity.policySubtitle')}</p>
        </div>
        <div className="pol-hero-params">
          {[['24h', t('dataSecurity.complianceWindow')], ['30m/1h', t('dataSecurity.coolingPeriod')], [t('dataSecurity.userIp'), t('dataSecurity.independentTracking')]].map(([v, l]) => (
            <div key={l} className="pol-hero-param">
              <span className="pol-hero-param-val sec-mono">{v}</span>
              <span className="pol-hero-param-label">{l}</span>
            </div>
          ))}
        </div>
      </div>

      {/* 2) Compliance thresholds - 2 large cards */}
      <div className="pol-thresh-row">
        {[
          { level: 'C4', label: t('dataSecurity.highSensitive'), color: '#ef4444', num: 50, result: 'Critical', desc: t('dataSecurity.c4Desc'), items: [t('dataSecurity.dlpMatch_credential_leak'), t('dataSecurity.dlpMatch_cvv_code'), t('dataSecurity.dlpMatch_credit_card'), t('dataSecurity.dlpMatch_biometric_data'), t('dataSecurity.dlpMatch_medical_health')] },
          { level: 'C3', label: t('dataSecurity.sensitive'), color: '#f97316', num: 500, result: 'High', desc: t('dataSecurity.c3Desc'), items: [t('dataSecurity.dlpMatch_id_number'), t('dataSecurity.dlpMatch_phone_number'), t('dataSecurity.dlpMatch_bank_card'), t('dataSecurity.dlpMatch_customer_address'), t('dataSecurity.dlpMatch_passport_number'), t('dataSecurity.dlpMatch_iban'), t('dataSecurity.dlpMatch_large_amount'), t('dataSecurity.dlpMatch_contract_number'), t('dataSecurity.dlpMatch_vehicle_info'), t('dataSecurity.dlpMatch_property_info'), t('dataSecurity.dlpMatch_income_info'), t('dataSecurity.dlpMatch_geo_location'), t('dataSecurity.dlpMatch_otp_verification'), t('dataSecurity.dlpMatch_loan_credit_info'), t('dataSecurity.dlpMatch_insurance_policy'), t('dataSecurity.dlpMatch_family_relation')] },
        ].map(t2 => (
          <div key={t2.level} className="pol-thresh" style={{ '--c': t2.color } as React.CSSProperties}>
            <div className="pol-thresh-head">
              <span className="pol-thresh-badge" style={{ background: t2.color + '18', color: t2.color }}>{t2.level} {t2.label}</span>
              <span className="pol-thresh-arrow">→</span>
              <span className="pol-thresh-result" style={{ color: t2.color }}>{t2.result}</span>
            </div>
            <div className="pol-thresh-body">
              <div className="pol-thresh-num sec-mono" style={{ color: t2.color }}>{t2.num}<span className="pol-thresh-unit">{t('dataSecurity.itemsPer24h')}</span></div>
              <div className="pol-thresh-desc">{t2.desc}</div>
            </div>
            <div className="pol-thresh-tags">
              {t2.items.map(i => <span key={i} className="pol-tag" style={{ background: t2.color + '0c', color: t2.color, borderColor: t2.color + '22' }}>{i}</span>)}
            </div>
          </div>
        ))}
      </div>

      {/* 3) Data classification tower - 4 layers from red to green */}
      <div className="pol-tower">
        <div className="pol-tower-title">{t('dataSecurity.dataClassificationTitle')}</div>
        {[
          { level: 4, label: t('dataSecurity.classHighSensitive'), color: '#ef4444', desc: t('dataSecurity.c4Desc'), items: [t('dataSecurity.dlpMatch_credential_leak'), t('dataSecurity.dlpMatch_cvv_code'), t('dataSecurity.dlpMatch_credit_card'), t('dataSecurity.dlpMatch_biometric_data'), t('dataSecurity.dlpMatch_medical_health')] },
          { level: 3, label: t('dataSecurity.classSensitive'), color: '#f97316', desc: t('dataSecurity.c3DescFull'), items: [t('dataSecurity.dlpMatch_id_number'), t('dataSecurity.dlpMatch_phone_number'), t('dataSecurity.dlpMatch_bank_card'), t('dataSecurity.dlpMatch_customer_address'), t('dataSecurity.dlpMatch_passport_number'), t('dataSecurity.dlpMatch_iban'), t('dataSecurity.dlpMatch_large_amount'), t('dataSecurity.dlpMatch_bank_account_context'), t('dataSecurity.dlpMatch_contract_number'), t('dataSecurity.dlpMatch_vehicle_info'), t('dataSecurity.dlpMatch_property_info'), t('dataSecurity.dlpMatch_income_info'), t('dataSecurity.dlpMatch_geo_location'), t('dataSecurity.dlpMatch_otp_verification'), t('dataSecurity.dlpMatch_loan_credit_info'), t('dataSecurity.dlpMatch_insurance_policy'), t('dataSecurity.dlpMatch_family_relation')] },
          { level: 2, label: t('dataSecurity.classInternal'), color: '#eab308', desc: t('dataSecurity.c2Desc'), items: [t('dataSecurity.dlpMatch_swift_code'), t('dataSecurity.dlpMatch_tax_id'), t('dataSecurity.dlpMatch_employee_info'), t('dataSecurity.dlpMatch_judicial_record'), t('dataSecurity.dlpMatch_education_info'), t('dataSecurity.dlpMatch_business_license')] },
          { level: 1, label: t('dataSecurity.classPublic'), color: '#22c55e', desc: t('dataSecurity.c1Desc'), items: [t('dataSecurity.dlpMatch_social_credit_code')] },
        ].map(r => (
          <div key={r.level} className="pol-tower-row">
            <div className="pol-tower-side" style={{ background: r.color + '08', borderRight: `3px solid ${r.color}` }}>
              <span className="sec-mono" style={{ fontSize: 18, fontWeight: 800, color: r.color }}>C{r.level}</span>
              <span style={{ fontSize: 11, color: r.color, fontWeight: 600 }}>{r.label}</span>
            </div>
            <div className="pol-tower-main">
              <span className="pol-tower-desc">{r.desc}</span>
              <div className="pol-tower-tags">
                {r.items.map(i => <span key={i} className="pol-tag" style={{ background: r.color + '0c', color: r.color, borderColor: r.color + '1a' }}>{i}</span>)}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 4) Detection scenarios - 3 columns */}
      <div className="pol-detect">
        <div className="pol-detect-title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
          {t('dataSecurity.complianceDetectionSystem')}
        </div>
        <div className="pol-detect-grid">
          {[
            { icon: INCIDENT_TYPE_ICON.draft_box_abuse, color: '#a855f7', title: t('dataSecurity.draftBoxRisk'), desc: t('dataSecurity.draftBoxRiskDesc'), trigger: t('dataSecurity.draftBoxTrigger'), output: t('dataSecurity.draftBoxOutput') },
            { icon: INCIDENT_TYPE_ICON.file_transit_abuse, color: '#3b82f6', title: t('dataSecurity.fileTransitRisk'), desc: t('dataSecurity.fileTransitRiskDesc'), trigger: t('dataSecurity.fileTransitTrigger'), output: t('dataSecurity.fileTransitOutput') },
            { icon: INCIDENT_TYPE_ICON.self_sending, color: '#f97316', title: t('dataSecurity.selfSendRisk'), desc: t('dataSecurity.selfSendRiskDesc'), trigger: t('dataSecurity.selfSendTrigger'), output: t('dataSecurity.selfSendOutput') },
          ].map((s, idx) => (
            <div key={idx} className="pol-detect-lane">
              <div className="pol-detect-head" style={{ color: s.color }}>
                <span style={{ width: 32, height: 32, borderRadius: 8, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', background: s.color + '12' }}>{s.icon}</span>
                <span style={{ fontSize: 15, fontWeight: 700 }}>{s.title}</span>
              </div>
              <p className="pol-detect-desc">{s.desc}</p>
              <div className="pol-detect-rule">
                <div className="pol-detect-label">{t('dataSecurity.trigger')}</div>
                <div className="pol-detect-value">{s.trigger}</div>
              </div>
              <div className="pol-detect-rule">
                <div className="pol-detect-label">{t('dataSecurity.output')}</div>
                <div className="pol-detect-value" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{s.output}</div>
              </div>
            </div>
          ))}
        </div>
        <div className="pol-detect-footer">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
          JR/T 0197-2020 {t('dataSecurity.complianceTracking')} — <strong style={{ color: '#ef4444' }}>C4 {t('dataSecurity.highSensitive')} ≥50 {t('dataSecurity.itemsPer24h')} → Critical</strong>，<strong style={{ color: '#f97316' }}>C3+ {t('dataSecurity.sensitive')} ≥500 {t('dataSecurity.itemsPer24h')} → High</strong>（{t('dataSecurity.perUserIpCooling')}）
        </div>
      </div>

      {/* 5) Supporting policies - 2 columns */}
      <div className="pol-aux-row">
        {[
          { emoji: '🌙', bg: 'rgba(168,85,247,.1)', title: t('dataSecurity.offHoursWeighting'), desc: t('dataSecurity.offHoursWeightingPolicyDesc'), chips: [['Medium', '#f97316', 'High'], ['High', '#ef4444', 'Critical']] },
          { emoji: '⚡', bg: 'rgba(249,115,22,.1)', title: t('dataSecurity.batchAnomalyDetection'), desc: t('dataSecurity.batchAnomalyDesc'), chips: [[t('dataSecurity.gte5times'), '#eab308', t('dataSecurity.severity_medium')], [t('dataSecurity.gte10times'), '#f97316', t('dataSecurity.severity_high')], [t('dataSecurity.gte15times'), '#ef4444', t('dataSecurity.severity_critical')]] },
        ].map(a => (
          <div key={a.title} className="pol-aux">
            <div style={{ width: 40, height: 40, borderRadius: 10, background: a.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20, flexShrink: 0 }}>{a.emoji}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>{a.title}</div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 8 }}>{a.desc}</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {a.chips.map(([from, color, to]) => (
                  <span key={from} className="ds3-aux-chip">{from} → <b style={{ color: color as string }}>{to}</b></span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
