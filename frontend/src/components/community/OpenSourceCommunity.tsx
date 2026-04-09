import { useState } from 'react'

type TabKey = 'mission' | 'roadmap' | 'finance' | 'intel'

const TABS: { key: TabKey; label: string; icon: JSX.Element }[] = [
  { key: 'mission', label: '开源使命', icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg> },
  { key: 'roadmap', label: '路线图', icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> },
  { key: 'finance', label: '资金明细', icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg> },
  { key: 'intel', label: '共享情报', icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> },
]

// -- Open-source roadmap --
const OPEN_SOURCE_ROADMAP: { phase: string; title: string; status: 'done' | 'current' | 'planned'; date: string; items: string[] }[] = [
  { phase: 'v0.9.0', title: '核心引擎发布测试', status: 'current' as const, date: '2026 Q1',
    items: ['邮件协议解析器 (SMTP / POP3 / IMAP)', '20 模块威胁检测流水线', 'DS-Murphy 证据融合算法', 'YARA 规则引擎 (50 条规则)', 'ClamAV 病毒签名集成'] },
  { phase: 'v1.0.0', title: '正式开源发布', status: 'planned' as const, date: '2026 Q2',
    items: ['收敛断路器与多信号融合调优', '误报自动闭环反馈机制', '零宽字符 / HTML 实体编码防御', 'IDN 同形攻击检测'] },
  { phase: 'v1.x.x', title: '情报共享网络', status: 'planned' as const, date: '2026 Q3',
    items: ['社区 IOC 情报订阅 / 发布 API', '匿名化威胁样本投递通道', '跨组织 TLP 情报交换协议', '社区 YARA 规则市场'] },
]

// -- Commercial roadmap (tentative, still planning) --
const COMMERCIAL_ROADMAP = [
  { phase: 'Pro', title: '高级 AI 模型', status: 'planned' as const, date: '待定',
    items: ['Fine-tuned 钓鱼检测 NLP 模型', 'Claude / GPT 深度语义分析', '多模态分析 (图片/PDF/QR 码)', '上下文感知智能研判'] },
  { phase: 'Enterprise', title: '企业级功能', status: 'planned' as const, date: '待定',
    items: ['多租户架构与权限隔离', '合规报告生成器 (等保/PCI-DSS)', '高级仪表盘与自定义看板', 'SOAR 自动化编排增强'] },
  { phase: 'Cloud', title: '云端服务', status: 'planned' as const, date: '待定',
    items: ['SaaS 托管部署方案', '全球威胁情报实时同步', '7×24 技术支持与 SLA', '联邦学习 — 隐私安全模型训练'] },
]

// -- Funding allocation breakdown --
const FINANCE_ITEMS = [
  { category: '公益事业', pct: 80, items: ['帮助弱势群体与困难家庭', '乡村教育与助学支持', '公益慈善机构捐赠', '社会福利与救助项目'], color: '#10b981', icon: '💚' },
  { category: '项目发展', pct: 10, items: ['AI 模型训练与 GPU 算力', '服务器、CI/CD 与基础设施运维', 'Claude / GPT API 调用成本', '开源依赖与工具链维护'], color: '#3b82f6', icon: '⚡' },
  { category: '团队招募', pct: 10, items: ['安全研究员招募与激励', '开源贡献者奖金计划', '社区运营与技术布道'], color: '#a855f7', icon: '🤝' },
]

// -- Threat-intel sharing channels --
const INTEL_FEEDS = [
  { name: 'Vigilyx IOC Feed', type: 'STIX/TAXII', desc: '社区共建的邮件威胁 IOC 情报源，包含恶意发件人、钓鱼域名、恶意 IP 等', status: 'planned', subscribers: 0 },
  { name: 'YARA 规则订阅', type: 'YARA Rules', desc: '社区贡献的 YARA 检测规则，每周更新，覆盖最新恶意软件家族和钓鱼手法', status: 'planned', subscribers: 0 },
  { name: '钓鱼样本库', type: 'Samples', desc: '匿名化处理后的钓鱼邮件样本，供安全研究和模型训练使用', status: 'planned', subscribers: 0 },
  { name: '威胁分析报告', type: 'Reports', desc: '社区安全研究员撰写的邮件威胁分析报告和应急响应指南', status: 'planned', subscribers: 0 },
]

export default function OpenSourceCommunity() {
  const [activeTab, setActiveTab] = useState<TabKey>('mission')

  return (
    <div className="osc-page">
      {/* -- Page header -- */}
      <div className="osc-hero">
        <div className="osc-hero-content">
          <div className="osc-hero-badge">OPEN SOURCE</div>
          <h1 className="osc-hero-title">Vigilyx 开源社区</h1>
          <p className="osc-hero-desc">
            构建开放、协作、共享的邮件安全防御生态。
            <br />
            让每一个组织都能获得企业级的邮件威胁检测能力。
          </p>
          <div className="osc-hero-stats">
            <div className="osc-hero-stat">
              <span className="osc-hero-stat-val">20</span>
              <span className="osc-hero-stat-lbl">检测模块</span>
            </div>
            <div className="osc-hero-stat-sep" />
            <div className="osc-hero-stat">
              <span className="osc-hero-stat-val">50</span>
              <span className="osc-hero-stat-lbl">YARA 规则</span>
            </div>
            <div className="osc-hero-stat-sep" />
            <div className="osc-hero-stat">
              <span className="osc-hero-stat-val">AGPL-3.0</span>
              <span className="osc-hero-stat-lbl">许可证</span>
            </div>
          </div>
        </div>
      </div>

      {/* -- Tab navigation -- */}
      <div className="osc-tabs">
        {TABS.map(t => (
          <button key={t.key} className={`osc-tab ${activeTab === t.key ? 'osc-tab--active' : ''}`} onClick={() => setActiveTab(t.key)}>
            {t.icon}
            <span>{t.label}</span>
          </button>
        ))}
      </div>

      {/* -- Open-source mission -- */}
      {activeTab === 'mission' && (
        <div className="osc-section osc-fade-in">
          <div className="osc-mission-grid">
            {[
              { title: '安全平权', desc: '邮件安全不应是大企业的专属。我们将 20 模块检测流水线、DS-Murphy 融合算法、AI 辅助分析完全开源，让中小型组织也能部署企业级邮件威胁检测。', icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>, color: '#3b82f6' },
              { title: '协作防御', desc: '单点防御永远不够。通过社区 IOC 情报共享、YARA 规则市场、威胁样本交换，构建集体免疫网络——一个节点发现威胁，所有节点同步防御。', icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>, color: '#10b981' },
              { title: '透明可审计', desc: '安全产品的代码应该是可审计的。完整公开检测逻辑、融合算法、判定阈值，让每一个安全决策都可追溯、可解释、可验证。', icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>, color: '#f59e0b' },
              { title: '持续演进', desc: '威胁在进化，防御也必须。社区驱动的 YARA 规则更新、NLP 模型迭代、新攻击手法检测，确保防御能力始终跟上攻击者的步伐。', icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>, color: '#a855f7' },
            ].map((item, i) => (
              <div key={i} className="osc-mission-card" style={{ '--osc-color': item.color } as React.CSSProperties}>
                <div className="osc-mission-icon" style={{ color: item.color }}>{item.icon}</div>
                <h3 className="osc-mission-title">{item.title}</h3>
                <p className="osc-mission-desc">{item.desc}</p>
              </div>
            ))}
          </div>

          <div className="osc-cta-row">
            <div className="osc-cta-card">
              <div className="osc-cta-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>
              </div>
              <div>
                <div className="osc-cta-title">GitHub 仓库</div>
                <div className="osc-cta-desc">Star、Fork、Issue、PR — 一切从这里开始</div>
              </div>
              <span className="osc-cta-badge">即将公开</span>
            </div>
            <div className="osc-cta-card">
              <div className="osc-cta-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
              </div>
              <div>
                <div className="osc-cta-title">社区讨论</div>
                <div className="osc-cta-desc">技术交流、功能建议、威胁情报分享</div>
              </div>
              <span className="osc-cta-badge">即将开放</span>
            </div>
          </div>
        </div>
      )}

      {/* -- Roadmap -- */}
      {activeTab === 'roadmap' && (
        <div className="osc-section osc-fade-in">
          <div className="osc-roadmap-dual">
            {/* Open-source track */}
            <div className="osc-track">
              <div className="osc-track-header osc-track-header--oss">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                <span className="osc-track-label">开源路线</span>
                <span className="osc-track-badge osc-track-badge--oss">FREE & OPEN</span>
              </div>
              <div className="osc-track-body">
                {OPEN_SOURCE_ROADMAP.map((m, i) => (
                  <div key={i} className={`osc-rm-card osc-rm-card--${m.status}`} style={{ '--rm-color': m.status === 'done' ? '#10b981' : m.status === 'current' ? '#3b82f6' : 'var(--text-tertiary)' } as React.CSSProperties}>
                    <div className="osc-rm-card-top">
                      <span className="osc-rm-phase">{m.phase}</span>
                      <span className="osc-rm-date">{m.date}</span>
                      <span className={`osc-rm-status osc-rm-status--${m.status}`}>
                        {m.status === 'done' ? '已完成' : m.status === 'current' ? '进行中' : '计划中'}
                      </span>
                    </div>
                    <h4 className="osc-rm-title">{m.title}</h4>
                    <ul className="osc-rm-list">
                      {m.items.map((item, j) => (
                        <li key={j}>
                          {m.status === 'done' ? (
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                          ) : m.status === 'current' ? (
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><circle cx="12" cy="12" r="5" fill="#3b82f6" fillOpacity="0.15"/></svg>
                          ) : (
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="2"><circle cx="12" cy="12" r="4"/></svg>
                          )}
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>

            {/* Commercial track */}
            <div className="osc-track">
              <div className="osc-track-header osc-track-header--biz">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
                <span className="osc-track-label">商业路线</span>
                <span className="osc-track-badge osc-track-badge--biz">PRO / ENTERPRISE</span>
              </div>
              <div className="osc-track-body">
                {COMMERCIAL_ROADMAP.map((m, i) => (
                  <div key={i} className={`osc-rm-card osc-rm-card--planned`} style={{ '--rm-color': 'var(--text-tertiary)' } as React.CSSProperties}>
                    <div className="osc-rm-card-top">
                      <span className="osc-rm-phase">{m.phase}</span>
                      <span className="osc-rm-date">{m.date}</span>
                      <span className="osc-rm-status osc-rm-status--planned">规划中</span>
                    </div>
                    <h4 className="osc-rm-title">{m.title}</h4>
                    <ul className="osc-rm-list">
                      {m.items.map((item, j) => (
                        <li key={j}>
                          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="2"><circle cx="12" cy="12" r="4"/></svg>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* -- Funding breakdown -- */}
      {activeTab === 'finance' && (
        <div className="osc-section osc-fade-in">
          <div className="osc-finance-notice">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
            <span>我们承诺将所获资金的绝大部分回馈社会。以下是资金分配计划，所有明细将公开透明、可审计。</span>
          </div>

          {/* Allocation-ratio visualization */}
          <div className="osc-finance-bar">
            {FINANCE_ITEMS.map((item, i) => (
              <div key={i} className="osc-finance-bar-seg" style={{ flex: item.pct, background: item.color }} title={`${item.category} ${item.pct}%`} />
            ))}
          </div>
          <div className="osc-finance-bar-labels">
            {FINANCE_ITEMS.map((item, i) => (
              <span key={i} style={{ flex: item.pct, color: item.color, textAlign: 'center', fontSize: 10, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{item.pct}%</span>
            ))}
          </div>

          <div className="osc-finance-cards">
            {FINANCE_ITEMS.map((item, i) => (
              <div key={i} className="osc-finance-card" style={{ '--osc-color': item.color } as React.CSSProperties}>
                <div className="osc-finance-card-head">
                  <span className="osc-finance-emoji">{item.icon}</span>
                  <div className="osc-finance-card-title">
                    <span className="osc-finance-cat">{item.category}</span>
                    <span className="osc-finance-pct" style={{ color: item.color }}>{item.pct}%</span>
                  </div>
                </div>
                <ul className="osc-finance-list">
                  {item.items.map((sub, j) => (
                    <li key={j} className="osc-finance-list-item">
                      <span className="osc-finance-bullet" style={{ background: item.color }} />
                      {sub}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <div className="osc-finance-footer">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span>资金使用明细将在本页面公开展示，接受社区监督与审计。</span>
          </div>
        </div>
      )}

      {/* -- Shared intel -- */}
      {activeTab === 'intel' && (
        <div className="osc-section osc-fade-in">
          <div className="osc-intel-intro">
            <h3>威胁情报共享网络</h3>
            <p>社区驱动的情报交换机制：一个节点发现威胁，所有节点同步防御。遵循 TLP（Traffic Light Protocol）标准，保护敏感信息。</p>
          </div>

          <div className="osc-intel-grid">
            {INTEL_FEEDS.map((feed, i) => (
              <div key={i} className="osc-intel-card">
                <div className="osc-intel-card-head">
                  <span className="osc-intel-name">{feed.name}</span>
                  <span className={`osc-intel-status osc-intel-status--${feed.status}`}>
                    {feed.status === 'active' ? '运行中' : feed.status === 'beta' ? '测试中' : '计划中'}
                  </span>
                </div>
                <span className="osc-intel-type">{feed.type}</span>
                <p className="osc-intel-desc">{feed.desc}</p>
                <div className="osc-intel-footer">
                  <span className="osc-intel-sub">
                    {feed.status === 'planned' ? '即将上线' : `${feed.subscribers} 订阅者`}
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div className="osc-intel-tlp">
            <h4 className="osc-intel-tlp-title">TLP 标签说明</h4>
            <div className="osc-intel-tlp-grid">
              {[
                { color: '#dc2626', label: 'TLP:RED', desc: '仅限特定接收方，不可转发' },
                { color: '#f59e0b', label: 'TLP:AMBER', desc: '限组织内部和必要合作方' },
                { color: '#10b981', label: 'TLP:GREEN', desc: '可在社区内共享' },
                { color: '#e2e8f0', label: 'TLP:CLEAR', desc: '可公开发布' },
              ].map((tlp, i) => (
                <div key={i} className="osc-intel-tlp-item">
                  <span className="osc-intel-tlp-dot" style={{ background: tlp.color }} />
                  <span className="osc-intel-tlp-label">{tlp.label}</span>
                  <span className="osc-intel-tlp-desc">{tlp.desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
