import { type TopicId } from './knowledgeData'

interface LocalizedCopy {
  zh: string
  en: string
}

interface FlowNode {
  tone: 'sender' | 'mta' | 'relay'
  title: LocalizedCopy
  subtitle: LocalizedCopy
  edgeToNext?: LocalizedCopy
}

interface VisualCard {
  tone: 'blue' | 'cyan' | 'green' | 'amber' | 'purple' | 'red'
  title: LocalizedCopy
  items: LocalizedCopy[]
}

interface TopicVisual {
  title: LocalizedCopy
  caption: LocalizedCopy
  nodes: FlowNode[]
  cards: VisualCard[]
}

type TopicArtKind =
  | 'mail-route'
  | 'tls-gate'
  | 'auth-shield'
  | 'fusion-core'
  | 'timeline-alert'
  | 'threat-mail'
  | 'intel-radar'
  | 'ai-console'
  | 'soar-ops'
  | 'webmail-dlp'
  | 'mode-split'
  | 'message-bus'
  | 'quarantine-lab'
  | 'link-mask'

function copy(zh: string, en: string): LocalizedCopy {
  return { zh, en }
}

function pickText(text: LocalizedCopy, language: string): string {
  return language.startsWith('en') ? text.en : text.zh
}

function FlowNodeIcon({ tone }: { tone: FlowNode['tone'] }) {
  const props = {
    width: 18,
    height: 18,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 2,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
  }

  switch (tone) {
    case 'sender':
      return (
        <svg {...props}>
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
          <circle cx="12" cy="7" r="4" />
        </svg>
      )
    case 'relay':
      return (
        <svg {...props}>
          <polyline points="17 1 21 5 17 9" />
          <path d="M3 11V9a4 4 0 0 1 4-4h14" />
          <polyline points="7 23 3 19 7 15" />
          <path d="M21 13v2a4 4 0 0 1-4 4H3" />
        </svg>
      )
    case 'mta':
    default:
      return (
        <svg {...props}>
          <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
          <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
          <line x1="6" y1="6" x2="6.01" y2="6" />
          <line x1="6" y1="18" x2="6.01" y2="18" />
        </svg>
      )
  }
}

function getTopicArtKind(topicId: TopicId): TopicArtKind {
  switch (topicId) {
    case 'mta':
      return 'mail-route'
    case 'opportunistic-tls':
    case 'mandatory-tls':
    case 'starttls':
      return 'tls-gate'
    case 'spf-dkim-dmarc':
      return 'auth-shield'
    case 'ds-fusion':
    case 'module-pipeline':
      return 'fusion-core'
    case 'temporal-evt':
      return 'timeline-alert'
    case 'phishing-detection':
    case 'bec-attack':
    case 'social-engineering':
    case 'attachment-weaponization':
      return 'threat-mail'
    case 'ioc-intel':
      return 'intel-radar'
    case 'ai-nlp':
      return 'ai-console'
    case 'soar-alerts':
      return 'soar-ops'
    case 'data-security':
      return 'webmail-dlp'
    case 'mirror-vs-mta':
      return 'mode-split'
    case 'message-bus':
      return 'message-bus'
    case 'mta-quarantine':
      return 'quarantine-lab'
    case 'link-obfuscation':
      return 'link-mask'
  }
}

function ArtText({
  x,
  y,
  text,
  size = 15,
  weight = 600,
  fill = '#e2e8f0',
  anchor = 'start',
}: {
  x: number
  y: number
  text: string
  size?: number
  weight?: number
  fill?: string
  anchor?: 'start' | 'middle' | 'end'
}) {
  return (
    <text
      x={x}
      y={y}
      fill={fill}
      textAnchor={anchor}
      dominantBaseline="middle"
      style={{ fontSize: `${size}px`, fontWeight: weight, letterSpacing: '-0.01em' }}
    >
      {text}
    </text>
  )
}

function ArtPill({
  x,
  y,
  w,
  label,
  tone,
}: {
  x: number
  y: number
  w: number
  label: string
  tone: 'blue' | 'cyan' | 'green' | 'amber' | 'purple' | 'red'
}) {
  const tones = {
    blue: { fill: '#0b2944', stroke: '#2563eb', text: '#93c5fd' },
    cyan: { fill: '#062d33', stroke: '#06b6d4', text: '#67e8f9' },
    green: { fill: '#082a1d', stroke: '#16a34a', text: '#86efac' },
    amber: { fill: '#332407', stroke: '#d97706', text: '#fcd34d' },
    purple: { fill: '#24113a', stroke: '#9333ea', text: '#d8b4fe' },
    red: { fill: '#391114', stroke: '#dc2626', text: '#fca5a5' },
  }[tone]

  return (
    <g>
      <rect x={x} y={y} width={w} height="30" rx="15" fill={tones.fill} stroke={tones.stroke} strokeWidth="1.5" />
      <ArtText x={x + w / 2} y={y + 15} text={label} size={12} weight={700} fill={tones.text} anchor="middle" />
    </g>
  )
}

function ArtPanel({
  x,
  y,
  w,
  h,
  title,
  subtitle,
  accent = '#22d3ee',
}: {
  x: number
  y: number
  w: number
  h: number
  title: string
  subtitle?: string
  accent?: string
}) {
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx="20" fill="#08111b" stroke="#1f3347" strokeWidth="1.5" />
      <rect x={x + 18} y={y + 18} width={w - 36} height="8" rx="4" fill={accent} opacity="0.2" />
      <ArtText x={x + 18} y={y + 42} text={title} size={16} weight={700} />
      {subtitle && <ArtText x={x + 18} y={y + 64} text={subtitle} size={12} fill="#94a3b8" />}
    </g>
  )
}

function ArtArrow({ x1, y1, x2, y2, label }: { x1: number; y1: number; x2: number; y2: number; label?: string }) {
  return (
    <g>
      <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#22d3ee" strokeWidth="3" strokeLinecap="round" opacity="0.8" />
      <path d={`M ${x2 - 12} ${y2 - 8} L ${x2} ${y2} L ${x2 - 12} ${y2 + 8}`} fill="none" stroke="#22d3ee" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      {label && <ArtText x={(x1 + x2) / 2} y={y1 - 14} text={label} size={11} fill="#67e8f9" anchor="middle" />}
    </g>
  )
}

function TopicIllustration({ topicId, language }: { topicId: TopicId; language: string }) {
  const kind = getTopicArtKind(topicId)

  const renderScene = () => {
    switch (kind) {
      case 'mail-route':
        return (
          <>
            <ArtPanel x={52} y={88} w={156} h={126} title={pickText(copy('发件端', 'Sender side'), language)} subtitle={pickText(copy('MUA → MSA', 'MUA → MSA'), language)} accent="#60a5fa" />
            <ArtPanel x={274} y={72} w={170} h={142} title={pickText(copy('中继路径', 'Relay path'), language)} subtitle={pickText(copy('SMTP :25', 'SMTP :25'), language)} accent="#22d3ee" />
            <ArtPanel x={508} y={88} w={156} h={126} title={pickText(copy('收件 MTA', 'Recipient MTA'), language)} subtitle={pickText(copy('MX 命中', 'MX lookup'), language)} accent="#f59e0b" />
            <ArtPanel x={730} y={104} w={164} h={110} title={pickText(copy('邮箱访问', 'Mailbox access'), language)} subtitle={pickText(copy('POP3 / IMAP', 'POP3 / IMAP'), language)} accent="#34d399" />
            <ArtArrow x1={208} y1={150} x2={274} y2={150} label="SMTP :587" />
            <ArtArrow x1={444} y1={150} x2={508} y2={150} label="SMTP :25" />
            <ArtArrow x1={664} y1={150} x2={730} y2={150} label="POP3 / IMAP" />
            <ArtPill x={88} y={236} w={84} label="MTA" tone="blue" />
            <ArtPill x={330} y={236} w={122} label={pickText(copy('过滤网关', 'Filter gateway'), language)} tone="cyan" />
            <ArtPill x={770} y={236} w={90} label="MUA" tone="green" />
          </>
        )
      case 'tls-gate':
        return (
          <>
            <ArtPanel x={70} y={86} w={202} h={136} title={pickText(copy('明文握手', 'Cleartext handshake'), language)} subtitle={pickText(copy('EHLO / STARTTLS', 'EHLO / STARTTLS'), language)} accent="#f59e0b" />
            <ArtPanel x={360} y={70} w={236} h={168} title={pickText(copy('TLS 升级闸门', 'TLS upgrade gate'), language)} subtitle={pickText(copy('220 Ready to start TLS', '220 Ready to start TLS'), language)} accent="#22d3ee" />
            <ArtPanel x={684} y={86} w={202} h={136} title={pickText(copy('加密 SMTP', 'Encrypted SMTP'), language)} subtitle={pickText(copy('正文 / 附件密文', 'Body / attachment ciphertext'), language)} accent="#34d399" />
            <ArtArrow x1={272} y1={154} x2={360} y2={154} label="STARTTLS" />
            <ArtArrow x1={596} y1={154} x2={684} y2={154} label={pickText(copy('TLS 握手', 'TLS handshake'), language)} />
            <ArtPill x={418} y={116} w={120} label={pickText(copy('证书验证', 'Cert validation'), language)} tone="cyan" />
            <ArtPill x={412} y={168} w={132} label={pickText(copy('防降级检查', 'Downgrade check'), language)} tone="red" />
          </>
        )
      case 'auth-shield':
        return (
          <>
            <ArtPill x={98} y={110} w={92} label="SPF" tone="blue" />
            <ArtPill x={98} y={158} w={92} label="DKIM" tone="purple" />
            <ArtPill x={98} y={206} w={108} label="DMARC" tone="cyan" />
            <ArtArrow x1={206} y1={125} x2={360} y2={176} />
            <ArtArrow x1={190} y1={173} x2={360} y2={176} />
            <ArtArrow x1={206} y1={221} x2={360} y2={176} />
            <path d="M 390 92 L 500 126 L 500 200 C 500 248 454 278 390 300 C 326 278 280 248 280 200 L 280 126 Z" fill="#0b2944" stroke="#22d3ee" strokeWidth="2.5" />
            <ArtText x={390} y={166} text={pickText(copy('发件身份', 'Sender identity'), language)} size={19} weight={800} anchor="middle" />
            <ArtText x={390} y={194} text={pickText(copy('对齐 + 策略', 'Alignment + policy'), language)} size={13} fill="#94a3b8" anchor="middle" />
            <ArtPanel x={598} y={104} w={264} h={138} title={pickText(copy('处理动作', 'Enforcement'), language)} subtitle={pickText(copy('放行 / 隔离 / 拒绝', 'Allow / quarantine / reject'), language)} accent="#34d399" />
          </>
        )
      case 'fusion-core':
        return (
          <>
            {[0, 1, 2, 3, 4, 5].map((index) => {
              const positions = [
                { x: 112, y: 102, label: pickText(copy('内容', 'Content'), language) },
                { x: 112, y: 212, label: pickText(copy('链接', 'Links'), language) },
                { x: 300, y: 62, label: pickText(copy('身份', 'Identity'), language) },
                { x: 300, y: 252, label: pickText(copy('行为', 'Behavior'), language) },
                { x: 488, y: 102, label: pickText(copy('语义', 'Semantic'), language) },
                { x: 488, y: 212, label: pickText(copy('协议', 'Protocol'), language) },
              ][index]
              return (
                <g key={positions.label}>
                  <rect x={positions.x} y={positions.y} width="116" height="44" rx="14" fill="#0d1723" stroke="#243447" />
                  <ArtText x={positions.x + 58} y={positions.y + 22} text={positions.label} size={13} weight={700} anchor="middle" />
                </g>
              )
            })}
            {[
              [228, 124],
              [228, 234],
              [416, 84],
              [416, 274],
              [604, 124],
              [604, 234],
            ].map(([x, y], index) => (
              <ArtArrow key={`${x}-${y}-${index}`} x1={x} y1={y} x2={420} y2={178} />
            ))}
            <circle cx="420" cy="178" r="78" fill="#0c2633" stroke="#22d3ee" strokeWidth="2.5" />
            <ArtText x={420} y={160} text={pickText(copy('Murphy', 'Murphy'), language)} size={24} weight={800} anchor="middle" />
            <ArtText x={420} y={190} text={pickText(copy('融合核心', 'fusion core'), language)} size={14} fill="#67e8f9" anchor="middle" />
            <ArtPanel x={694} y={110} w={188} h={136} title={pickText(copy('最终风险', 'Final risk'), language)} subtitle={pickText(copy('Safe → Critical', 'Safe → Critical'), language)} accent="#ef4444" />
            <ArtPill x={734} y={170} w={112} label="Risk 0.84" tone="red" />
          </>
        )
      case 'timeline-alert':
        return (
          <>
            <ArtPanel x={54} y={90} w={232} h={156} title={pickText(copy('时间序列', 'Timeline'), language)} subtitle={pickText(copy('历史 verdict 流', 'Historical verdict stream'), language)} accent="#60a5fa" />
            <polyline points="82,214 120,194 160,204 200,150 242,168" fill="none" stroke="#60a5fa" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
            <circle cx="242" cy="168" r="7" fill="#60a5fa" />
            <ArtPill x={94} y={116} w={88} label="CUSUM" tone="blue" />
            <ArtPill x={186} y={116} w={86} label="EWMA" tone="cyan" />
            <ArtPanel x={360} y={72} w={248} h={192} title={pickText(copy('行为阶段', 'Attack phase'), language)} subtitle={pickText(copy('HMM / 图谱 / 尾部风险', 'HMM / graph / tail risk'), language)} accent="#a855f7" />
            <ArtPill x={392} y={128} w={74} label="S0" tone="green" />
            <ArtPill x={478} y={128} w={74} label="S1" tone="amber" />
            <ArtPill x={392} y={174} w={74} label="S2" tone="purple" />
            <ArtPill x={478} y={174} w={74} label="S3" tone="red" />
            <ArtPill x={434} y={220} w={74} label="S4" tone="red" />
            <ArtPanel x={680} y={106} w={208} h={124} title={pickText(copy('告警优先级', 'Alert priority'), language)} subtitle={pickText(copy('P0 / P1 / P2 / P3', 'P0 / P1 / P2 / P3'), language)} accent="#ef4444" />
            <ArtArrow x1={286} y1={168} x2={360} y2={168} />
            <ArtArrow x1={608} y1={168} x2={680} y2={168} />
          </>
        )
      case 'threat-mail':
        return (
          <>
            <ArtPanel x={72} y={72} w={370} h={206} title={pickText(copy('邮件样本', 'Sample message'), language)} subtitle={pickText(copy('看起来正常，但细节危险', 'Looks normal, but details are risky'), language)} accent="#60a5fa" />
            <ArtPill x={102} y={122} w={126} label={pickText(copy('紧急付款', 'Urgent payment'), language)} tone="red" />
            <ArtPill x={242} y={122} w={116} label={pickText(copy('外部域名', 'External domain'), language)} tone="amber" />
            <ArtPill x={102} y={168} w={112} label={pickText(copy('短链', 'Short link'), language)} tone="purple" />
            <ArtPill x={228} y={168} w={140} label={pickText(copy('伪装附件', 'Disguised file'), language)} tone="red" />
            <ArtText x={104} y={228} text={pickText(copy('From: ceo@partner-mail.co', 'From: ceo@partner-mail.co'), language)} size={14} fill="#94a3b8" />
            <ArtText x={104} y={252} text={pickText(copy('Subject: 今日内完成付款确认', 'Subject: Confirm payment today'), language)} size={14} fill="#e2e8f0" />
            <ArtPanel x={520} y={94} w={336} h={162} title={pickText(copy('平台看见的信号', 'Signals the platform sees'), language)} subtitle={pickText(copy('内容 + 链接 + 身份 + 语义', 'Content + link + identity + semantics'), language)} accent="#22d3ee" />
            <ArtPill x={556} y={148} w={118} label={pickText(copy('BEC 话术', 'BEC phrases'), language)} tone="red" />
            <ArtPill x={688} y={148} w={128} label={pickText(copy('显示名异常', 'Display-name drift'), language)} tone="amber" />
            <ArtPill x={556} y={196} w={112} label={pickText(copy('首联外部', 'First-contact'), language)} tone="purple" />
            <ArtPill x={682} y={196} w={128} label={pickText(copy('落地页风险', 'Landing-page risk'), language)} tone="cyan" />
          </>
        )
      case 'intel-radar':
        return (
          <>
            <circle cx="290" cy="178" r="118" fill="none" stroke="#163047" strokeWidth="2" />
            <circle cx="290" cy="178" r="84" fill="none" stroke="#163047" strokeWidth="2" />
            <circle cx="290" cy="178" r="50" fill="none" stroke="#163047" strokeWidth="2" />
            <line x1="172" y1="178" x2="408" y2="178" stroke="#163047" strokeWidth="2" />
            <line x1="290" y1="60" x2="290" y2="296" stroke="#163047" strokeWidth="2" />
            <circle cx="354" cy="126" r="8" fill="#22d3ee" />
            <circle cx="246" cy="110" r="8" fill="#f59e0b" />
            <circle cx="332" cy="224" r="8" fill="#ef4444" />
            <ArtPill x={168} y={86} w={88} label="IP" tone="amber" />
            <ArtPill x={352} y={92} w={104} label="URL" tone="cyan" />
            <ArtPill x={200} y={244} w={116} label="SHA256" tone="purple" />
            <ArtPanel x={544} y={90} w={312} h={178} title={pickText(copy('IOC 判定面板', 'IOC decision panel'), language)} subtitle={pickText(copy('本地缓存 → 外部情报 → 白名单保护', 'Local cache → external intel → whitelist protection'), language)} accent="#22d3ee" />
            <ArtPill x={578} y={146} w={120} label={pickText(copy('malicious', 'malicious'), language)} tone="red" />
            <ArtPill x={714} y={146} w={126} label={pickText(copy('suspicious', 'suspicious'), language)} tone="amber" />
            <ArtPill x={632} y={198} w={150} label={pickText(copy('admin_clean', 'admin_clean'), language)} tone="green" />
          </>
        )
      case 'ai-console':
        return (
          <>
            <ArtPanel x={76} y={84} w={238} h={190} title={pickText(copy('零样本路径', 'Zero-shot path'), language)} subtitle={pickText(copy('phishing / scam / bec / spam / legitimate', 'phishing / scam / bec / spam / legitimate'), language)} accent="#a855f7" />
            <ArtPanel x={366} y={68} w={238} h={206} title={pickText(copy('微调路径', 'Fine-tuned path'), language)} subtitle={pickText(copy('analyst feedback → LoRA', 'analyst feedback → LoRA'), language)} accent="#22d3ee" />
            <ArtPanel x={656} y={102} w={228} h={138} title={pickText(copy('semantic_scan 输出', 'semantic_scan output'), language)} subtitle={pickText(copy('标签 + 置信度', 'label + confidence'), language)} accent="#34d399" />
            <ArtArrow x1={314} y1={176} x2={366} y2={176} label={pickText(copy('优先 fine-tuned', 'Prefer fine-tuned'), language)} />
            <ArtArrow x1={604} y1={176} x2={656} y2={176} label={pickText(copy('融合进 verdict', 'Fuse into verdict'), language)} />
            <ArtPill x={118} y={138} w={132} label={pickText(copy('NLI 立即可用', 'NLI ready now'), language)} tone="purple" />
            <ArtPill x={404} y={134} w={156} label={pickText(copy('K-Fold 质量门槛', 'K-Fold quality gate'), language)} tone="cyan" />
            <ArtPill x={716} y={158} w={116} label="confidence" tone="green" />
          </>
        )
      case 'soar-ops':
        return (
          <>
            <ArtPanel x={64} y={92} w={196} h={154} title={pickText(copy('告警队列', 'Alert queue'), language)} subtitle={pickText(copy('P0 → P3', 'P0 → P3'), language)} accent="#ef4444" />
            <ArtPill x={100} y={138} w={82} label="P0" tone="red" />
            <ArtPill x={190} y={138} w={82} label="P1" tone="amber" />
            <ArtPill x={100} y={184} w={82} label="P2" tone="cyan" />
            <ArtPill x={190} y={184} w={82} label="P3" tone="blue" />
            <ArtPanel x={344} y={72} w={266} h={194} title={pickText(copy('SOAR 规则引擎', 'SOAR rule engine'), language)} subtitle={pickText(copy('等级 + 类别 + 模块 → 动作', 'Level + category + module → action'), language)} accent="#22d3ee" />
            <ArtPill x={384} y={128} w={84} label="webhook" tone="cyan" />
            <ArtPill x={480} y={128} w={64} label="log" tone="blue" />
            <ArtPill x={404} y={180} w={116} label={pickText(copy('SMTP alert', 'SMTP alert'), language)} tone="amber" />
            <ArtPanel x={694} y={106} w={192} h={126} title={pickText(copy('处置动作', 'Response actions'), language)} subtitle={pickText(copy('通知 / 打单 / 记录', 'Notify / ticket / record'), language)} accent="#34d399" />
            <ArtArrow x1={260} y1={168} x2={344} y2={168} />
            <ArtArrow x1={610} y1={168} x2={694} y2={168} />
          </>
        )
      case 'webmail-dlp':
        return (
          <>
            <ArtPanel x={78} y={72} w={338} h={210} title={pickText(copy('浏览器邮件会话', 'Browser mail session'), language)} subtitle={pickText(copy('Compose / Draft / Upload', 'Compose / Draft / Upload'), language)} accent="#60a5fa" />
            <rect x="110" y="122" width="270" height="34" rx="12" fill="#0f172a" stroke="#243447" />
            <rect x="110" y="170" width="186" height="34" rx="12" fill="#0f172a" stroke="#243447" />
            <rect x="306" y="170" width="74" height="34" rx="12" fill="#0f172a" stroke="#243447" />
            <ArtText x={124} y={139} text={pickText(copy('To: 自己的邮箱 / 外部收件人', 'To: self mailbox / external recipient'), language)} size={13} fill="#94a3b8" />
            <ArtText x={124} y={187} text={pickText(copy('附件上传 / 草稿保存', 'Attachment upload / draft save'), language)} size={13} fill="#94a3b8" />
            <ArtPanel x={514} y={92} w={334} h={170} title={pickText(copy('DLP 检测层', 'DLP detection layer'), language)} subtitle={pickText(copy('银行卡 / 身份证 / 金额 / 合同号', 'Bank cards / IDs / amounts / contract IDs'), language)} accent="#34d399" />
            <ArtPill x={548} y={148} w={130} label={pickText(copy('draft_box_abuse', 'draft_box_abuse'), language)} tone="amber" />
            <ArtPill x={690} y={148} w={132} label={pickText(copy('file_transit', 'file_transit'), language)} tone="purple" />
            <ArtPill x={626} y={198} w={116} label={pickText(copy('self_sending', 'self_sending'), language)} tone="red" />
            <ArtArrow x1={416} y1={176} x2={514} y2={176} />
          </>
        )
      case 'mode-split':
        return (
          <>
            <ArtPanel x={66} y={72} w={356} h={196} title={pickText(copy('旁路镜像模式', 'Mirror mode'), language)} subtitle={pickText(copy('抓包 → 分析 → 告警', 'Capture → analyze → alert'), language)} accent="#60a5fa" />
            <ArtPanel x={538} y={72} w={356} h={196} title={pickText(copy('MTA 代理模式', 'MTA proxy mode'), language)} subtitle={pickText(copy('SMTP 中继 → 判定 → 处置', 'SMTP relay → verdict → response'), language)} accent="#ef4444" />
            <ArtPanel x={432} y={116} w={96} h={108} title="Vigilyx" subtitle={pickText(copy('共享引擎', 'Shared core'), language)} accent="#22d3ee" />
            <ArtArrow x1={422} y1={170} x2={432} y2={170} />
            <ArtArrow x1={528} y1={170} x2={538} y2={170} />
            <ArtPill x={122} y={128} w={108} label={pickText(copy('无侵入', 'Low intrusion'), language)} tone="blue" />
            <ArtPill x={244} y={128} w={132} label={pickText(copy('事后审计', 'Post-event audit'), language)} tone="cyan" />
            <ArtPill x={598} y={128} w={108} label={pickText(copy('前置拦截', 'Pre-delivery block'), language)} tone="red" />
            <ArtPill x={720} y={128} w={118} label={pickText(copy('隔离放行', 'Quarantine flow'), language)} tone="amber" />
          </>
        )
      case 'message-bus':
        return (
          <>
            <ArtPanel x={64} y={86} w={222} h={160} title="Sniffer" subtitle={pickText(copy('写入会话数据', 'Writes session data'), language)} accent="#60a5fa" />
            <ArtPanel x={356} y={64} w={258} h={204} title="Redis Streams" subtitle={pickText(copy('数据面 / consumer groups', 'Data plane / consumer groups'), language)} accent="#22d3ee" />
            <ArtPanel x={684} y={86} w={210} h={160} title="Engine" subtitle={pickText(copy('XREADGROUP / XACK', 'XREADGROUP / XACK'), language)} accent="#34d399" />
            <ArtArrow x1={286} y1={166} x2={356} y2={166} label={pickText(copy('vigilyx:stream:sessions', 'vigilyx:stream:sessions'), language)} />
            <ArtArrow x1={614} y1={166} x2={684} y2={166} label={pickText(copy('at-least-once', 'at-least-once'), language)} />
            <ArtPill x={408} y={118} w={90} label="PEL" tone="amber" />
            <ArtPill x={510} y={118} w={108} label="XAUTOCLAIM" tone="purple" />
            <ArtPanel x={356} y={286} w={258} h={46} title={pickText(copy('Pub/Sub 控制广播', 'Pub/Sub control broadcast'), language)} accent="#f59e0b" />
          </>
        )
      case 'quarantine-lab':
        return (
          <>
            <ArtPanel x={66} y={86} w={206} h={158} title={pickText(copy('SMTP DATA', 'SMTP DATA'), language)} subtitle={pickText(copy('收下整封邮件', 'Receive full message'), language)} accent="#60a5fa" />
            <ArtPanel x={340} y={66} w={262} h={198} title={pickText(copy('内联判定', 'Inline verdict'), language)} subtitle={pickText(copy('Safe / Low / Medium / High / Critical', 'Safe / Low / Medium / High / Critical'), language)} accent="#22d3ee" />
            <ArtPanel x={670} y={86} w={224} h={158} title={pickText(copy('隔离区', 'Quarantine'), language)} subtitle={pickText(copy('保留 raw_eml 与操作记录', 'Preserve raw_eml and release metadata'), language)} accent="#ef4444" />
            <ArtArrow x1={272} y1={166} x2={340} y2={166} />
            <ArtArrow x1={602} y1={166} x2={670} y2={166} />
            <ArtPill x={392} y={124} w={90} label="Safe" tone="green" />
            <ArtPill x={492} y={124} w={84} label="Low" tone="blue" />
            <ArtPill x={392} y={176} w={100} label="Medium" tone="amber" />
            <ArtPill x={504} y={176} w={80} label="High" tone="red" />
            <ArtPill x={732} y={144} w={106} label={pickText(copy('释放 / 删除', 'Release / delete'), language)} tone="purple" />
          </>
        )
      case 'link-mask':
        return (
          <>
            <ArtPanel x={76} y={92} w={234} h={148} title={pickText(copy('用户看到的链接', 'Visible link'), language)} subtitle={pickText(copy('看起来像 trusted-site.com', 'Looks like trusted-site.com'), language)} accent="#60a5fa" />
            <ArtPanel x={366} y={72} w={248} h={188} title={pickText(copy('真实跳转链路', 'Actual redirect chain'), language)} subtitle={pickText(copy('短链 / 参数 / 编码 / 中间跳板', 'Shortener / params / encoding / relay hops'), language)} accent="#f59e0b" />
            <ArtPanel x={670} y={92} w={224} h={148} title={pickText(copy('最终落地页', 'Final destination'), language)} subtitle={pickText(copy('真实恶意域名或钓鱼页', 'Actual malicious domain or phishing page'), language)} accent="#ef4444" />
            <ArtArrow x1={310} y1={166} x2={366} y2={166} label="href" />
            <ArtArrow x1={614} y1={166} x2={670} y2={166} label={pickText(copy('redirect', 'redirect'), language)} />
            <ArtPill x={414} y={128} w={92} label="bit.ly" tone="purple" />
            <ArtPill x={518} y={128} w={78} label="@token" tone="amber" />
            <ArtPill x={440} y={180} w={130} label={pickText(copy('IDN 同形', 'IDN homograph'), language)} tone="red" />
          </>
        )
    }
  }

  return (
    <div className="sk-showcase-art" aria-hidden="true">
      <svg viewBox="0 0 960 360" role="presentation">
        <defs>
          <linearGradient id={`art-bg-${kind}`} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#06111b" />
            <stop offset="50%" stopColor="#0a1623" />
            <stop offset="100%" stopColor="#07131f" />
          </linearGradient>
          <linearGradient id={`art-grid-${kind}`} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#0f1d2d" stopOpacity="0" />
            <stop offset="50%" stopColor="#1f3347" stopOpacity="0.55" />
            <stop offset="100%" stopColor="#0f1d2d" stopOpacity="0" />
          </linearGradient>
        </defs>

        <rect x="0" y="0" width="960" height="360" rx="28" fill={`url(#art-bg-${kind})`} />
        <circle cx="172" cy="84" r="112" fill="#22d3ee" opacity="0.08" />
        <circle cx="810" cy="286" r="128" fill="#2563eb" opacity="0.08" />
        <circle cx="540" cy="64" r="92" fill="#a855f7" opacity="0.06" />
        {[72, 144, 216, 288].map(y => <line key={`h-${y}`} x1="44" y1={y} x2="916" y2={y} stroke={`url(#art-grid-${kind})`} strokeWidth="1" />)}
        {[140, 280, 420, 560, 700, 840].map(x => <line key={`v-${x}`} x1={x} y1="34" x2={x} y2="326" stroke={`url(#art-grid-${kind})`} strokeWidth="1" />)}
        {renderScene()}
      </svg>
    </div>
  )
}

const topicVisuals: Record<TopicId, TopicVisual> = {
  mta: {
    title: copy('邮件投递路径图解', 'Mail delivery path'),
    caption: copy('先看路径，再看正文。MTA 文章的重点不是术语定义，而是邮件如何从客户端穿过多个服务器到达收件人。', 'Start with the path, then read the text. The real point of this article is how mail moves from a client, across several servers, and finally reaches the recipient.'),
    nodes: [
      { tone: 'sender', title: copy('发件人', 'Sender'), subtitle: copy('MUA 客户端', 'MUA client'), edgeToNext: copy('SMTP :587', 'SMTP :587') },
      { tone: 'mta', title: copy('发件 MTA', 'Sender MTA'), subtitle: copy('提交入口', 'Submission server'), edgeToNext: copy('SMTP :25', 'SMTP :25') },
      { tone: 'relay', title: copy('中继 / 过滤', 'Relay / Filter'), subtitle: copy('可选网关', 'Optional gateway'), edgeToNext: copy('SMTP :25', 'SMTP :25') },
      { tone: 'mta', title: copy('收件 MTA', 'Recipient MTA'), subtitle: copy('MX 命中', 'MX target'), edgeToNext: copy('POP3 / IMAP', 'POP3 / IMAP') },
      { tone: 'sender', title: copy('收件人', 'Recipient'), subtitle: copy('邮箱访问', 'Mailbox access') },
    ],
    cards: [
      {
        tone: 'blue',
        title: copy('关键角色', 'Key roles'),
        items: [
          copy('MTA 负责服务器间转发', 'MTA handles server-to-server transfer'),
          copy('MUA 是 Outlook、Thunderbird 这类客户端', 'MUA is the user-facing mail client'),
          copy('MSA 通常负责 587 提交入口', 'MSA usually handles port 587 submission'),
        ],
      },
      {
        tone: 'cyan',
        title: copy('Vigilyx 介入点', 'Where Vigilyx fits'),
        items: [
          copy('镜像模式只观察，不改投递路径', 'Mirror mode only observes and does not alter the mail path'),
          copy('MTA 代理模式则直接变成 SMTP 中继', 'MTA proxy mode becomes an SMTP relay inline'),
          copy('两种模式共用同一套解析和检测引擎', 'Both modes reuse the same parser and detection stack'),
        ],
      },
    ],
  },
  'opportunistic-tls': {
    title: copy('机会性 TLS 升级流程', 'Opportunistic TLS upgrade path'),
    caption: copy('这是“能加密就加密”的典型链路。重点是 STARTTLS 能否出现，以及是否会被中途剥离。', 'This is the canonical “encrypt when possible” flow. The key question is whether STARTTLS appears and whether someone strips it on the way.'),
    nodes: [
      { tone: 'mta', title: copy('发件 MTA', 'Sender MTA'), subtitle: copy('明文连接', 'Cleartext connect'), edgeToNext: copy('EHLO', 'EHLO') },
      { tone: 'relay', title: copy('能力协商', 'Capability list'), subtitle: copy('看 250-STARTTLS', 'Look for 250-STARTTLS'), edgeToNext: copy('STARTTLS', 'STARTTLS') },
      { tone: 'mta', title: copy('TLS 握手', 'TLS handshake'), subtitle: copy('220 Ready', '220 Ready'), edgeToNext: copy('加密 SMTP', 'Encrypted SMTP') },
      { tone: 'mta', title: copy('收件 MTA', 'Recipient MTA'), subtitle: copy('继续投递', 'Continue delivery') },
    ],
    cards: [
      {
        tone: 'green',
        title: copy('优点', 'Advantages'),
        items: [
          copy('无需预配置即可自动协商', 'Negotiates automatically without pre-coordination'),
          copy('兼容不支持 TLS 的旧服务器', 'Remains compatible with legacy non-TLS servers'),
          copy('部署成本很低，覆盖面广', 'Has very low deployment cost and broad coverage'),
        ],
      },
      {
        tone: 'red',
        title: copy('风险点', 'Risks'),
        items: [
          copy('可被 STRIPTLS 降级为明文', 'Can be downgraded to plaintext by STRIPTLS'),
          copy('很多环境并不严格校验证书', 'Many environments do not validate certificates strictly'),
          copy('用户通常看不到是否真的用了加密', 'Users usually cannot tell whether encryption was actually used'),
        ],
      },
    ],
  },
  'mandatory-tls': {
    title: copy('强制 TLS 判定路径', 'Mandatory TLS decision path'),
    caption: copy('这里不是“尽量加密”，而是“要么成功加密，要么拒绝发送”。', 'This is not “encrypt if you can.” It is “either build a valid secure channel or refuse delivery.”'),
    nodes: [
      { tone: 'relay', title: copy('策略发现', 'Policy lookup'), subtitle: copy('MTA-STS / DANE', 'MTA-STS / DANE'), edgeToNext: copy('要求 TLS', 'Require TLS') },
      { tone: 'mta', title: copy('建立连接', 'Open connection'), subtitle: copy('尝试 STARTTLS', 'Try STARTTLS'), edgeToNext: copy('校验证书', 'Validate cert') },
      { tone: 'relay', title: copy('验证通过', 'Validation passes'), subtitle: copy('继续发送', 'Continue sending'), edgeToNext: copy('加密投递', 'Encrypted delivery') },
      { tone: 'sender', title: copy('失败则拒绝', 'Reject on failure'), subtitle: copy('不回退明文', 'No plaintext fallback') },
    ],
    cards: [
      {
        tone: 'cyan',
        title: copy('常见实现', 'Common implementations'),
        items: [
          copy('MTA-STS 通过 HTTPS 发布域策略', 'MTA-STS publishes domain policy over HTTPS'),
          copy('DANE 通过 DNSSEC 绑定 TLSA 记录', 'DANE binds TLS expectations with DNSSEC-protected TLSA records'),
          copy('合作方场景也可用手工 TLS policy', 'Partner domains can also use manual TLS policy'),
        ],
      },
      {
        tone: 'amber',
        title: copy('与机会性 TLS 的区别', 'How it differs from opportunistic TLS'),
        items: [
          copy('加密失败时直接拒绝，不回退明文', 'Rejects on encryption failure instead of falling back'),
          copy('必须校验证书', 'Requires certificate validation'),
          copy('能对抗降级攻击，但部署更重', 'Stops downgrade attacks but costs more to deploy'),
        ],
      },
    ],
  },
  starttls: {
    title: copy('STARTTLS 协议升级示意', 'STARTTLS protocol upgrade'),
    caption: copy('镜像环境最容易看到的是升级前的明文握手，而不是升级后的密文内容。', 'In mirror deployments the most visible part is the cleartext negotiation before the upgrade, not the encrypted content after it.'),
    nodes: [
      { tone: 'mta', title: copy('TCP 明文连接', 'TCP cleartext'), subtitle: copy('220 Banner', '220 banner'), edgeToNext: copy('EHLO', 'EHLO') },
      { tone: 'relay', title: copy('能力列表', 'Capability list'), subtitle: copy('250-STARTTLS', '250-STARTTLS'), edgeToNext: copy('STARTTLS', 'STARTTLS') },
      { tone: 'mta', title: copy('升级命令', 'Upgrade command'), subtitle: copy('220 Ready', '220 Ready'), edgeToNext: copy('TLS 握手', 'TLS handshake') },
      { tone: 'relay', title: copy('加密会话', 'Encrypted session'), subtitle: copy('MAIL FROM / DATA', 'MAIL FROM / DATA') },
    ],
    cards: [
      {
        tone: 'green',
        title: copy('Vigilyx 能看到的部分', 'What Vigilyx can see'),
        items: [
          copy('EHLO、250-STARTTLS、STARTTLS 都在明文里', 'EHLO, 250-STARTTLS, and STARTTLS stay in cleartext'),
          copy('是否真的发起升级一眼可见', 'It is easy to tell whether the client actually upgraded'),
          copy('升级成功后正文和附件会变成密文', 'After the upgrade, body and attachments become ciphertext'),
        ],
      },
      {
        tone: 'purple',
        title: copy('和隐式 TLS 的区别', 'Compared with implicit TLS'),
        items: [
          copy('STARTTLS 先明文再升级', 'STARTTLS begins clear and upgrades later'),
          copy('465 隐式 TLS 从第一个包就是密文', 'Port 465 implicit TLS is encrypted from the first packet'),
          copy('所以镜像抓包的可见性完全不同', 'That makes passive visibility completely different'),
        ],
      },
    ],
  },
  'spf-dkim-dmarc': {
    title: copy('发件人认证三件套', 'The sender-authentication triad'),
    caption: copy('这三层并不是“重复功能”，而是从发件 IP、内容签名、域策略三个角度一起约束发件身份。', 'These controls are not duplicates. They constrain sender identity from three angles: sending IP, content signature, and domain-level policy.'),
    nodes: [
      { tone: 'relay', title: copy('SPF', 'SPF'), subtitle: copy('看发件 IP', 'Check sending IP'), edgeToNext: copy('DKIM', 'DKIM') },
      { tone: 'mta', title: copy('DKIM', 'DKIM'), subtitle: copy('验头和正文签名', 'Verify header/body signature'), edgeToNext: copy('DMARC', 'DMARC') },
      { tone: 'relay', title: copy('DMARC', 'DMARC'), subtitle: copy('域策略 + 对齐', 'Policy + alignment'), edgeToNext: copy('处理动作', 'Enforcement') },
      { tone: 'sender', title: copy('最终动作', 'Final action'), subtitle: copy('放行 / 隔离 / 拒绝', 'Allow / quarantine / reject') },
    ],
    cards: [
      {
        tone: 'blue',
        title: copy('分别解决什么问题', 'What each one solves'),
        items: [
          copy('SPF 判断这台 IP 是否有权代发', 'SPF checks whether the IP is authorized to send'),
          copy('DKIM 判断邮件内容是否被篡改', 'DKIM checks whether the content was altered'),
          copy('DMARC 决定 SPF / DKIM 都失败时怎么办', 'DMARC decides what to do when SPF and DKIM fail'),
        ],
      },
      {
        tone: 'amber',
        title: copy('不要和 TLS 混淆', 'Do not confuse this with TLS'),
        items: [
          copy('TLS 保护的是传输链路', 'TLS protects the transport path'),
          copy('SPF / DKIM / DMARC 保护的是发件身份', 'SPF, DKIM, and DMARC protect sender identity'),
          copy('一封邮件可以“加密但伪造”，也可以“明文但真实”', 'A message can be encrypted but spoofed, or cleartext but authentic'),
        ],
      },
    ],
  },
  'ds-fusion': {
    title: copy('多引擎融合可视化', 'Multi-engine fusion at a glance'),
    caption: copy('真正难的不是单个模块打分，而是如何把“支持恶意”“支持安全”“模块没把握”这三种状态合成到一起。', 'The hard part is not scoring one module. It is merging support for malicious, support for safe, and plain uncertainty into one coherent result.'),
    nodes: [
      { tone: 'mta', title: copy('模块评分', 'Module scores'), subtitle: copy('score + confidence', 'score + confidence'), edgeToNext: copy('转 BPA', 'Convert to BPA') },
      { tone: 'relay', title: copy('BPA 三元组', 'BPA triplets'), subtitle: copy('b / d / u', 'b / d / u'), edgeToNext: copy('引擎分组', 'Group engines') },
      { tone: 'mta', title: copy('Murphy 融合', 'Murphy fusion'), subtitle: copy('冲突先降噪', 'De-conflict first'), edgeToNext: copy('风险输出', 'Risk output') },
      { tone: 'sender', title: copy('最终 Verdict', 'Final verdict'), subtitle: copy('Safe → Critical', 'Safe → Critical') },
    ],
    cards: [
      {
        tone: 'purple',
        title: copy('三元组在表达什么', 'What the triplet means'),
        items: [
          copy('b = 支持 Threat 的质量', 'b = mass supporting Threat'),
          copy('d = 支持 Normal 的质量', 'd = mass supporting Normal'),
          copy('u = 模块没有把握，不等于低风险', 'u = the module is unsure, not low risk'),
        ],
      },
      {
        tone: 'red',
        title: copy('为什么不用简单概率', 'Why not use a single probability'),
        items: [
          copy('P=0.5 不能区分“50% 风险”和“根本看不清”', 'P=0.5 cannot separate “50% risky” from “cannot tell at all”'),
          copy('多模块剧烈冲突时，冲突本身就是信号', 'Strong inter-module conflict is itself a signal'),
          copy('Murphy 修正就是为了解决这种冲突放大问题', 'Murphy correction exists to stabilize this conflict'),
        ],
      },
    ],
  },
  'temporal-evt': {
    title: copy('时序层不是看一封邮件', 'The temporal layer looks beyond one message'),
    caption: copy('单封邮件只给你一个截面。时序层关心的是：这个发件人是不是在持续变坏，这次异常是不是历史长尾。', 'One message gives you only a snapshot. The temporal layer asks whether the sender is drifting over time and whether this event lives deep in the historical tail.'),
    nodes: [
      { tone: 'mta', title: copy('Verdict 流', 'Verdict stream'), subtitle: copy('持续输入', 'Continuous input'), edgeToNext: copy('CUSUM / EWMA', 'CUSUM / EWMA') },
      { tone: 'relay', title: copy('行为漂移', 'Behavior drift'), subtitle: copy('变点 + 漂移', 'Change point + drift'), edgeToNext: copy('HMM / 图谱', 'HMM / graph') },
      { tone: 'mta', title: copy('攻击阶段', 'Attack phase'), subtitle: copy('侦察 → 实施', 'Recon → execution'), edgeToNext: copy('EVT', 'EVT') },
      { tone: 'sender', title: copy('P0-P3 告警', 'P0-P3 alert'), subtitle: copy('稀有度 + 影响', 'Rarity + impact') },
    ],
    cards: [
      {
        tone: 'blue',
        title: copy('它能抓到什么', 'What it catches'),
        items: [
          copy('温水煮青蛙式的缓慢风险上升', 'Slow-boil risk escalation over time'),
          copy('首次联系人后的持续异常互动', 'Sustained abnormal interaction after first contact'),
          copy('历史上极少见但业务影响很大的长尾事件', 'Rare historical tail events with high business impact'),
        ],
      },
      {
        tone: 'amber',
        title: copy('为什么单封邮件不够', 'Why single-message scoring is not enough'),
        items: [
          copy('BEC 往往先建立信任，再发起攻击', 'BEC often builds trust before the actual attack'),
          copy('每一封都不高危，但整体轨迹异常', 'Each message may look mild while the trajectory is not'),
          copy('尾部建模能把“极少见”转成优先级', 'Tail modeling turns rarity into priority'),
        ],
      },
    ],
  },
  'module-pipeline': {
    title: copy('默认安全管线示意', 'Default security pipeline'),
    caption: copy('这里最容易误解的点是：20 个条目不等于 20 个独立引擎。它们先跑模块，再映射到更高层的概念引擎。', 'The key distinction here is that 20 pipeline entries do not mean 20 independent fusion engines. Modules run first, then collapse into higher-level conceptual engines.'),
    nodes: [
      { tone: 'mta', title: copy('EmailSession', 'EmailSession'), subtitle: copy('头 / 正文 / 附件 / 链接', 'headers / body / attachments / links'), edgeToNext: copy('模块执行', 'Run modules') },
      { tone: 'relay', title: copy('模块层', 'Module layer'), subtitle: copy('20 默认条目', '20 default entries'), edgeToNext: copy('引擎映射', 'Map to engines') },
      { tone: 'mta', title: copy('融合层', 'Fusion layer'), subtitle: copy('Copula + Murphy', 'Copula + Murphy'), edgeToNext: copy('判定', 'Verdict') },
      { tone: 'sender', title: copy('最终结果', 'Final result'), subtitle: copy('写库 + WebSocket', 'Persist + WebSocket') },
    ],
    cards: [
      {
        tone: 'cyan',
        title: copy('默认核心模块', 'Default core modules'),
        items: [
          copy('内容、HTML、附件、头、链接、语义、身份、交易、AV、YARA', 'Content, HTML, attachment, header, link, semantic, identity, transaction, AV, and YARA'),
          copy('verdict 是汇总阶段，不是前置分析模块', 'verdict is the final aggregation stage, not an early detector'),
          copy('运行时还可接入落地页、AITM、沙箱等扩展', 'Landing-page, AITM, and sandbox modules can join at runtime'),
        ],
      },
      {
        tone: 'purple',
        title: copy('为什么要分层', 'Why it is layered'),
        items: [
          copy('独立模块可以并行，缩短分析时延', 'Independent modules can run in parallel to reduce latency'),
          copy('依赖链通过 DAG 保证顺序', 'Dependency order is enforced by the DAG'),
          copy('先模块、后引擎、再融合，才能控制重复计数', 'Module-first, engine-second, fusion-last keeps evidence from being double-counted'),
        ],
      },
    ],
  },
  'phishing-detection': {
    title: copy('钓鱼检测不是单点命中', 'Phishing detection is not a single hit'),
    caption: copy('真正的钓鱼邮件通常是“单看都不够致命，合起来才危险”。所以平台会把内容、链接、语义、身份一起看。', 'Real phishing often looks only mildly suspicious in isolation. The danger appears when content, links, semantics, and identity signals line up together.'),
    nodes: [
      { tone: 'mta', title: copy('内容引擎', 'Content engine'), subtitle: copy('钓鱼话术 / BEC / HTML', 'Lures / BEC / HTML'), edgeToNext: copy('链接引擎', 'URL engine') },
      { tone: 'relay', title: copy('链接引擎', 'URL engine'), subtitle: copy('短链 / 同形 / 落地页', 'Shorteners / homographs / landing pages'), edgeToNext: copy('语义 / 身份', 'Semantic / identity') },
      { tone: 'mta', title: copy('行为与身份', 'Behavior and identity'), subtitle: copy('首次联系人 / 回复链异常', 'First contact / thread anomalies'), edgeToNext: copy('融合与熔断', 'Fusion + breaker') },
      { tone: 'sender', title: copy('最终判定', 'Final verdict'), subtitle: copy('避免漏报', 'Prevent false negatives') },
    ],
    cards: [
      {
        tone: 'red',
        title: copy('常见风险信号', 'Common risky signals'),
        items: [
          copy('紧迫性措辞 + 金融实体 + 高管名', 'Urgency language + financial entities + executive names'),
          copy('二维码、设备码钓鱼、假登录页', 'QR lures, device-code phishing, and fake login pages'),
          copy('显示名正常但域名或链路异常', 'Normal-looking display names with abnormal domains or link paths'),
        ],
      },
      {
        tone: 'green',
        title: copy('为什么还要熔断器', 'Why the circuit breaker matters'),
        items: [
          copy('融合层可能稀释少数强信号', 'The fusion layer can dilute a minority high-confidence signal'),
          copy('高信度规则模块需要最低地板值', 'High-confidence rule modules need a minimum risk floor'),
          copy('这样才不会被大量“无信号模块”冲没', 'That keeps them from being erased by many “no signal” modules'),
        ],
      },
    ],
  },
  'ioc-intel': {
    title: copy('IOC 情报链路', 'IOC intelligence flow'),
    caption: copy('IOC 不是越多越好。真正重要的是先查本地，再控外部源，再防止系统把自己放大成误报循环。', 'More IOC is not automatically better. What matters is local-first lookup, controlled external enrichment, and strong protection against self-reinforcing false positives.'),
    nodes: [
      { tone: 'mta', title: copy('提取指标', 'Extract indicator'), subtitle: copy('IP / 域名 / URL / 哈希', 'IP / domain / URL / hash'), edgeToNext: copy('本地 IOC', 'Local IOC') },
      { tone: 'relay', title: copy('本地缓存', 'Local cache'), subtitle: copy('命中先返回', 'Return local hit first'), edgeToNext: copy('外部查询', 'External query') },
      { tone: 'mta', title: copy('外部源', 'External intel'), subtitle: copy('OTX / VT / AbuseIPDB', 'OTX / VT / AbuseIPDB'), edgeToNext: copy('TTL / 白名单', 'TTL / whitelist') },
      { tone: 'sender', title: copy('情报结果', 'Intel result'), subtitle: copy('malicious / suspicious / clean', 'malicious / suspicious / clean') },
    ],
    cards: [
      {
        tone: 'blue',
        title: copy('支持的指标', 'Supported indicators'),
        items: [
          copy('IP、邮箱、域名、附件哈希、URL、主题模式', 'IP, sender address, domain, attachment hash, URL, and subject patterns'),
          copy('每条记录都有来源、判定、置信度、TTL', 'Each record stores source, verdict, confidence, and TTL'),
          copy('admin_clean 是不会被自动覆盖的白名单来源', 'admin_clean is the protected whitelist source'),
        ],
      },
      {
        tone: 'red',
        title: copy('为什么不能低于 High 自动写入', 'Why auto-recording must stay at High or above'),
        items: [
          copy('否则 Medium 邮件能把自己的域名写进 IOC', 'Otherwise a Medium message can write its own domain into IOC storage'),
          copy('后续正常邮件会反复命中并被继续抬高分数', 'Later benign mail will keep hitting that indicator and get inflated'),
          copy('这就是典型的正反馈误报放大循环', 'That is a classic self-reinforcing false-positive loop'),
        ],
      },
    ],
  },
  'ai-nlp': {
    title: copy('AI / NLP 模型工作流', 'AI / NLP model workflow'),
    caption: copy('平台里的 NLP 不是单模型直出，而是“零样本立即可用 + 分析师反馈驱动微调”的双路径结构。', 'NLP in the platform is not a single black box. It is a dual path: zero-shot for immediate use and fine-tuning driven by analyst feedback.'),
    nodes: [
      { tone: 'mta', title: copy('邮件文本', 'Mail text'), subtitle: copy('正文 / 标题 / 上下文', 'Body / subject / context'), edgeToNext: copy('零样本或微调', 'Zero-shot or fine-tuned') },
      { tone: 'relay', title: copy('模型路径', 'Model path'), subtitle: copy('优先 fine-tuned', 'Prefer fine-tuned'), edgeToNext: copy('semantic_scan', 'semantic_scan') },
      { tone: 'mta', title: copy('语义结果', 'Semantic output'), subtitle: copy('标签 + 置信度', 'Labels + confidence'), edgeToNext: copy('D-S 融合', 'D-S fusion') },
      { tone: 'sender', title: copy('最终风险', 'Final risk'), subtitle: copy('不会单独抬地板', 'Cannot raise the floor alone') },
    ],
    cards: [
      {
        tone: 'purple',
        title: copy('模型优先级', 'Model priority'),
        items: [
          copy('若 `data/nlp_models/latest/` 可用，先走 fine-tuned', 'If `data/nlp_models/latest/` exists, fine-tuned wins'),
          copy('否则回退到零样本 mDeBERTa 路径', 'Otherwise the service falls back to the zero-shot mDeBERTa path'),
          copy('两条路径共用同一基座，但标签集不同', 'Both paths share the backbone but use different label sets'),
        ],
      },
      {
        tone: 'amber',
        title: copy('为什么 NLP 不能单独触发熔断', 'Why NLP cannot trigger the circuit breaker by itself'),
        items: [
          copy('它属于语义信号，不是强规则信号', 'It is a semantic signal, not a hard-rule signal'),
          copy('否则单个噪音模型会压过多模块安全共识', 'Otherwise one noisy model could overrule a broad safe consensus'),
          copy('它的价值是协同增强，而不是单点裁决', 'Its value is in corroboration, not single-sensor verdicting'),
        ],
      },
    ],
  },
  'soar-alerts': {
    title: copy('告警到处置的闭环', 'From alert to automated response'),
    caption: copy('安全平台真正有用的地方，不是只给分，而是把分数转换成可执行动作。', 'A security platform becomes useful when it turns scores into actions, not when it only displays numbers.'),
    nodes: [
      { tone: 'mta', title: copy('Verdict', 'Verdict'), subtitle: copy('Risk + ThreatLevel', 'Risk + threat level'), edgeToNext: copy('P0-P3', 'P0-P3') },
      { tone: 'relay', title: copy('告警分级', 'Alert priority'), subtitle: copy('EL + EVT + 冲突', 'EL + EVT + conflict'), edgeToNext: copy('规则匹配', 'Rule match') },
      { tone: 'mta', title: copy('SOAR 规则', 'SOAR rule'), subtitle: copy('等级 + 类别 + 模块', 'Level + category + modules'), edgeToNext: copy('动作执行', 'Execute') },
      { tone: 'sender', title: copy('处置动作', 'Actions'), subtitle: copy('Webhook / Log / 邮件', 'Webhook / log / email') },
    ],
    cards: [
      {
        tone: 'red',
        title: copy('告警优先级看什么', 'What drives alert priority'),
        items: [
          copy('EL 把技术风险和业务影响绑在一起', 'EL ties technical risk to business impact'),
          copy('EVT 把历史长尾里的异常提出来', 'EVT highlights events that live deep in the historical tail'),
          copy('CUSUM、冲突、时间序列异常也会抬高优先级', 'CUSUM, conflict, and temporal anomalies can raise priority too'),
        ],
      },
      {
        tone: 'cyan',
        title: copy('动作层的原则', 'Principles of the action layer'),
        items: [
          copy('规则是确定性的，方便审计和复现', 'Rules stay deterministic for auditability and reproducibility'),
          copy('Webhook 走外部系统，Log 走日志链路，Alert 走 SMTP', 'Webhook targets external systems, Log feeds the logging path, and Alert uses SMTP'),
          copy('动作异步执行，不阻塞主检测链路', 'Actions run asynchronously and do not block the main detection pipeline'),
        ],
      },
    ],
  },
  'data-security': {
    title: copy('Webmail 数据安全链路', 'Webmail data-security flow'),
    caption: copy('这块不是看 SMTP，而是看浏览器里发邮件、存草稿、传文件时的 HTTP 会话。', 'This path is not about SMTP. It watches browser-driven webmail sessions such as drafting, uploading, and sending through HTTP.'),
    nodes: [
      { tone: 'mta', title: copy('HTTP 会话', 'HTTP session'), subtitle: copy('WEBMAIL_SERVERS 命中', 'WEBMAIL_SERVERS hit'), edgeToNext: copy('字段提取', 'Extract fields') },
      { tone: 'relay', title: copy('请求解析', 'Request parsing'), subtitle: copy('from / to / subject', 'from / to / subject'), edgeToNext: copy('DLP 扫描', 'DLP scan') },
      { tone: 'mta', title: copy('事件生成', 'Incident creation'), subtitle: copy('info → critical', 'info → critical'), edgeToNext: copy('推送前端', 'Push to UI') },
      { tone: 'sender', title: copy('API / WebSocket', 'API / WebSocket'), subtitle: copy('实时展示', 'Realtime display') },
    ],
    cards: [
      {
        tone: 'amber',
        title: copy('三类重点模式', 'Three focus patterns'),
        items: [
          copy('草稿箱滥用：把敏感数据先存草稿', 'Draft-box abuse: storing sensitive data as a draft'),
          copy('文件中转滥用：借 webmail 上传链路转移文件', 'File-transit abuse: using upload flows as a transfer channel'),
          copy('自发送：把数据发给自己的邮箱', 'Self-sending: mailing sensitive data back to the same mailbox'),
        ],
      },
      {
        tone: 'green',
        title: copy('DLP 在找什么', 'What the DLP layer looks for'),
        items: [
          copy('银行卡、身份证、手机号、合同号、发票号、大额金额', 'Bank cards, ID numbers, mobile numbers, contract IDs, invoice IDs, and large financial values'),
          copy('请求体和上传文件都会扫', 'Both request bodies and uploaded files are scanned'),
          copy('命中后落 `data_security_incidents` 并推到前端', 'Hits land in `data_security_incidents` and are pushed to the frontend'),
        ],
      },
    ],
  },
  'mirror-vs-mta': {
    title: copy('镜像模式 vs MTA 代理模式', 'Mirror mode vs MTA proxy mode'),
    caption: copy('这篇最适合先看图。两种模式共用能力栈，但一个在旁路观测，一个在投递链路里内联处置。', 'This article is easiest to understand visually. Both modes share the analysis stack, but one observes passively and the other acts inline on the delivery path.'),
    nodes: [
      { tone: 'relay', title: copy('镜像口 / TAP', 'SPAN / TAP'), subtitle: copy('只复制流量', 'Traffic copy only'), edgeToNext: copy('Sniffer', 'Sniffer') },
      { tone: 'mta', title: copy('旁路模式', 'Mirror mode'), subtitle: copy('抓包 → 分析 → 告警', 'Capture → analyze → alert'), edgeToNext: copy('对照', 'Compare') },
      { tone: 'mta', title: copy('MTA 代理', 'MTA proxy'), subtitle: copy('SMTP 中继内联', 'Inline SMTP relay'), edgeToNext: copy('处置', 'Respond') },
      { tone: 'sender', title: copy('前置阻断', 'Pre-delivery control'), subtitle: copy('放行 / 隔离 / 拒绝', 'Allow / quarantine / reject') },
    ],
    cards: [
      {
        tone: 'blue',
        title: copy('镜像模式适合', 'Mirror mode is best for'),
        items: [
          copy('先观察现网流量', 'Observing production traffic first'),
          copy('调规则、查误报、做审计取证', 'Tuning rules, checking false positives, and running forensics'),
          copy('几乎不改现有邮件路径', 'Keeping changes to the mail path near zero'),
        ],
      },
      {
        tone: 'red',
        title: copy('MTA 代理模式适合', 'MTA proxy mode is best for'),
        items: [
          copy('要在投递前做实时拦截', 'Realtime blocking before delivery'),
          copy('需要隔离高风险邮件并人工复核', 'Quarantining high-risk mail for analyst review'),
          copy('接受 SMTP 路径和证书部署改造', 'Accepting SMTP-path and certificate deployment changes'),
        ],
      },
    ],
  },
  'message-bus': {
    title: copy('数据面和控制面分离', 'Separate the data plane from the control plane'),
    caption: copy('消息层不是一个 Redis 功能全包。会话数据要求可靠，命令广播要求轻量，所以分两条线。', 'The message layer does not use one Redis primitive for everything. Session data needs reliability, while command fan-out needs lightness, so the architecture splits them deliberately.'),
    nodes: [
      { tone: 'mta', title: copy('Sniffer', 'Sniffer'), subtitle: copy('会话生产者', 'Session producer'), edgeToNext: copy('Streams', 'Streams') },
      { tone: 'relay', title: copy('Redis Streams', 'Redis Streams'), subtitle: copy('数据面', 'Data plane'), edgeToNext: copy('Consumer Group', 'Consumer group') },
      { tone: 'mta', title: copy('Engine', 'Engine'), subtitle: copy('XREADGROUP / XACK', 'XREADGROUP / XACK'), edgeToNext: copy('DB / API', 'DB / API') },
      { tone: 'sender', title: copy('Pub/Sub', 'Pub/Sub'), subtitle: copy('控制广播', 'Control broadcast') },
    ],
    cards: [
      {
        tone: 'green',
        title: copy('为什么数据面走 Streams', 'Why the data plane uses Streams'),
        items: [
          copy('邮件会话和 HTTP 会话不能静默丢', 'Email and HTTP sessions must not be silently dropped'),
          copy('XACK 之后才算真正处理成功', 'A message counts as done only after XACK'),
          copy('崩溃恢复还能靠 PEL / XAUTOCLAIM 找回未完成工作', 'PEL and XAUTOCLAIM recover abandoned work after crashes'),
        ],
      },
      {
        tone: 'purple',
        title: copy('为什么控制面走 Pub/Sub', 'Why the control plane uses Pub/Sub'),
        items: [
          copy('reload、rescan、status 更像广播通知', 'reload, rescan, and status look more like broadcasts'),
          copy('这些消息轻量、幂等、可接受 fire-and-forget', 'They are lightweight, idempotent, and acceptable as fire-and-forget'),
          copy('更适合同时扇出到多个组件和 WebSocket 层', 'They fan out naturally to multiple components and the WebSocket layer'),
        ],
      },
    ],
  },
  'mta-quarantine': {
    title: copy('隔离区处置流', 'Quarantine response flow'),
    caption: copy('隔离区的价值不是“先挡住”，而是“挡住以后还保留可追溯、可放行、可删除的操作面”。', 'Quarantine is valuable not only because it stops the message, but because it preserves a reviewable, releasable, and deletable control surface afterward.'),
    nodes: [
      { tone: 'mta', title: copy('SMTP DATA', 'SMTP DATA'), subtitle: copy('收完整封邮件', 'Receive full message'), edgeToNext: copy('inline 判定', 'Inline verdict') },
      { tone: 'relay', title: copy('内联引擎', 'Inline engine'), subtitle: copy('Safe / Low / Medium / High / Critical', 'Safe / Low / Medium / High / Critical'), edgeToNext: copy('三种动作', 'Three actions') },
      { tone: 'mta', title: copy('放行 / 隔离 / 拒绝', 'Forward / quarantine / reject'), subtitle: copy('策略驱动', 'Policy driven'), edgeToNext: copy('管理员处置', 'Admin review') },
      { tone: 'sender', title: copy('释放 / 删除', 'Release / delete'), subtitle: copy('JWT 记操作人', 'JWT ties operator identity') },
    ],
    cards: [
      {
        tone: 'amber',
        title: copy('隔离区里会存什么', 'What gets stored'),
        items: [
          copy('session_id、mail_from、rcpt_to、subject、threat_level、reason', 'session_id, mail_from, rcpt_to, subject, threat_level, and reason'),
          copy('status、created_at、released_at、released_by、ttl_days', 'status, created_at, released_at, released_by, and ttl_days'),
          copy('最关键的是原始 `raw_eml`', 'Most importantly, the original `raw_eml` payload'),
        ],
      },
      {
        tone: 'red',
        title: copy('为什么这是审计链路的一部分', 'Why this is part of the audit trail'),
        items: [
          copy('放行 API 不信前端自报 released_by', 'The release API does not trust client-supplied released_by'),
          copy('操作人来自已认证 JWT 用户', 'Operator identity comes from the authenticated JWT user'),
          copy('所以后续复盘能追到是谁放行了哪封邮件', 'That preserves traceability for who released which message'),
        ],
      },
    ],
  },
  'bec-attack': {
    title: copy('BEC 攻击链', 'BEC attack chain'),
    caption: copy('BEC 的可怕之处在于它经常不带恶意文件，而是靠“像真的一样”的上下文欺骗财务流程。', 'BEC is dangerous because it often carries no malware at all. It abuses realistic context to manipulate finance workflows.'),
    nodes: [
      { tone: 'relay', title: copy('侦察', 'Reconnaissance'), subtitle: copy('组织架构 / 高管 / 财务流程', 'Org chart / executives / payment flow'), edgeToNext: copy('入侵邮箱', 'Compromise mailbox') },
      { tone: 'mta', title: copy('潜伏观察', 'Observe silently'), subtitle: copy('看真实往来', 'Watch real threads'), edgeToNext: copy('插入欺诈请求', 'Inject request') },
      { tone: 'relay', title: copy('伪造付款', 'Fake payment change'), subtitle: copy('账号替换', 'Swap receiving account'), edgeToNext: copy('资金转移', 'Transfer funds') },
      { tone: 'sender', title: copy('事后发现', 'Late discovery'), subtitle: copy('往往已转账', 'Funds already moved') },
    ],
    cards: [
      {
        tone: 'red',
        title: copy('常见变体', 'Common variants'),
        items: [
          copy('CEO 欺诈、发票欺诈、律师冒充、数据窃取、线程劫持', 'CEO fraud, invoice fraud, lawyer impersonation, data theft, and thread hijacking'),
          copy('很多攻击利用真实合作方关系来降低警惕', 'Many attacks exploit real partner relationships to lower suspicion'),
          copy('所以单看附件和病毒扫描经常不够', 'That is why attachment checks and AV alone are often insufficient'),
        ],
      },
      {
        tone: 'cyan',
        title: copy('平台重点看什么', 'What the platform emphasizes'),
        items: [
          copy('紧迫性词、转账语义、金融实体', 'Urgency language, transfer semantics, and financial entities'),
          copy('显示名与域名不匹配、首次联系人、回复链异常', 'Display-name mismatch, first contact, and reply-chain anomalies'),
          copy('AI 的 bec / spoofing / social_engineering 语义信号', 'AI-driven bec, spoofing, and social_engineering signals'),
        ],
      },
    ],
  },
  'social-engineering': {
    title: copy('社会工程学诱导路径', 'Social-engineering lure path'),
    caption: copy('技术门槛不高，但命中率可能很高，因为它打的是人的判断而不是软件漏洞。', 'The technical barrier may be low, but the success rate can be high because the target is human judgment, not a software bug.'),
    nodes: [
      { tone: 'relay', title: copy('权威 / 恐惧 / 好奇', 'Authority / fear / curiosity'), subtitle: copy('先制造情绪', 'Create an emotional trigger'), edgeToNext: copy('行动催促', 'Pressure action') },
      { tone: 'mta', title: copy('立即操作', 'Act now'), subtitle: copy('点击 / 回复 / 下载', 'Click / reply / download'), edgeToNext: copy('交付凭据或数据', 'Hand over data') },
      { tone: 'relay', title: copy('后续利用', 'Follow-on abuse'), subtitle: copy('账户接管 / 数据窃取', 'ATO / data theft'), edgeToNext: copy('平台检测', 'Platform detection') },
      { tone: 'sender', title: copy('语义识别', 'Semantic recognition'), subtitle: copy('规则 + NLP', 'Rules + NLP') },
    ],
    cards: [
      {
        tone: 'amber',
        title: copy('典型话术', 'Typical lure themes'),
        items: [
          copy('账户异常、即将冻结、限时处理、工资调整、快递异常', 'Account warnings, impending lockout, time pressure, payroll changes, and delivery exceptions'),
          copy('共同特点是制造情绪后压缩决策时间', 'The common pattern is emotional pressure plus compressed decision time'),
          copy('APT 场景里会掺真实姓名、项目名、职位名', 'APT campaigns often mix in real names, project names, and job titles'),
        ],
      },
      {
        tone: 'green',
        title: copy('平台如何识别', 'How the platform identifies it'),
        items: [
          copy('content_scan 覆盖多语言钓鱼关键词和 Unicode 归一化', 'content_scan covers multilingual phishing phrases and Unicode normalization'),
          copy('NLP 看的是语义意图，不只是关键词', 'NLP looks at intent, not only keywords'),
          copy('再叠加 SPF / DKIM / DMARC 和首次联系人的身份信号', 'Then it layers SPF / DKIM / DMARC and first-contact identity signals'),
        ],
      },
    ],
  },
  'attachment-weaponization': {
    title: copy('恶意附件投递路径', 'Malicious attachment delivery path'),
    caption: copy('附件武器化的核心不是“附件本身很奇怪”，而是“看起来像正常文档，但打开以后才开始攻击”。', 'The essence of attachment weaponization is not that the file looks obviously malicious. It looks normal until the victim opens it and the second stage begins.'),
    nodes: [
      { tone: 'mta', title: copy('伪装文件', 'Disguised file'), subtitle: copy('Office / PDF / HTML / ISO', 'Office / PDF / HTML / ISO'), edgeToNext: copy('用户打开', 'User opens') },
      { tone: 'relay', title: copy('触发逻辑', 'Trigger logic'), subtitle: copy('宏 / JS / 下载器', 'Macro / JS / dropper'), edgeToNext: copy('二阶段载荷', 'Second stage') },
      { tone: 'mta', title: copy('实际恶意行为', 'Actual malicious action'), subtitle: copy('木马 / 勒索 / 凭据窃取', 'Trojan / ransomware / credential theft'), edgeToNext: copy('平台检测', 'Platform checks') },
      { tone: 'sender', title: copy('多层校验', 'Multi-layer checks'), subtitle: copy('扩展名 + 魔数 + 文本 + 哈希', 'Extension + magic bytes + text + hash') },
    ],
    cards: [
      {
        tone: 'red',
        title: copy('高风险类型', 'High-risk file types'),
        items: [
          copy('宏文档、带脚本的 PDF、HTML 走私、双重扩展名、压缩包嵌套、ISO / IMG', 'Macro docs, scripted PDFs, HTML smuggling, double extensions, nested archives, and ISO / IMG images'),
          copy('很多场景会继续从外部再拉二阶段载荷', 'Many payloads fetch the real second stage later from outside'),
          copy('密码压缩包会明显增加分析难度', 'Password-protected archives make inspection much harder'),
        ],
      },
      {
        tone: 'cyan',
        title: copy('平台如何拆解', 'How the platform breaks it down'),
        items: [
          copy('attach_scan 先看扩展名和真实文件类型', 'attach_scan checks extension and real file type first'),
          copy('attach_hash 对 SHA-256 做本地 / 外部信誉比对', 'attach_hash compares SHA-256 against local and external reputation'),
          copy('attach_content、AV、YARA、QR 检测再补深层证据', 'attach_content, AV, YARA, and QR decoding add deeper evidence'),
        ],
      },
    ],
  },
  'link-obfuscation': {
    title: copy('链接伪装拆解图', 'Link obfuscation breakdown'),
    caption: copy('用户看到的链接文本，往往不是最终落地页。真正危险的是中间那段被编码、被重定向、被同形替换的部分。', 'What the user sees in the link text is often not the real destination. The dangerous part hides in the encoded, redirected, or homograph-swapped middle.'),
    nodes: [
      { tone: 'relay', title: copy('显示文本', 'Displayed text'), subtitle: copy('看起来像正常域名', 'Looks like a trusted domain'), edgeToNext: copy('真实 href', 'Real href') },
      { tone: 'mta', title: copy('跳转链路', 'Redirect chain'), subtitle: copy('短链 / 参数 / 编码', 'Shortener / params / encoding'), edgeToNext: copy('真实域名', 'Real host') },
      { tone: 'relay', title: copy('落地页', 'Landing page'), subtitle: copy('登录页 / 钓鱼页', 'Login page / phish'), edgeToNext: copy('平台检测', 'Platform checks') },
      { tone: 'sender', title: copy('风险揭示', 'Risk surfaced'), subtitle: copy('结构 + 情报 + 抓取内容', 'Structure + intel + fetched content') },
    ],
    cards: [
      {
        tone: 'amber',
        title: copy('常见伪装手法', 'Common obfuscation techniques'),
        items: [
          copy('href / 文本不一致、短链、多重重定向、URL 编码、@ 符号、data URI', 'href/text mismatch, shorteners, multi-hop redirects, URL encoding, at-sign abuse, and data URIs'),
          copy('IDN 同形攻击让域名视觉上像真站', 'IDN homographs make a fake domain look visually legitimate'),
          copy('很多攻击把真实风险藏在参数和中间跳板里', 'Many attacks hide the risk inside parameters and intermediate hops'),
        ],
      },
      {
        tone: 'green',
        title: copy('平台如何还原真实目标', 'How the platform reveals the real target'),
        items: [
          copy('link_scan 先做结构和模式检查', 'link_scan starts with structural and pattern checks'),
          copy('link_reputation 再接本地 IOC 和外部情报', 'link_reputation adds local IOC and external intelligence'),
          copy('link_content / landing_page_scan 最后看抓到的页面内容', 'link_content and landing_page_scan finally inspect the fetched page content'),
        ],
      },
    ],
  },
}

export function TopicVisualShowcase({ topicId, language }: { topicId: TopicId; language: string }) {
  const visual = topicVisuals[topicId]
  if (!visual) return null

  return (
    <section className="sk-showcase" aria-label={pickText(visual.title, language)}>
      <div className="sk-showcase-header">
        <span className="sk-showcase-eyebrow">{language.startsWith('en') ? 'Visual Guide' : '图解'}</span>
        <h2 className="sk-showcase-title">{pickText(visual.title, language)}</h2>
        <p className="sk-showcase-caption">{pickText(visual.caption, language)}</p>
      </div>

      <TopicIllustration topicId={topicId} language={language} />

      <div className="sk-flow sk-showcase-flow">
        {visual.nodes.map((node, index) => (
          <div className="sk-showcase-flow-fragment" key={`${topicId}-${index}`}>
            <div className="sk-flow-node">
              <div className={`sk-flow-icon ${node.tone}`}>
                <FlowNodeIcon tone={node.tone} />
              </div>
              <div className="sk-flow-label">{pickText(node.title, language)}</div>
              <div className="sk-flow-sub">{pickText(node.subtitle, language)}</div>
            </div>
            {node.edgeToNext && (
              <div className="sk-flow-arrow">
                <span>{pickText(node.edgeToNext, language)}</span>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="sk-cards-row sk-showcase-cards">
        {visual.cards.map((card, index) => (
          <div className="sk-info-card sk-showcase-card" key={`${topicId}-card-${index}`}>
            <div className={`sk-info-card-header ${card.tone}`}>{pickText(card.title, language)}</div>
            <ul>
              {card.items.map((item, itemIndex) => (
                <li key={`${topicId}-card-${index}-item-${itemIndex}`}>{pickText(item, language)}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  )
}
