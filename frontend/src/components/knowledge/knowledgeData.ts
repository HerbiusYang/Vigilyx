import { englishTopics } from './knowledgeEnglish'

export type TopicId = 'mta' | 'opportunistic-tls' | 'mandatory-tls' | 'starttls' | 'spf-dkim-dmarc' | 'ds-fusion' | 'temporal-evt' | 'module-pipeline' | 'phishing-detection' | 'ioc-intel' | 'ai-nlp' | 'soar-alerts' | 'data-security' | 'mirror-vs-mta' | 'message-bus' | 'mta-quarantine' | 'bec-attack' | 'social-engineering' | 'attachment-weaponization' | 'link-obfuscation'

interface TopicSection {
  heading: string
  plainText: string
  headingEn?: string
  plainTextEn?: string
}

export type CategoryFilter = 'all' | 'email-security' | 'general' | 'platform'

export interface TopicEntry {
  id: TopicId
  title: string
  titleEn?: string
  subtitle: string
  subtitleEn?: string
  lead: string
  leadEn?: string
  tag: string
  tagEn?: string
  tagClass: string
  iconType: 'mail' | 'lock-open' | 'lock-closed' | 'code' | 'shield' | 'analytics'
  category: CategoryFilter
  sections: TopicSection[]
  searchableText: string
  keywords: string[]
  readingTime: number
  referenceUrl?: string
}

export const categoryFilters: CategoryFilter[] = ['all', 'email-security', 'general', 'platform']

function buildSearchableText(entry: Omit<TopicEntry, 'searchableText' | 'readingTime'>): string {
  const parts = [
    entry.title,
    entry.titleEn || '',
    entry.subtitle,
    entry.subtitleEn || '',
    entry.lead,
    entry.leadEn || '',
    ...entry.keywords,
    ...entry.sections.flatMap(s => [s.heading, s.headingEn || '', s.plainText, s.plainTextEn || '']),
  ]
  return parts.join(' ').toLowerCase()
}

function estimateReadingTime(text: string): number {
  // ~300 chars/min for mixed Chinese+English
  return Math.max(2, Math.ceil(text.length / 300))
}

const rawTopics: Omit<TopicEntry, 'searchableText' | 'readingTime'>[] = [
  {
    id: 'mta',
    title: '什么是 MTA',
    subtitle: 'Mail Transfer Agent 邮件传输代理',
    lead: 'MTA 是负责在互联网上传递电子邮件的服务器软件。每封邮件从发送到接收，至少经过 2 个 MTA。',
    tag: '基础',
    tagClass: 'sk-tag-blue',
    referenceUrl: 'https://en.wikipedia.org/wiki/Message_transfer_agent',
    iconType: 'mail',
    category: 'general',
    keywords: ['MTA', 'Mail Transfer Agent', 'Postfix', 'Sendmail', 'Exim', 'Exchange', 'Coremail', 'SMTP', 'MUA', 'MDA', 'MSA', 'Mail User Agent', 'Mail Delivery Agent', 'Mail Submission Agent', '邮件传输代理', '邮件投递'],
    sections: [
      {
        heading: '核心概念',
        plainText: 'MTA Mail Transfer Agent 邮件传输代理 是电子邮件基础设施的核心组件。它的职责是接收邮件并将其路由到下一个目的地，类似于现实中的邮局分拣中心。常见的 MTA 软件：Postfix、Sendmail、Exim、Microsoft Exchange、Coremail',
      },
      {
        heading: '邮件投递流程',
        plainText: '当你发送一封邮件时，它会经过以下路径：发件人 MUA 邮件客户端 通过 SMTP 587 连接到 发件 MTA 如 smtp.gmail.com 然后通过 SMTP 25 转发到 中继 MTA 网关过滤 再到 收件 MTA 通过 MX 记录定位 最后通过 POP3 IMAP 到达 收件人 MUA 邮件客户端',
      },
      {
        heading: 'MTA 与 Vigilyx 的关系',
        plainText: 'Vigilyx 支持两种邮件流量接入方式。旁路镜像模式通过抓包观察 MTA 之间的 SMTP 会话，适合事后审计与告警；MTA 代理模式则直接作为 SMTP 中继接收邮件，在投递前完成解析 判定与可选隔离或拦截。两种模式共享同一套解析器与检测引擎，只是介入时机不同。MTA Mail Transfer Agent 负责服务器间转发邮件。MUA Mail User Agent 是 Outlook Thunderbird 等用户客户端。MDA Mail Delivery Agent 负责本地投递。MSA Mail Submission Agent 接收用户提交邮件，常见端口为 587。',
      },
    ],
  },
  {
    id: 'opportunistic-tls',
    title: '什么是机会性 TLS',
    subtitle: 'Opportunistic TLS / STARTTLS 升级',
    lead: '机会性 TLS 是一种"能加密就加密，不能就算了"的策略。它是当今 MTA 之间最主流的加密方式，但存在被降级攻击的风险。',
    tag: '加密',
    tagClass: 'sk-tag-amber',
    iconType: 'lock-open',
    category: 'email-security',
    keywords: ['Opportunistic TLS', 'STARTTLS', 'TLS', 'encryption', '加密', 'STRIPTLS', '降级攻击', 'downgrade attack', 'EHLO', '机会性加密', '明文', 'plaintext'],
    sections: [
      {
        heading: '工作原理',
        plainText: '机会性 TLS 的流程如下：发件 MTA 连接到收件 MTA 建立普通的 TCP 连接 端口 25 此时是明文。EHLO 握手 发件方发送 EHLO 命令 收件方返回支持的扩展列表。检查是否支持 STARTTLS 如果收件方在响应中包含 250-STARTTLS 说明它支持 TLS 升级。发送 STARTTLS 命令 发件方发送 STARTTLS 收件方回复 220 Ready to start TLS。TLS 握手 双方进行 TLS 协商 后续所有 SMTP 通信均通过加密信道传输',
      },
      {
        heading: '机会性 TLS 的关键特征',
        plainText: '优势：无需预配置 自动协商。向后兼容不支持 TLS 的服务器。部署成本极低 广泛使用。比完全不加密好得多。风险：可被 STRIPTLS 降级攻击。通常不验证服务器证书。中间人可篡改 EHLO 响应。用户无法感知是否加密',
      },
      {
        heading: '降级攻击 (STRIPTLS Attack)',
        plainText: '这是机会性 TLS 最大的安全隐患。攻击者在网络中间 如路由器 ISP 拦截流量 修改 EHLO 响应 删除 250-STARTTLS 行。发件 MTA 看不到 STARTTLS 支持 就会退回到明文传输。Vigilyx 中的体现：如果你在 SMTP 对话中看到服务端支持 STARTTLS 但最终会话未加密 可能遭遇了降级攻击或客户端未发起 STARTTLS',
      },
      {
        heading: '与 Vigilyx 抓包的关系',
        plainText: 'STARTTLS 成功 EHLO STARTTLS 命令可见 之后为加密密文 无法还原邮件内容。未发起 STARTTLS 全部 SMTP 对话明文可见 可完整还原邮件。端口 465 隐式 TLS 从第一个包起就是加密 完全不可见',
      },
    ],
  },
  {
    id: 'mandatory-tls',
    title: '什么是强制 TLS',
    subtitle: 'Mandatory TLS / DANE / MTA-STS',
    lead: '强制 TLS 要求 MTA 之间的通信必须加密。如果无法建立加密通道，邮件将被拒绝发送，而非降级为明文。',
    tag: '加密',
    tagClass: 'sk-tag-green',
    iconType: 'lock-closed',
    category: 'email-security',
    keywords: ['Mandatory TLS', 'MTA-STS', 'DANE', 'DNSSEC', 'TLSA', 'RFC 8461', 'RFC 7672', '强制加密', 'enforce', 'TLS Policy', 'Postfix', 'certificate', '证书'],
    sections: [
      {
        heading: '为什么需要强制 TLS',
        plainText: '机会性 TLS 的根本问题是加密是可选的。攻击者可以通过 STRIPTLS 攻击强制降级为明文。强制 TLS 解决的正是这个问题。机会性 TLS 尝试加密 失败则回退到明文。强制 TLS 必须加密 失败则拒绝发送',
      },
      {
        heading: '实现方式',
        plainText: 'MTA-STS RFC 8461 收件域名发布一个 HTTPS 策略文件 声明所有发往本域的邮件必须使用 TLS 发件 MTA 在发送前查询此策略 mode 可选值 enforce 强制 testing 仅报告 none 禁用。DANE RFC 7672 通过 DNSSEC 在 DNS 中发布 TLSA 记录 绑定邮件服务器的 TLS 证书指纹 发件 MTA 通过 DNS 验证证书真实性 依赖 DNSSEC 部署门槛较高 但安全性极强 免疫 CA 被入侵的风险。手动配置 TLS Policy 在 Postfix 等 MTA 中手动指定对特定域名强制 TLS 适用于已知的合作方域名 无法覆盖所有收件域',
      },
      {
        heading: '机会性 TLS vs 强制 TLS 完整对比',
        plainText: '加密失败时 机会性回退到明文 强制拒绝发送。证书验证 机会性通常不验证 强制必须验证。防降级攻击 机会性不能 强制能。部署难度 机会性极低默认行为 强制较高需 DNS 策略配置。兼容性 机会性最好全球适用 强制一般需对方也支持。Vigilyx 可见性 机会性 STARTTLS 前明文可见 强制完全不可见',
      },
    ],
  },
  {
    id: 'starttls',
    title: 'STARTTLS 命令详解',
    subtitle: '明文到加密的协议升级过程',
    lead: 'STARTTLS 是一种协议扩展命令，用于将已建立的明文连接就地升级为 TLS 加密连接。它是实现机会性 TLS 的核心机制。',
    tag: '协议',
    tagClass: 'sk-tag-purple',
    iconType: 'code',
    category: 'email-security',
    keywords: ['STARTTLS', 'SMTP', 'EHLO', 'TLS handshake', 'implicit TLS', '显式 TLS', '隐式 TLS', 'port 25', 'port 465', 'port 587', '协议升级', 'protocol upgrade', 'Postfix', 'ESMTP'],
    sections: [
      {
        heading: 'SMTP 中的 STARTTLS 交互过程',
        plainText: '以下是一次典型的 SMTP STARTTLS 会话 Vigilyx 可以完整捕获加密前的明文部分。220 mail.example.com ESMTP Postfix EHLO sender.example.org 250-mail.example.com 250-SIZE 52428800 250-STARTTLS 服务器声明支持 STARTTLS 250 8BITMIME STARTTLS 客户端请求升级加密 220 2.0.0 Ready to start TLS 开始 TLS 握手 后续 SMTP 命令均加密 MAIL FROM DATA 等',
      },
      {
        heading: 'STARTTLS vs 隐式 TLS',
        plainText: 'STARTTLS 显式 TLS 端口 25 MTA 间 587 提交 连接方式先明文再升级加密 握手可见性 EHLO STARTTLS 明文可抓 适用场景 MTA 之间端口 25。隐式 TLS 端口 465 提交 连接即加密 TLS 包裹 第一个包即密文 适用场景 MUA MSA 端口 465',
      },
    ],
  },
  {
    id: 'spf-dkim-dmarc',
    title: 'SPF / DKIM / DMARC',
    subtitle: '邮件发件人验证三件套',
    lead: '这三种机制共同解决一个问题：这封邮件真的是它声称的发件人发送的吗？',
    tag: '认证',
    tagClass: 'sk-tag-cyan',
    iconType: 'shield',
    category: 'email-security',
    keywords: ['SPF', 'DKIM', 'DMARC', 'Sender Policy Framework', 'DomainKeys Identified Mail', 'Domain-based Message Authentication', 'DNS', 'TXT record', 'email authentication', '发件人验证', '伪造', 'spoof', 'phishing', '钓鱼'],
    sections: [
      {
        heading: '三者关系',
        plainText: 'SPF Sender Policy Framework 在 DNS 中声明哪些 IP 有权代表我的域名发送邮件 收件 MTA 检查发件 IP 是否在授权列表中 v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all。DKIM DomainKeys Identified Mail 发件 MTA 使用私钥对邮件头和正文签名 收件方通过 DNS 获取公钥验证 可确保邮件在传输中未被篡改 DKIM-Signature v=1 a=rsa-sha256 d=example.com。DMARC Domain-based Message Authentication 基于 SPF 和 DKIM 的策略层 域名所有者声明如果 SPF 和 DKIM 都未通过 应该如何处理 放行 隔离 拒绝 v=DMARC1 p=reject rua=mailto:dmarc@example.com',
      },
      {
        heading: '与传输加密 (TLS) 的区别',
        plainText: 'SPF DKIM DMARC 解决的是认证问题 TLS 解决的是加密问题。一封邮件可以是加密传输 TLS 但发件人是伪造的 无 SPF DKIM 也可以是明文传输但发件人是真实的。两者互补 缺一不可',
      },
    ],
  },
  {
    id: 'ds-fusion',
    title: 'D-S 证据理论与多引擎融合',
    subtitle: 'D-S uncertainty theory, clustered fusion & legacy Murphy',
    lead: 'Vigilyx 的默认邮件管线通过 DAG 编排检测模块与最终判定阶段。正式融合使用 clustered_ds_v2：先执行证据准入和因果物件去重，再做单边 BPA 融合及具名约束。旧版 V1/Murphy 实现已移除，历史配置名加载时迁移到 V2。模块是否执行仍取决于条件、外部服务及显式启用配置。',
    tag: '风险模型',
    tagClass: 'sk-tag-red',
    iconType: 'analytics',
    category: 'platform',
    keywords: ['Dempster-Shafer', 'D-S', '证据理论', 'BPA', 'belief', 'disbelief', 'uncertainty', '不确定性', 'Murphy', '融合', 'fusion', 'Jousselme', '距离', 'Zadeh', '悖论', 'Copula', '依赖校正', '主观逻辑', 'subjective logic', 'Noisy-OR', '贝叶斯', 'Bayesian', '多引擎', 'risk score', '风险分数', 'BEC', 'phishing', 'ATO', '对抗鲁棒性', 'robustness', 'diversity'],
    sections: [
      {
        heading: '为什么需要 D-S 证据理论',
        plainText: '传统贝叶斯方法用单一概率 P(threat) 表达威胁程度。当一个检测模块无法判断时，它只能输出 P=0.5，但这与模块明确认为50%概率是威胁完全不同。前者是不确定 后者是确定的中等风险。Noisy-OR 模型假设各证据源独立，无法处理证据冲突。当两个模块一个说高危一个说安全时 Noisy-OR 简单地相乘 无法表达冲突本身就是重要信号。Dempster-Shafer 证据理论引入三值表示 belief disbelief uncertainty 显式区分确定性判断和不确定状态 为多源融合提供了理论基础',
      },
      {
        heading: 'BPA 三元组：显式不确定性建模',
        plainText: '在辨识框架 Θ = {Threat, Normal} 上定义基本概率赋值 Basic Probability Assignment BPA 简化为三元组 b d u。b belief 对 Threat 的信度 即恶意信度。d disbelief 对 Normal 的信度 即正常信度。u uncertainty 分配给整个框架 Θ 的质量 表示不确定度。约束条件 b + d + u = 1。从传统评分转换：给定模块输出 score confidence，b = score × confidence，d = (1-score) × confidence，u = 1 - confidence。风险分数计算 Risk = b + η × u，η 是可配置的风险态度参数；Vigilyx 当前编译默认值为 0.30。Pignistic 概率：P_bet(Threat) = b + u/2，将不确定性均匀分配',
      },
      {
        heading: 'Dempster 合成规则与 Zadeh 悖论',
        plainText: '给定两个 BPA m₁ 和 m₂ Dempster 合成规则通过正交和计算联合信度。冲突因子 K = m₁(T)·m₂(N) + m₁(N)·m₂(T)。合成结果 m(T) = [m₁(T)·m₂(T) + m₁(T)·m₂(Θ) + m₁(Θ)·m₂(T)] / (1-K)。m(N) = [m₁(N)·m₂(N) + m₁(N)·m₂(Θ) + m₁(Θ)·m₂(N)] / (1-K)。m(Θ) = m₁(Θ)·m₂(Θ) / (1-K)。Zadeh 悖论：当两个证据源高度冲突时 K 接近 1 分母趋近于零 合成结果将少量一致证据放大到极端 产生反直觉结论。例如传感器A说99%是Threat 传感器B说99%是Normal K=0.98 合成后可能给出一个荒谬的高确信结果。需要在融合前进行冲突预处理',
      },
      {
        heading: '旧版 Murphy 修正融合算法（已移除的 Murphy）',
        plainText: '以下算法仅作历史数学背景；旧版 Murphy 运行实现已经移除。Murphy 修正通过证据距离加权平均预处理解决 Zadeh 悖论。第一步 Jousselme 证据距离。d_J(m₁, m₂) = sqrt(0.5 · (m₁-m₂)ᵀ · D · (m₁-m₂))，D 矩阵基于焦元的 Jaccard 相似度。对于二元框架 D 为 3×3 矩阵 对角线为 1 |T∩N|/|T∪N|=0 |T∩Θ|/|T∪Θ|=0.5。第二步 相似度与可信度。sim(i,j) = 1 - d_J(i,j)。crd(i) = Σⱼ≠ᵢ sim(i,j) 可信度等于与其他所有证据的相似度之和。w_i = crd(i) / Σ crd(j) 归一化权重。第三步 加权平均。m_avg = Σ w_i · m_i 得到消除冲突后的平均证据。第四步 自合成。m_final = m_avg ⊕ m_avg ⊕ ... 共 N-1 次 Dempster 合成 N 为引擎数量 多次自合成增强证据收敛性',
      },
      {
        heading: '旧版路径中的 Copula 依赖校正',
        plainText: 'Dempster 合成规则假设证据源之间相互独立。但实际系统中 内容分析引擎与语义意图引擎可能共享文本特征 URL 分析与内容分析可能观察到相同的钓鱼 URL 这种相关性会导致证据被重复计算。旧版 已移除的 Murphy 路径的 Copula 依赖校正通过相关系数矩阵 R 量化引擎间相关性；当前默认 clustered_ds_v2 不执行此步骤。对于相关系数 ρ_ij 较高的引擎对 在融合前注入不确定性：b_i_new = b_i × (1 - ρ_ij)，u_i_new = u_i + (b_i + d_i) × ρ_ij。直觉是 相关的引擎给出的证据要打折扣 因为它们不是真正独立的信息源。这些相关系数示例属于旧版 A–H 引擎配置，不是默认 clustered_ds_v2 的参数。',
      },
      {
        heading: '当前默认路径的八个证据簇',
        plainText: '默认路径把归一化检测信号归入八个 EvidenceClusterId：inherited_gateway_prior（继承的网关先验）、delivery_integrity（投递完整性）、sender_identity_authenticity（发件人身份真实性）、link_and_html_deception（链接与 HTML 欺骗）、payload_malware（载荷恶意软件）、external_reputation_ioc（外部信誉与 IOC）、social_engineering_intent（社会工程意图）和 business_sensitivity（业务敏感度）。系统先按稳定因果键去重，将每个物件归入一个融合簇。簇内合并物件质量，再将各簇与合格正常证据组合一次；场景规则另行使用归一化来源和因果键。',
      },
      {
        heading: '旧版融合的多样性约束',
        plainText: '旧版 已移除的 Murphy 路径包含引擎多样性权重约束；当前默认 clustered_ds_v2 不使用 40% 单引擎权重上限。默认路径通过因果键去重、物件级单边融合和具备独立证据准入条件的风险地板处理多源重复与融合稀释。',
      },
    ],
  },
  {
    id: 'temporal-evt',
    title: '时序分析与尾部风险告警',
    subtitle: 'Temporal Analysis, HMM Attack Phase & EVT Alert',
    lead: '单封邮件的安全分析无法捕捉跨时间窗口的渐进攻击模式。时序分析层运行在单邮件判定之后，通过 CUSUM 变点检测、双速 EWMA 基线漂移、HMM 攻击阶段推断和通信图谱异常检测，识别"温水煮青蛙"式的高级威胁。',
    tag: '风险模型',
    tagClass: 'sk-tag-red',
    iconType: 'analytics',
    category: 'platform',
    keywords: ['CUSUM', 'EWMA', 'HMM', 'Hidden Markov Model', '隐马尔可夫', '时序分析', 'temporal', '变点检测', 'change point', '基线漂移', 'drift', '实体风险', 'entity risk', '攻击阶段', 'attack phase', '通信图谱', 'communication graph', 'GPD', 'EVT', '极值理论', 'Extreme Value Theory', 'Generalized Pareto', 'P0', 'P1', 'P2', 'P3', '告警', 'alert', '期望损失', 'expected loss', 'CVaR', '重现期', 'return period', 'BEC', 'ATO', '温水煮青蛙'],
    sections: [
      {
        heading: '时序分析层的定位',
        plainText: '旁路监测系统的独特优势在于可以观察到所有邮件流量的完整时间序列。单封邮件分析只能回答这封邮件是否危险 时序分析层回答这个发件人的行为是否在逐渐变化。这对于 BEC 商业邮件妥协和 ATO 账户接管攻击尤为关键 攻击者通常先建立信任再实施攻击 每一封邮件单独看可能风险不高 但时间维度上的模式揭示真实意图。时序分析在单邮件判定 verdict 产出后异步运行 不阻塞下一封邮件处理',
      },
      {
        heading: 'CUSUM 累积和变点检测',
        plainText: 'CUSUM Cumulative Sum 是经典的序列变点检测算法 用于检测发件人风险水平的突然偏移。正向累积和 S⁺(t) = max(0, S⁺(t-1) + r(t) - μ₀ - k)。其中 r(t) 为第 t 封邮件的风险分数 μ₀ 为该发件人的历史正常风险均值 k 为容许偏差 取 0.5σ。报警条件 当 S⁺(t) > h 时触发 h 为报警阈值 取 4σ。直觉解释 CUSUM 在每一步累积风险偏离正常水平的量 如果偏离是随机波动 累积和会被 max(0,...) 重置为零。只有持续偏高的风险才会使 S⁺ 不断累积突破阈值。k 控制灵敏度 k 越小越灵敏 h 控制误报率 h 越大误报越少',
      },
      {
        heading: '双速 EWMA 基线漂移检测',
        plainText: '指数加权移动平均 EWMA 用两个不同速度追踪发件人的行为基线。快速 EWMA E_fast(t) = α_f × r(t) + (1-α_f) × E_fast(t-1) 其中 α_f = 0.05 对应约 20 封邮件的记忆窗口。慢速 EWMA E_slow(t) = α_s × r(t) + (1-α_s) × E_slow(t-1) 其中 α_s = 0.005 对应约 200 封邮件的记忆窗口。漂移分数 drift = |E_fast - E_slow| / max(E_slow, ε) 其中 ε 是一个小常数防止除零。当快速基线显著偏离慢速基线时 说明发件人的行为正在发生变化。温水煮青蛙的数学指纹 如果攻击者每天只略微提高风险 单日的变化不会触发 CUSUM 但快慢 EWMA 的分离会逐渐加大 漂移分数升高即可报警',
      },
      {
        heading: '实体风险累积模型',
        plainText: '每封邮件只更新一个长期基线键：普通域名按注册域聚合，公共邮箱服务商（如 qq.com、gmail.com）按完整发件地址隔离用户基线。风险值默认 α=0.92；风险上升时，新观测以 8% 权重融入历史；风险下降时，良性观测的权重减半为 4%，实体仍在观察名单（默认阈值 0.30）时再降为 2%，避免短暂的干净流量迅速洗掉风险。首次观测直接初始化风险值。',
      },
      {
        heading: 'HMM 五状态攻击阶段推断',
        plainText: '隐马尔可夫模型 Hidden Markov Model 用于推断发件人-收件人对之间的攻击阶段。五个隐状态 S0 正常通信 S1 侦察阶段 S2 信任建立 S3 攻击实施 S4 收割获利。默认转移矩阵中 S0→S0 为 0.990、S0→S1 为 0.008、S1→S2 为 0.050、S2→S3 为 0.030、S3→S4 为 0.100；其余概率分配给其他转移和自循环。模型支持观测 (risk_single, u_final, K_conflict, 时间间隔, 内容相似度变化)，但当前生产路径将内容相似度变化固定传入 0.0，因此该特征尚未参与线上推断。每个状态有对应的发射概率分布。前向算法在线推断后验概率 γ_t(s) = P(S_t=s | O₁...O_t)。时序风险 Risk_temporal = Σ γ_t(s) × w_s 其中权重 w = {0.0, 0.3, 0.5, 1.0, 1.0} 对应五个状态',
      },
      {
        heading: '通信图谱异常检测',
        plainText: '维护一个有向加权图 节点为邮箱地址 边为通信记录 包含频率和风险历史。三种异常模式。模式一 新发件人群发 一个首次出现的发件人短时间内向大量收件人发送邮件 典型的群发钓鱼。默认条件是：首次观测不超过 24 小时的发件人出度达到 10；已观测超过 24 小时的发件人出现风险分数高于 0.5 的新边；或历史出度大于 3 且新增收件人后，新旧出度比超过默认 3 倍。图谱参数可配置。',
      },
      {
        heading: 'GPD 极值理论与尾部风险',
        plainText: '广义帕累托分布 Generalized Pareto Distribution 用于建模风险分数的极端尾部行为。仅对超过阈值 u 的观测值拟合 P(X > x | X > u) = (1 + ξ(x-u)/σ)^{-1/ξ}。阈值 u 取历史风险分数的 95 分位数。形状参数 ξ 决定尾部厚度 ξ > 0 为重尾 Frechet 分布 ξ = 0 为指数尾。尺度参数 σ 决定尾部展宽程度。参数通过 PWM 概率加权矩方法拟合。令 N 为窗口样本数、N_u 为超过阈值 u 的样本数，超阈值率 p_u=N_u/N；代码用 T=1/(p_u×P(X>x|X>u)) 计算以样本数计的重现期。反解得到 VaR_T=u+(σ/ξ)×[(p_u×T)^ξ−1]（ξ 接近 0 时取指数极限）。对 ξ<1，超越 VaR_T 的条件期望为 CVaR_T=VaR_T+[σ+ξ(VaR_T−u)]/(1−ξ)。T 表示观测样本间隔，不是年份。',
      },
      {
        heading: 'P0-P3 动态告警分级',
        plainText: '仅当 Risk_final≥0.15 才生成告警。EL=Risk_final×收件人影响权重，默认权重 1.0；匹配 ceo@ 为 5.0、cfo@/finance@ 为 4.5、it-admin@ 为 4.0、admin@ 为 3.5，并取所有收件人中的最高值。P0 条件：EL≥3、K_conflict>0.7、EVT T≥10000，或 Risk_final≥0.4 时 CUSUM 告警 / Hawkes 比率>5。P1 条件：EL≥1.5、EVT T≥1000、HMM 攻击阶段 γ(S3)>0.3、Hawkes 比率>3、Novelty>0.6 或 K_cross>0.5。P2 条件：EL≥0.5、u_final>0.6、EVT T≥100、HMM 信任建立阶段 γ(S2)>0.25、通信图异常、Novelty>0.3，或 Risk_final<0.4 时的 CUSUM 告警。没有更高等级信号时，达到 Risk_final≥0.15 的邮件为 P3；P3 记录受全局每分钟 30 条限流，超额单条告警会被抑制并在后续窗口生成汇总告警。系统按最严重的匹配条件定级。EVT 的 T 以样本数计。',
      },
    ],
  },
  {
    id: 'module-pipeline',
    title: '安全模块管线与融合实现',
    subtitle: 'Security Module Pipeline & D-S Fusion Integration',
    lead: 'Vigilyx 的默认邮件管线通过 DAG 编排检测模块与最终判定阶段。正式融合使用 clustered_ds_v2：先执行证据准入和因果物件去重，再做单边 BPA 融合及具名约束。旧版 V1/Murphy 实现已移除，历史配置名加载时迁移到 V2。模块是否执行仍取决于条件、外部服务及显式启用配置。',
    tag: '风险模型',
    tagClass: 'sk-tag-red',
    iconType: 'analytics',
    category: 'platform',
    keywords: ['模块', 'module', 'pipeline', '管线', 'SecurityModule', 'ModuleResult', '编排', 'orchestrator', 'DAG', '并行', 'parallel', 'timeout', '超时', 'score', 'confidence', 'BPA', '转换', 'conversion', '引擎映射', 'engine map', 'content_scan', 'domain_verify', 'link_scan', 'header_scan', 'semantic_scan', 'anomaly_detect', 'attach_scan', '融合管线', 'fusion pipeline', 'Dempster', 'Copula', 'Murphy', '信任折扣', 'trust discount', 'threat level', '威胁等级'],
    sections: [
      {
        heading: '模块系统架构',
        plainText: '模块的 score 和 confidence 仍显示原始检测结果。正式 D-S V2 按因果物件去重，再用强度、置信度与证据簇可靠性形成单边恶意质量 b；没有独立的正常证据时 d=0，其余质量保留为 u。低模块分数不会自动成为正常证据，原始模块 BPA 与 V2 物件 BPA 需要分别解读。',
      },
      {
        heading: '默认管线与扩展模块',
        plainText: '编译默认配置包含 29 个条目：content_scan、html_scan、html_pixel_art、attach_scan、attach_content、attach_qr_scan、attach_hash、mime_scan、header_scan、link_scan、link_reputation、link_content、landing_page_scan、url_sandbox_scan、process_sandbox_scan、anomaly_detect、aitm_detect、rmm_detect、prompt_injection_scan、toad_detect、semantic_scan、domain_verify、identity_anomaly、transaction_correlation、av_eml_scan、av_attach_scan、sandbox_scan、yara_scan 与 verdict。QR、落地页、AITM 和沙箱模块已在默认配置中；部分模块受依赖条件、外部服务或显式 opt-in 门控，因此“有配置项”不代表每封邮件都会执行。verdict 是最终汇总阶段，不是独立检测模块。',
      },
      {
        heading: '管线编排器：事件驱动的 DAG 调度',
        plainText: '完整异步管线根据模块元数据中的 depends_on 和配置中的 ConditionConfig 构建 DAG，并用拓扑排序检查是否存在循环依赖。运行时采用事件驱动调度：所有根节点立即并发启动；节点完成后，其后继节点只要所有依赖都已完成，就会立即启动，不等待其他节点或整层结束。条件中的 depends_module 用于建立依赖，并指定 min_threat_level 检查的模块；若硬依赖因禁用而没有结果，节点会跳过并标记检查不完整。MTA inline 中，检测模块若依赖被延后的模块也会跳过并标记不完整；最终 verdict 只等待已选入 inline 管线的依赖。阻断判定的模块执行失败/超时或必需依赖不可用时，MTA 返回临时失败（默认 451；启用 fail-open 时可能继续转发，且仍执行出站 DLP 处置）。遇到依赖缺失且没有仍在超时中的 inline 模块时，系统会先把 inline 判定结果交给 MTA 处理流程，再启动完整管线记录诊断；后续结果只用于审计和界面展示，不改变处理流程根据 inline 判定选择的投递动作。判定已完成但 Safe/Low 结果带有覆盖不完整标记时，会转入隔离。link_reputation 的外部情报失败属于非阻断可用性问题，不会单独阻止放行。重复或未知启用模块 ID、依赖环，以及未绑定 depends_module 的 min_threat_level 都会被配置接口拒绝，避免判断受并发完成顺序影响。should_run 与 ConditionConfig 也可跳过当前消息不适用的模块；每个执行中的模块有独立超时，失败或超时会记录占位结果和状态。MTA inline 判定另有受限模块集合与优先级，不等同于完整异步管线。',
      },
      {
        heading: '从评分到三元组：模块输出转换',
        plainText: '模块的 score 和 confidence 仍显示原始检测结果。正式 D-S V2 按因果物件去重，再用强度、置信度与证据簇可靠性形成单边恶意质量 b；没有独立的正常证据时 d=0，其余质量保留为 u。低模块分数不会自动成为正常证据，原始模块 BPA 与 V2 物件 BPA 需要分别解读。',
      },
      {
        heading: '八个证据簇与因果来源',
        plainText: '当前默认路径先将归一化信号映射到八个 EvidenceClusterId：inherited_gateway_prior、delivery_integrity、sender_identity_authenticity、link_and_html_deception、payload_malware、external_reputation_ioc、social_engineering_intent 和 business_sensitivity。V2 先按稳定因果键去重，每个物件保留最强的完整强度/可靠性组合，簇内合并后将各簇与合格正常证据组合一次。具名场景约束另行检查归一化来源及因果键。模块 ID 属于配置和分析结果；配置存在不代表每封邮件都会执行，也不代表模块会按 A–H 引擎分组直接投票。',
      },
      {
        heading: '默认 clustered_ds_v2 来源融合',
        plainText: '正式 clustered_ds_v2 对每个物件保留最强的完整强度/可靠性组合，同一物件的多个检测器不会重复投票。不同物件在簇内合并，再对簇与有来源依据的正常证据执行一次对称多元组合；恶意与正常的冲突进入不确定性，不做加权均值的重复自合成。只有完整覆盖及经过密码学验证的对齐身份等合格来源能够提供正常质量。',
      },
      {
        heading: '默认路径中的身份与场景修正',
        plainText: '默认路径将发件人身份、投递完整性等信号映射到证据簇，在物件去重及簇内合并后执行一次组合；风险地板和上限基于经准入的唯一因果来源与邮件场景执行。它不会对所有邮件统一应用 trust_score×0.4。该乘法折扣属于 noisy_or 聚合路径，不能套用于默认 clustered_ds_v2。',
      },
      {
        heading: '最终判定：默认路径的风险分数与威胁等级',
        plainText: 'V2 基础风险为 Bel(恶意)，不把未知质量按 η 转为恶意。最终综合风险应用具名攻击约束和显式核查策略。分级为严重≥85%、高危≥65%、中危≥40%、低危≥15%。单个随机发件域名或 From/Reply-To 域名不匹配按身份核查策略至少中危；这不会改写原始 Bel。未知表示证据不足，不能理解为已确认安全。',
      },
    ],
  },
  // ============== Newly added articles (2026-03-19) ==============
  {
    id: 'phishing-detection' as TopicId,
    title: '钓鱼邮件检测技术',
    subtitle: '默认配置条目覆盖多维检测与来源融合',
    lead: 'Vigilyx 的编译默认邮件分析管线包含 29 个配置条目，覆盖内容、附件、链接、协议、语义、身份和行为分析；条件门控、外部服务和显式 opt-in 决定其中哪些模块实际运行。',
    tag: '检测',
    tagClass: 'sk-tag-red',
    iconType: 'shield' as const,
    category: 'platform',
    sections: [
      {
        heading: '多维检测架构',
        plainText: '邮件威胁不是单一维度能捕获的。一封精心制作的钓鱼邮件可能通过了 SPF/DKIM 验证，使用了看似正常的发件域名，但在正文中包含紧迫性话术、在附件中夹带二维码或在链接目标页中暴露 OAuth 设备码诱导。Vigilyx 的默认 29 个配置条目包含检测模块和最终 verdict 阶段。运行时先按稳定因果键去重，再将物件归入八个证据簇，簇内合并后执行一次 clustered_ds_v2 组合。配置中的 A-H engine_id 只是模块分类。落地页、AITM 与沙箱模块已在默认配置中，但是否执行取决于上游条件、外部服务和显式 opt-in。',
      },
      {
        heading: '内容分析引擎 (B)',
        plainText: 'content_scan 是核心规则模块，维护钓鱼关键词 BEC 短语与 DLP 模式等规则库。html_scan 检测隐藏表单 脚本注入 事件处理器与 data URI 等 HTML 威胁。html_pixel_art 识别 1px 追踪信标与像素伪装。attach_scan 通过扩展名和 magic bytes 识别危险文件类型。attach_content 负责解压和提取附件文本进行深度分析。attach_hash 对附件 SHA256 做本地与外部情报比对。默认配置包含 attach_qr_scan，用于解析图片附件中的二维码并评估其是否指向设备码钓鱼或伪造登录页；具体执行仍受条件门控。',
      },
      {
        heading: 'URL 链接分析引擎 (D)',
        plainText: 'link_scan 从 HTML 中提取 URL，检测 IP 直连链接、同形字攻击、Punycode 域名、短链服务、href 与显示文本不匹配、@ 符号滥用等模式。link_reputation 查询本地 IOC 缓存和外部情报源。link_content 实际抓取目标页面并分析登录表单 JavaScript 载荷与可疑路径关键词。若运行时启用 landing_page_scan 与 aitm_detect，系统还能进一步识别设备码钓鱼链条、验证码门控页面和中间人登录页等更深层的着陆页风险。',
      },
      {
        heading: '语义与行为分析 (F/G/H)',
        plainText: 'semantic_scan 默认运行 Rust 本地语义规则，保留来源、言语行为、请求对象和有界关系证明。可选 CPU ONNX bge/e5 意图模型通过 SEMANTIC_INTENT_MODEL_DIR 加载，默认只写影子诊断；显式配置 SEMANTIC_INTENT_SCORE_THRESHOLD 后替代本地规则及后续 Python NLP/OCR 路径，命中以 Low 模块分数 0.20 进入融合，不保证最终等级或处置。Python AI 是单独的可选 NLP/OCR 服务。identity_anomaly 分析首次联系与身份变化，transaction_correlation 提供跨会话业务风险线索。',
      },
      {
        heading: '安全熔断器：防止融合漏报',
        plainText: '默认 clustered_ds_v2 的通用 circuit breaker 只接受被标记为可触发地板的原生来源：来源分数至少 0.55、置信度至少 0.70，地板为来源分数×alert_floor_factor（默认 1.0，配置验证不允许折减）。Convergence breaker 默认要求至少 2 个来源分数达到 `convergence_belief_threshold=0.10` 的独立因果键、分属至少 2 个证据簇，且至少有一个可触发地板的原生来源；基准地板为 0.40，每多一个独立来源增加 0.05，最多增加 0.15。已验证身份且只有低置信上下文信号时还有专门上限，因此不能概括为任意两个模块都保证 Medium。',
      },
    ],
    keywords: ['钓鱼', 'phishing', 'BEC', '商务欺诈', 'DLP', '内容检测', 'URL', '链接', '附件', '同形字', 'homograph', 'NLP', '语义', '熔断器', 'circuit breaker', '关键词', '魔数', 'magic bytes', '短链', '信标', 'pixel tracking'],
  },
  {
    id: 'ioc-intel' as TopicId,
    title: 'IOC 威胁情报管理',
    subtitle: '指标录入、情报查询与误报控制',
    lead: 'IOC (Indicators of Compromise) 是已知恶意活动的标识符——IP 地址、域名、文件哈希、URL 或邮箱地址。Vigilyx 的情报系统支持自动录入、外部查询和白名单保护。',
    tag: '情报',
    tagClass: 'sk-tag-amber',
    iconType: 'analytics' as const,
    category: 'platform',
    sections: [
      {
        heading: 'IOC 类型与来源',
        plainText: '系统支持 6 种 IOC 类型：IP 地址（Received 头中的外部 IP）、邮箱地址（mail_from 发件人）、域名（发件域名）、文件哈希（附件 SHA256）、URL（link_scan 标记的可疑链接）、邮件主题（可手工维护的特征主题模式）。自动 IOC 提取不记录主题。每个 IOC 记录包含：indicator 值、类型、来源（auto/auto_reference/manual/admin_clean）、判定（malicious/suspicious/clean）、置信度 0-1、攻击类型推断、命中计数、过期时间。auto_reference 是由 Low 及以上邮件裁决产生的短期可疑观察，只作为下一封邮件的弱威胁参考，不是白名单；admin_clean 才是明确的白名单保护来源。',
      },
      {
        heading: '自动记录与正反馈循环防护',
        plainText: '当邮件裁决达到 Low 及以上时，引擎会提取 IOC（IP、域名、哈希、URL、邮箱）并以 auto_reference/suspicious 写入短期参考。下一封邮件命中后仍需完整重判，IOC 只提供弱威胁信号；Critical 可沿通用路径写入 auto/malicious。仿冒域名专用路径是例外：命中相似度门槛且整体裁决达到 High 时即写入 malicious IOC；Safe 不写入通用自动 IOC。为避免正反馈，参考 TTL 为 24 小时，外部 IP 仍需多个独立会话出现，且强 malicious 条目不能被低危参考降级。',
      },
      {
        heading: '外部情报源查询',
        plainText: 'IP 情报查询可并行使用 OTX AlienVault、VirusTotal 与可选的 AbuseIPDB；域名查询使用 OTX 与 VirusTotal。OTX 限速 10 次/分钟，脉冲数 ≥25 或 3–24 都只返回 suspicious（置信度分别为 0.45 或 0.31–0.38），少于 3 返回 clean；OTX 单独不会判 malicious。VirusTotal 配置官方 API key 时优先使用官方 API（4 次/分钟、每日 500 次配额）：malicious 引擎数 ≥3 判 malicious，至少 1 个 malicious 或 ≥3 个 suspicious 判 suspicious。若官方 API 因非配额原因失败，且已启用 Playwright 抓取，则会回退到抓取路径（6 次/分钟）；未配置 API key 时也只有显式启用抓取才会查询 VT。抓取路径以 malicious 占比 ≥30% 或数量 ≥5 判 malicious，以占比 ≥10% 或数量 ≥2 判 suspicious。外部结果缓存在本地 IOC 表，TTL 为 malicious 30 天、suspicious/unknown 1 天、clean/safe 3 天。常规查询优先使用本地外部情报缓存；已有本地检测信号时，调用方会重新验证外部 clean 缓存，admin_clean/system 白名单仍优先。',
      },
      {
        heading: '白名单与情报放行',
        plainText: '情报白名单用于排除已知安全的域名/IP 被误标为可疑。添加白名单等同于创建 verdict=clean、source=admin_clean 的 IOC 条目。admin_clean 条目受保护：即使后续自动分析将该指标标为 suspicious，UPSERT 也不会覆盖 admin_clean 的判定。白名单管理通过 API /api/security/intel-whitelist 进行，支持添加、删除、批量查看。典型使用场景：QQ 邮箱域名 qq.com、内部域名 your-company.com、合作方域名等被 OTX 误标为可疑时，加入白名单即可。',
      },
    ],
    keywords: ['IOC', '威胁情报', 'indicator', 'OTX', 'VirusTotal', 'AbuseIPDB', '白名单', 'whitelist', '误报', 'false positive', 'UPSERT', 'TTL', '正反馈', '放大循环', 'admin_clean', '情报源', 'pulse', '哈希', 'SHA256'],
  },
  {
    id: 'ai-nlp' as TopicId,
    title: 'AI/NLP 钓鱼检测模型',
    subtitle: '双模型架构：零样本 + Fine-Tuned 微调',
    lead: '可选 Python AI 服务支持零样本分类与审批后的微调模型推理；训练在服务外离线完成。Rust CPU ONNX 意图模型是独立集成。',
    tag: 'AI',
    tagClass: 'sk-tag-purple',
    iconType: 'analytics' as const,
    category: 'platform',
    sections: [
      {
        heading: '双模型优先级',
        plainText: '推理时优先使用 Fine-tuned 五分类模型（如果已训练）。Fine-tuned 模型保存在 data/nlp_models/latest/ 目录，基于分析师反馈训练而来，对本组织邮件特征的适配性更好；如果没有 Fine-tuned 模型或加载失败，则回退到零样本分类模型。零样本模型使用 NLI 机制，不需要本地训练数据即可工作，但准确率略低。两个模型共享同一个基座：MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7（约 550MB，支持 100+ 语言）。',
      },
      {
        heading: '零样本分类原理',
        plainText: '零样本分类将邮件内容与 5 个候选标签组成前提-假设对，通过 NLI 模型判断蕴含关系。候选标签分为 phishing scam bec spam legitimate 五类，CJK 字符占比大于 30% 时使用中文标签集，否则使用英文标签集。系统将 phishing scam bec 三类概率累加为恶意概率。需要注意的是，这套标签与微调模型并不完全相同；微调模型使用 legitimate phishing spoofing social_engineering other_threat 五类，更贴近平台中的分析师标注任务。',
      },
      {
        heading: '离线训练与模型审批',
        plainText: '管理员可通过分析师反馈积累样本并导出数据用于离线训练。当前 AI 服务已移除在线训练，旧 POST /training/train 返回 410 TRAINING_REMOVED，不存在达到 30 条样本即在线启动的流程。离线产物经验证并暂存为 pending 后，仍需管理员显式调用 POST /api/admin/nlp/approve（内部 POST /model/approve）才会热加载；审批前继续使用原模型。Python NLP 的审批流程与 Rust ONNX 意图模型的独立打包、配置及重启流程不同。',
      },
      {
        heading: 'NLP 与规则引擎的协作',
        plainText: '本地规则路径可接入 Python NLP，模型结果作为辅助证据处理；场景观察、覆盖缺口与恶意证据需要分别解读，风险等级由整体融合和策略决定。ONNX 意图模型默认影子运行，不改变结果；显式计分模式则替代本地规则及后续 Python NLP/OCR 路径，而不是同时把所有模型结果叠加。模型分数不能单独保证邮件恶意或最终处置。',
      },
    ],
    keywords: ['AI', 'NLP', 'mDeBERTa', '零样本', 'zero-shot', 'LoRA', '微调', 'fine-tune', '钓鱼检测', 'Focal Loss', 'R-Drop', '交叉验证', '热替换', '训练', 'NLI', '自然语言推理', '语义', '多语言', '分类'],
  },
  {
    id: 'soar-alerts' as TopicId,
    title: '告警分级与自动响应',
    subtitle: 'P0-P3 告警体系与 SOAR 处置引擎',
    lead: '基于极值理论 (EVT) 和期望损失 (EL) 的动态告警分级，配合可配置的自动化处置规则引擎。',
    tag: '告警',
    tagClass: 'sk-tag-red',
    iconType: 'shield' as const,
    category: 'platform',
    sections: [
      {
        heading: 'P0-P3 四级告警',
        plainText: 'Risk_final<0.15 不生成告警。P0 (Critical)：EL≥3.0、K_conflict>0.7、EVT T≥10000，或风险分数≥0.4 时 CUSUM 告警 / Hawkes 比率>5。P1 (High)：EL≥1.5、EVT T≥1000、HMM 攻击阶段 γ(S3)>0.3、Hawkes 比率>3、Novelty>0.6 或 K_cross>0.5。P2 (Medium)：EL≥0.5、u_final>0.6、EVT T≥100、HMM 信任建立阶段 γ(S2)>0.25、通信图异常、Novelty>0.3，或风险分数<0.4 时的 CUSUM 告警。其余已生成的告警为 P3 (Low)；P3 数据库记录受全局 30 条/分钟限流，超额单条记录会被抑制并在后续窗口生成汇总告警。系统采用最严重的匹配等级，EVT T 以样本数计。',
      },
      {
        heading: '期望损失与极值理论',
        plainText: 'EL（Expected Loss）是最终风险分数乘以最高收件人影响权重，不是模块置信度加权值。EVT（Extreme Value Theory）用 GPD（广义 Pareto 分布）拟合风险分数尾部：当前实现从滚动风险窗口取样，以阈值以上的超越值估计参数，并计算返回期 T 与 CVaR。T 是以样本数计的重现间隔；更大的 T 表示在该窗口模型下更罕见。',
      },
      {
        heading: 'SOAR 处置规则引擎',
        plainText: '管理员可配置自动化处置规则，每条规则包含：触发条件（min_threat_level、categories 列表、flagged_modules 列表，三者 AND 关系）和处置动作列表。支持三种动作类型：webhook（HTTP POST 到外部 SIEM/工单系统，有 SSRF 防护：阻止私有 IP 和环回地址，10 秒超时）；log（结构化日志输出）；alert（SMTP 邮件告警，异步发送不阻塞检测流水线）。规则按 priority 字段排序执行，可启用/禁用。邮件告警系统支持配置：SMTP 服务器/端口/TLS 模式、最低告警等级、是否通知收件人、是否通知管理员。',
      },
    ],
    keywords: ['P0', 'P1', 'P2', 'P3', '告警', 'alert', 'SOAR', '自动响应', '处置规则', 'webhook', 'SIEM', 'EVT', '极值理论', 'GPD', 'Pareto', 'EL', '期望损失', 'CVaR', 'VaR', '回归期', 'SMTP', '邮件告警'],
  },
  {
    id: 'data-security' as TopicId,
    title: '数据安全与外发邮件审查',
    subtitle: 'HTTP/Webmail DLP、SMTP 外发审查与隐私访问',
    lead: 'HTTP/Webmail 事件与 SMTP 外发审查分别记录敏感数据风险；旁路只能审计，MTA 可按策略对待中继邮件执行出站 DLP。POP3/IMAP 当前仅提供元数据和覆盖信号。',
    tag: '数据安全',
    tagClass: 'sk-tag-green',
    iconType: 'lock-closed' as const,
    category: 'platform',
    sections: [
      {
        heading: 'HTTP 流量捕获',
        plainText: 'Sniffer 启动时先读取环境值，再从 API 加载配置；API 返回 PostgreSQL 中已保存设置或内置默认值，并覆盖响应中存在的环境字段。标准 Compose 不传入 WEBMAIL_SERVERS，API 默认 Webmail 列表为空，因此需通过 UI/API 配置非空服务器列表才能启用 HTTP 捕获。非空 API 端口列表会替换环境端口列表。匹配流量会解析请求方法、URI、Host、Content-Type、Cookie，并从请求体前 64KB 提取邮件字段（from/to/subject）。支持 URL-encoded、JSON 和 Coremail 嵌套 JSON。HTTP 会话写入 Redis Stream vigilyx:stream:http_sessions，由引擎 consumer group 读取并执行数据安全检测。',
      },
      {
        heading: '三类数据泄露检测模式',
        plainText: '草稿箱滥用 (draft_box_abuse)：用户将敏感数据保存为邮件草稿而非直接发送，绕过出站邮件检测。检测方式：识别 Coremail compose.jsp 的保存草稿请求，提取草稿内容进行 DLP 扫描。文件中转滥用 (file_transit_abuse)：通过 Webmail 的文件上传功能中转敏感文件。检测方式：识别分块上传（Coremail chunked upload），重组完整文件内容后扫描。自发送检测 (self_sending)：用户给自己的邮箱发送包含敏感数据的邮件，绕过 DLP 策略。检测方式：比对 from 和 to 字段是否为同一用户（不区分大小写）。',
      },
      {
        heading: 'DLP 敏感数据扫描',
        plainText: '数据安全引擎对 HTTP 会话的请求体和上传文件执行 DLP 扫描，检测：银行卡号（16-19 位数字，Luhn 校验）、身份证号（18 位，含校验位验证）、手机号（中国大陆 11 位格式）、合同编号/发票号（特定格式模式）、金额数据（大于阈值的金融数字）。事件按严重程度分级：info（仅记录）、low（低风险）、medium（中等，可能需要审查）、high（高风险，建议阻断）、critical（严重，立即告警）。所有事件持久化到 data_security_incidents 表，通过 API 和 WebSocket 实时推送到前端展示。',
      },
      {
        heading: 'SMTP 外发审查与模式边界',
        plainText: 'SMTP 外发审查独立于 HTTP 事件和邮件威胁判定，列表、统计和详情使用 /api/data-security/email-reviews。旁路仅审计可检查载荷；MTA 按出站 DLP 策略对原本会中继的邮件告警、隔离或阻断。方向需要可信来源、域名及收件人证据，仅有本地 MAIL FROM 不足以认定外发。加密、方向未知、载荷不完整和检查失败保留未知状态。',
      },
      {
        heading: '隐私与临时内容访问',
        plainText: '隐私模式默认遮罩内容并保留安全分析。管理员填写具体资源、访问范围和用途，使用本人验证因子申请；独立 audit 用户使用单独因子审批。申请人随后获取绑定用户、JWT 会话、精确资源和范围的租约，最长五分钟。系统设置的隐私页管理策略和申请；策略缺失或不可读取时默认遮罩。关闭隐私后凭据仍被遮罩，已脱敏持久化的审查证据不能还原。',
      },
    ],
    keywords: ['数据安全', 'HTTP', 'Webmail', 'DLP', '数据泄露', '草稿箱', '文件中转', '自发送', 'Coremail', '银行卡', '身份证', '敏感数据', '分块上传', 'chunked', 'DataSecurityEngine', '请求体'],
  },
  {
    id: 'mirror-vs-mta' as TopicId,
    title: '镜像模式与 MTA 代理模式',
    subtitle: 'Vigilyx 两种部署路径与适用场景',
    lead: 'Vigilyx 同时支持旁路镜像和 MTA 代理两种部署模式。两者共用解析器与检测引擎，但介入时机、阻断能力与运维要求完全不同。',
    tag: '架构',
    tagClass: 'sk-tag-cyan',
    iconType: 'mail' as const,
    category: 'platform',
    sections: [
      {
        heading: '旁路镜像模式',
        plainText: '旁路镜像模式通过 SPAN TAP 或交换机镜像口捕获现网 SMTP POP3 IMAP HTTP 流量，优点是对现网几乎无侵入，不改变收发路径，适合事后审计与告警。缺点是它只能在邮件已经经过现网设备后再进行分析，因此默认场景下更擅长观测 取证 和告警，而不是投递前阻断。',
      },
      {
        heading: 'MTA 代理模式',
        plainText: 'MTA 代理模式把 Vigilyx 直接放在 SMTP 中继链路上。客户端或上游 MTA 先把邮件投递给 vigilyx-mta，再由其完成 SMTP 会话 解析 MIME 调用内嵌安全引擎 并依据判定结果接受 转发 隔离或拒绝。它支持 TLS 终结 内联超时控制 以及 fail-open 或 fail-closed 策略，是实时阻断能力的基础。',
      },
      {
        heading: '如何选择',
        plainText: '如果你的目标是先以最小改动观察流量 验证规则与排查误报，镜像模式更稳妥；如果你的目标是上线前置拦截 隔离高风险邮件 并接受 SMTP 路径改造，MTA 代理模式更合适。很多团队会先在镜像模式验证，再逐步迁移到 MTA 代理模式。',
      },
    ],
    keywords: ['镜像模式', 'MTA代理', 'MTA Proxy', 'Mirror mode', 'SMTP relay', 'inline', '旁路', '阻断', '隔离', '部署模式', '投递前检查'],
  },
  {
    id: 'message-bus' as TopicId,
    title: '消息总线与可靠投递',
    subtitle: 'Redis Streams 数据面与 Pub/Sub 控制面',
    lead: 'Vigilyx 的消息层按用途使用不同通道：会话和当前重扫请求走 Redis Streams，统计、判定通知与 reload 等控制信号走 Pub/Sub。Streams 支持 ACK 和失败恢复，但发布失败重试耗尽或近似长度修剪仍可能造成消息丢失。',
    tag: '架构',
    tagClass: 'sk-tag-purple',
    iconType: 'analytics' as const,
    category: 'platform',
    sections: [
      {
        heading: '数据面：Redis Streams',
        plainText: 'Sniffer 把邮件会话和 HTTP 会话分别写入 vigilyx:stream:sessions 与 vigilyx:stream:http_sessions；API 的历史重扫请求也写入 vigilyx:stream:rescan_requests。Engine 通过 consumer groups 读取，并在成功处理后执行 XACK。对成功写入且尚未被 MAXLEN 修剪的条目，这提供 at-least-once 处理；Sniffer 发布重试耗尽、队列满或近似长度修剪仍可能导致消息丢失。',
      },
      {
        heading: '失败恢复：PEL 与 XAUTOCLAIM',
        plainText: '如果消费者在处理过程中崩溃，仍保留在 Stream 中的未 ACK 条目会留在 Pending Entries List。Engine 可通过 XAUTOCLAIM 回收闲置超过阈值的条目并继续处理；已被 MAXLEN 修剪的条目无法通过 PEL 恢复。',
      },
      {
        heading: '控制面：Pub/Sub',
        plainText: 'reload 命令以及 Sniffer 统计、verdict、alert、数据安全 incident 和 engine status 通知使用 Pub/Sub。当前单条、批量和隔离区释放重扫请求使用 Redis Streams；Engine 仍保留旧版 Pub/Sub rescan 订阅用于兼容。Pub/Sub 不保留订阅者离线期间的消息，因此适合通知广播，不提供队列式重试。',
      },
    ],
    keywords: ['Redis Streams', 'Pub/Sub', 'consumer groups', 'XREADGROUP', 'XAUTOCLAIM', 'XACK', '消息总线', '数据面', '控制面', 'at-least-once', 'vigilyx:stream:sessions'],
  },
  {
    id: 'mta-quarantine' as TopicId,
    title: '隔离区与邮件放行',
    subtitle: 'Inline 判定、quarantine 存储与释放流程',
    lead: '在 MTA 代理模式下，Vigilyx 不必只在“放行”和“拒绝”之间二选一。隔离区提供了第三种处置路径：先接收并保全原始邮件，再由管理员审查和释放。',
    tag: '处置',
    tagClass: 'sk-tag-amber',
    iconType: 'shield' as const,
    category: 'platform',
    sections: [
      {
        heading: '何时进入隔离区',
        plainText: 'MTA 代理模式下，内联引擎会在 DATA 完成或 BDAT LAST 后对邮件执行快速判定。默认情况下，检查完整的 Safe 和 Low 邮件进入下游中继；判定已完成但覆盖不完整时，原本可接受的结果会转入隔离。阻断判定的模块失败/超时或必需依赖不可用时则返回临时失败（默认 451）；启用 fail-open 后可能继续尝试中继。Medium 和 High 写入 quarantine 表并向发件方返回成功，Critical 则直接拒绝。出站 DLP 会扫描邮件并记录审计；只有投递计划原本要中继（包括 fail-open 中继）时，才执行 allow_and_alert、quarantine 或 block 处置。allow_and_alert 继续中继，quarantine 隔离，block 拒绝；威胁判定已隔离或拒绝的邮件不会再被 DLP 处置改变投递结果。这样既保留实时处置能力，也能给分析师留下复核空间。',
      },
      {
        heading: '隔离区保存了什么',
        plainText: '隔离区记录通常包含 session_id mail_from rcpt_to subject threat_level reason status created_at released_at released_by ttl_days 以及原始 raw_eml。设计目标不是只存一个摘要，而是把后续复盘和人工放行所需的信息保全下来。',
      },
      {
        heading: '释放与删除',
        plainText: '管理员可以通过 /api/security/quarantine 查看列表和统计，通过 POST /api/security/quarantine/:id/release 执行放行，通过 DELETE /api/security/quarantine/:id 删除记录。released_by 来自已认证的 JWT 用户，而不是前端自报字段。换句话说，隔离区既是处置队列，也是审计链路的一部分。',
      },
    ],
    keywords: ['quarantine', '隔离区', 'release', 'raw_eml', 'MTA', 'inline verdict', '放行', '删除', '审计', 'POST /api/security/quarantine/:id/release'],
  },
  // === Attack-technique category ===
  {
    id: 'bec-attack' as TopicId,
    title: 'BEC 商业邮件欺诈',
    subtitle: 'Business Email Compromise 攻击手法与防御',
    lead: 'BEC 是最具经济破坏力的邮件攻击类型。攻击者伪装高管或合作方，诱导财务人员转账。全球年损失超 26 亿美元。',
    tag: '攻击手段',
    tagClass: 'sk-tag-red',
    iconType: 'shield' as const,
    category: 'email-security',
    referenceUrl: 'https://www.ic3.gov/Media/Y2023/PSA230609',
    sections: [
      {
        heading: '典型攻击流程',
        plainText: '1) 侦察阶段: 通过 LinkedIn/官网收集目标组织架构、高管姓名、财务流程。2) 邮箱入侵: 通过钓鱼或密码喷射攻破高管或供应商邮箱。3) 潜伏观察: 在被控邮箱中静默观察邮件往来，了解付款习惯和审批流程。4) 发起攻击: 在真实交易过程中插入伪造付款指令，修改收款账户为攻击者控制的银行账户。5) 资金转移: 受害者将款项转入攻击者账户，通常在数天后才发现异常。',
      },
      {
        heading: 'BEC 五种变体',
        plainText: 'CEO 欺诈: 冒充 CEO/CFO 紧急要求转账。发票欺诈: 冒充供应商发送修改过收款账号的真实发票。律师冒充: 声称涉及机密并购交易需紧急付款。数据窃取: 冒充 HR 索要员工 W-2 税表或个人信息。账户入侵: 利用已控邮箱在现有对话中插入欺诈请求（线程劫持）。',
      },
      {
        heading: 'Vigilyx 检测能力',
        plainText: 'content_scan 模块检测 BEC 关键词组合（紧急+转账+高管头衔）。identity_anomaly 模块检测显示名欺诈（显示名是内部高管但邮箱是外部域名）。transaction_correlation 模块关联紧迫性关键词与金融实体。AI 路径中，零样本模型会显式给出 bec 候选概率，而微调模型则主要通过 spoofing social_engineering other_threat 等标签间接表达风险。首次通信检测还能标记从未联系过的外部供应商。',
      },
    ],
    keywords: ['BEC', '商业邮件欺诈', 'CEO欺诈', '发票欺诈', '转账', '线程劫持', '供应商冒充', 'wire transfer', '付款', '账户入侵'],
  },
  {
    id: 'social-engineering' as TopicId,
    title: '社会工程学攻击',
    subtitle: '利用人性弱点的攻击手法',
    lead: '社会工程学攻击不依赖技术漏洞，而是利用人的信任、恐惧、好奇心和紧迫感。是 APT 攻击链的第一步。',
    tag: '攻击手段',
    tagClass: 'sk-tag-red',
    iconType: 'shield' as const,
    category: 'email-security',
    referenceUrl: 'https://attack.mitre.org/techniques/T1566/',
    sections: [
      {
        heading: '常见社工话术',
        plainText: '恐惧驱动: "您的账户将被关闭"、"检测到异常登录"、"逾期未处理将冻结"。权威冒充: 冒充 Microsoft/Apple/银行/税务局等权威机构。好奇心诱饵: "查看您的考核结果"、"工资调整通知"、"快递包裹异常"。紧迫感制造: "限时处理"、"立即操作"、"24小时内"。利益诱惑: "退税补贴"、"中奖通知"、"免费赠品"。',
      },
      {
        heading: 'APT 中的社工邮件',
        plainText: 'APT (高级持续性威胁) 组织的鱼叉式钓鱼邮件高度定制化: 使用目标真实姓名和职位、引用真实的内部项目或事件、附件伪装成真实的工作文档（周报、合同、发票）、发件人伪装成同事或合作伙伴。攻击者会花费数周进行目标侦察，确保邮件看起来完全合法。',
      },
      {
        heading: 'Vigilyx 检测能力',
        plainText: 'account_security_phishing 组合检测: 同时包含威胁描述和行动催促。content_scan 钓鱼关键词: 覆盖中英文 + 繁简体变体 + Unicode 正规化。NLP 语义分析: mDeBERTa 模型识别钓鱼/诈骗意图。SPF/DKIM/DMARC 认证结果: 验证发件人身份真实性。首次通信检测: 标记从未联系过的外部发件人。',
      },
    ],
    keywords: ['社会工程学', '钓鱼', 'APT', '鱼叉式钓鱼', 'spear phishing', '恐惧', '紧迫感', '权威冒充', 'Microsoft', '账户关闭', '异常登录', 'MITRE ATT&CK'],
  },
  {
    id: 'attachment-weaponization' as TopicId,
    title: '附件武器化',
    subtitle: '恶意附件的类型、伪装手法与检测',
    lead: '恶意附件是邮件攻击最常见的载体。攻击者将木马、勒索软件、信息窃取器隐藏在看似正常的文档中。',
    tag: '攻击手段',
    tagClass: 'sk-tag-red',
    iconType: 'code' as const,
    category: 'email-security',
    referenceUrl: 'https://attack.mitre.org/techniques/T1566/001/',
    sections: [
      {
        heading: '常见恶意附件类型',
        plainText: 'Office 宏文档: .docm/.xlsm 包含自动执行的 VBA 宏代码。PDF 嵌入: PDF 中嵌入 JavaScript 或指向恶意网站的链接/QR码。HTML 走私: .html 附件中用 JavaScript 在客户端重构恶意文件并触发下载。双重扩展名: "invoice.pdf.exe" 利用 Windows 隐藏扩展名的特性。压缩包嵌套: .zip/.rar 中包含可执行文件，有时加密码保护避免沙箱扫描。ISO/IMG 磁盘镜像: 绕过 Mark-of-the-Web (MOTW) 安全标记。',
      },
      {
        heading: '检测挑战',
        plainText: '密码保护: 加密的 ZIP/RAR/PDF 无法被自动化工具扫描内容。多态变异: 恶意代码每次生成时自动变异，绕过签名检测。合法服务托管: 恶意文件托管在 Google Drive/OneDrive/Dropbox 等合法服务上。延迟下载: 附件本身是干净的下载器，运行后才从 C2 服务器拉取实际恶意载荷。',
      },
      {
        heading: 'Vigilyx 检测能力',
        plainText: 'attach_scan 模块: 检测双重扩展名、可执行文件类型、压缩包嵌套。attach_hash 模块: 对附件做 SHA-256 哈希并查询 VirusTotal 信誉。attach_content 模块: 提取附件文本内容进行钓鱼关键词扫描。html_pixel_art 模块: 检测 HTML 中的 QR 码并解码提取 URL。magic bytes 检测: 通过文件头魔术字节识别真实文件类型（防止扩展名伪造）。',
      },
    ],
    keywords: ['附件', '恶意文档', '宏', 'VBA', 'PDF', 'HTML走私', '双重扩展名', '压缩包', '勒索软件', '木马', 'QR码', 'SHA-256', 'VirusTotal', '密码保护'],
  },
  {
    id: 'link-obfuscation' as TopicId,
    title: '链接伪装与重定向',
    subtitle: 'URL 混淆、重定向链、同形攻击',
    lead: '攻击者使用多种技术隐藏恶意链接的真实目的地，让用户误以为点击的是合法网站。',
    tag: '攻击手段',
    tagClass: 'sk-tag-red',
    iconType: 'lock-open' as const,
    category: 'email-security',
    referenceUrl: 'https://attack.mitre.org/techniques/T1566/002/',
    sections: [
      {
        heading: 'URL 混淆手法',
        plainText: 'href/text 不匹配: HTML 中显示 "https://bank.com" 但实际链接指向 "https://evil.com"。短链接: 用 bit.ly/tinyurl.com 等短链服务隐藏最终目标。多重重定向: 经过 3-4 个合法域名的重定向链，最终到达钓鱼页面。URL 编码: 用 %2F%3A 等编码混淆路径，部分安全工具无法正确解码。@ 符号: "https://legitimate.com@evil.com" 实际访问的是 evil.com。data: URI: 将钓鱼页面内容直接编码在 URL 中，无需外部服务器。',
      },
      {
        heading: 'IDN 同形攻击',
        plainText: '利用 Unicode 中视觉相似的字符注册域名。例如: "аpple.com"（第一个字母是西里尔字母 а U+0430）看起来和 "apple.com" 完全一样，但实际是不同域名。Punycode 转换后变成 "xn--pple-43d.com"。浏览器部分支持 IDN 显示，可能直接显示 Unicode 域名而非 Punycode，用户无法分辨。',
      },
      {
        heading: 'Vigilyx 检测能力',
        plainText: 'link_scan 模块: 检测 IP 链接、短链、href/text 不匹配、@ 符号、重定向参数、token 参数。link_content 模块: IDN 同形攻击检测（混合脚本域名）、URL 过长、双重编码、可疑路径关键词。link_reputation 模块: DGA 随机域名检测、可疑 TLD、外部情报查询（OTX/VT Scrape）。受信 URL 白名单: QQ 邮箱等合法服务的长参数 URL 不误报。',
      },
    ],
    keywords: ['URL', '链接', '重定向', '短链', 'IDN', '同形攻击', 'Punycode', 'href', 'data URI', '编码', 'DGA', '随机域名', 'bit.ly', '@ 符号', '混淆'],
  },
]

interface LocalizedTopicSection {
  heading: string
  plainText: string
}

export interface LocalizedTopicContent {
  title: string
  subtitle: string
  lead: string
  tag: string
  sections: LocalizedTopicSection[]
}

function isEnglishLanguage(language: string): boolean {
  return language.toLowerCase().startsWith('en')
}

export function getLocalizedTopicContent(entry: TopicEntry, language: string): LocalizedTopicContent {
  const useEnglish = isEnglishLanguage(language)
  return {
    title: useEnglish ? (entry.titleEn || entry.title) : entry.title,
    subtitle: useEnglish ? (entry.subtitleEn || entry.subtitle) : entry.subtitle,
    lead: useEnglish ? (entry.leadEn || entry.lead) : entry.lead,
    tag: useEnglish ? (entry.tagEn || entry.tag) : entry.tag,
    sections: entry.sections.map(section => ({
      heading: useEnglish ? (section.headingEn || section.heading) : section.heading,
      plainText: useEnglish ? (section.plainTextEn || section.plainText) : section.plainText,
    })),
  }
}

const topicIdSet = new Set<TopicId>(rawTopics.map(topic => topic.id))

export const topicEntries: TopicEntry[] = rawTopics.map(raw => {
  const english = englishTopics[raw.id]
  const merged: Omit<TopicEntry, 'searchableText' | 'readingTime'> = {
    ...raw,
    titleEn: english?.titleEn,
    subtitleEn: english?.subtitleEn,
    leadEn: english?.leadEn,
    tagEn: english?.tagEn,
    sections: raw.sections.map((section, index) => ({
      ...section,
      headingEn: english?.sectionsEn[index]?.heading,
      plainTextEn: english?.sectionsEn[index]?.plainText,
    })),
  }
  const searchableText = buildSearchableText(merged)
  return {
    ...merged,
    searchableText,
    readingTime: estimateReadingTime([raw.title, raw.subtitle, raw.lead, ...raw.sections.flatMap(section => [section.heading, section.plainText])].join(' ')),
  }
})

export function getTopicEntry(id: TopicId): TopicEntry | undefined {
  return topicEntries.find(t => t.id === id)
}

export function isTopicId(id: string | null | undefined): id is TopicId {
  return typeof id === 'string' && topicIdSet.has(id as TopicId)
}

export function getTopicPath(id: TopicId): string {
  return `/knowledge/${id}`
}
