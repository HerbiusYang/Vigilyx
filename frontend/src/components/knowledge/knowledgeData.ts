export type TopicId = 'mta' | 'opportunistic-tls' | 'mandatory-tls' | 'starttls' | 'spf-dkim-dmarc' | 'ds-fusion' | 'temporal-evt' | 'module-pipeline' | 'phishing-detection' | 'ioc-intel' | 'ai-nlp' | 'soar-alerts' | 'data-security' | 'bec-attack' | 'social-engineering' | 'attachment-weaponization' | 'link-obfuscation'

export interface TopicSection {
  heading: string
  plainText: string
}

export type CategoryFilter = '全部' | '邮件安全知识' | '通用知识' | '平台相关'

export interface TopicEntry {
  id: TopicId
  title: string
  subtitle: string
  lead: string
  tag: string
  tagClass: string
  iconType: 'mail' | 'lock-open' | 'lock-closed' | 'code' | 'shield' | 'analytics'
  category: CategoryFilter
  sections: TopicSection[]
  searchableText: string
  keywords: string[]
  readingTime: number
  referenceUrl?: string
}

export const categoryFilters: CategoryFilter[] = ['全部', '邮件安全知识', '通用知识', '平台相关']

function buildSearchableText(entry: Omit<TopicEntry, 'searchableText' | 'readingTime'>): string {
  const parts = [
    entry.title,
    entry.subtitle,
    entry.lead,
    ...entry.keywords,
    ...entry.sections.flatMap(s => [s.heading, s.plainText]),
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
    category: '通用知识',
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
        plainText: 'Vigilyx 通过镜像抓包捕获 MTA 之间的 SMTP 通信。当邮件在中继链路上传递时，每一跳都会产生一个独立的 session。MTA Mail Transfer Agent 服务器间转发邮件 SMTP。MUA Mail User Agent 用户的邮件客户端 Outlook Thunderbird。MDA Mail Delivery Agent 将邮件投递到用户邮箱 dovecot。MSA Mail Submission Agent 接收用户提交的邮件 端口 587',
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
    category: '邮件安全知识',
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
    category: '邮件安全知识',
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
    category: '邮件安全知识',
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
    category: '邮件安全知识',
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
    subtitle: 'Dempster-Shafer Evidence Theory & Murphy Correction',
    lead: '传统贝叶斯方法用单一概率 P(threat) 表示威胁程度，无法区分"确定安全"和"不确定"。D-S 证据理论通过三元组 (b, d, u) 显式建模不确定性，结合 Murphy 修正融合解决多源证据冲突，构成 Vigilyx 风险引擎的数学基础。',
    tag: '风险模型',
    tagClass: 'sk-tag-red',
    iconType: 'analytics',
    category: '平台相关',
    keywords: ['Dempster-Shafer', 'D-S', '证据理论', 'BPA', 'belief', 'disbelief', 'uncertainty', '不确定性', 'Murphy', '融合', 'fusion', 'Jousselme', '距离', 'Zadeh', '悖论', 'Copula', '依赖校正', '主观逻辑', 'subjective logic', 'Noisy-OR', '贝叶斯', 'Bayesian', '多引擎', 'risk score', '风险分数', 'BEC', 'phishing', 'ATO', '对抗鲁棒性', 'robustness', 'diversity'],
    sections: [
      {
        heading: '为什么需要 D-S 证据理论',
        plainText: '传统贝叶斯方法用单一概率 P(threat) 表达威胁程度。当一个检测模块无法判断时，它只能输出 P=0.5，但这与模块明确认为50%概率是威胁完全不同。前者是不确定 后者是确定的中等风险。Noisy-OR 模型假设各证据源独立，无法处理证据冲突。当两个模块一个说高危一个说安全时 Noisy-OR 简单地相乘 无法表达冲突本身就是重要信号。Dempster-Shafer 证据理论引入三值表示 belief disbelief uncertainty 显式区分确定性判断和不确定状态 为多源融合提供了理论基础',
      },
      {
        heading: 'BPA 三元组：显式不确定性建模',
        plainText: '在辨识框架 Θ = {Threat, Normal} 上定义基本概率赋值 Basic Probability Assignment BPA 简化为三元组 b d u。b belief 对 Threat 的信度 即恶意信度。d disbelief 对 Normal 的信度 即正常信度。u uncertainty 分配给整个框架 Θ 的质量 表示不确定度。约束条件 b + d + u = 1。从传统评分转换：给定模块输出 score confidence，b = score × confidence，d = (1-score) × confidence，u = 1 - confidence。风险分数计算 Risk = b + η × u，η 称为风险态度参数 取 0.7 表示将 70% 的不确定性视为威胁。Pignistic 概率：P_bet(Threat) = b + u/2，将不确定性均匀分配',
      },
      {
        heading: 'Dempster 合成规则与 Zadeh 悖论',
        plainText: '给定两个 BPA m₁ 和 m₂ Dempster 合成规则通过正交和计算联合信度。冲突因子 K = m₁(T)·m₂(N) + m₁(N)·m₂(T)。合成结果 m(T) = [m₁(T)·m₂(T) + m₁(T)·m₂(Θ) + m₁(Θ)·m₂(T)] / (1-K)。m(N) = [m₁(N)·m₂(N) + m₁(N)·m₂(Θ) + m₁(Θ)·m₂(N)] / (1-K)。m(Θ) = m₁(Θ)·m₂(Θ) / (1-K)。Zadeh 悖论：当两个证据源高度冲突时 K 接近 1 分母趋近于零 合成结果将少量一致证据放大到极端 产生反直觉结论。例如传感器A说99%是Threat 传感器B说99%是Normal K=0.98 合成后可能给出一个荒谬的高确信结果。需要在融合前进行冲突预处理',
      },
      {
        heading: 'Murphy 修正融合算法',
        plainText: 'Murphy 修正通过证据距离加权平均预处理解决 Zadeh 悖论。第一步 Jousselme 证据距离。d_J(m₁, m₂) = sqrt(0.5 · (m₁-m₂)ᵀ · D · (m₁-m₂))，D 矩阵基于焦元的 Jaccard 相似度。对于二元框架 D 为 3×3 矩阵 对角线为 1 |T∩N|/|T∪N|=0 |T∩Θ|/|T∪Θ|=0.5。第二步 相似度与可信度。sim(i,j) = 1 - d_J(i,j)。crd(i) = Σⱼ≠ᵢ sim(i,j) 可信度等于与其他所有证据的相似度之和。w_i = crd(i) / Σ crd(j) 归一化权重。第三步 加权平均。m_avg = Σ w_i · m_i 得到消除冲突后的平均证据。第四步 自合成。m_final = m_avg ⊕ m_avg ⊕ ... 共 N-1 次 Dempster 合成 N 为引擎数量 多次自合成增强证据收敛性',
      },
      {
        heading: 'Copula 依赖校正',
        plainText: 'Dempster 合成规则假设证据源之间相互独立。但实际系统中 内容分析引擎与语义意图引擎可能共享文本特征 URL 分析与内容分析可能观察到相同的钓鱼 URL 这种相关性会导致证据被重复计算。Copula 依赖校正通过相关系数矩阵 R 量化引擎间相关性。对于相关系数 ρ_ij 较高的引擎对 在融合前注入不确定性：b_i_new = b_i × (1 - ρ_ij)，u_i_new = u_i + (b_i + d_i) × ρ_ij。直觉是 相关的引擎给出的证据要打折扣 因为它们不是真正独立的信息源。默认相关系数矩阵 内容B与语义F相关 0.30 URL分析D与内容B相关 0.20 其余引擎对间 ρ ≤ 0.15',
      },
      {
        heading: '八引擎架构设计',
        plainText: '系统采用八个互补引擎覆盖邮件威胁的不同维度。引擎A 发件人信誉 SPF DKIM 验证结果 域名信誉 发送历史。引擎B 内容分析 JS散度字符分布 紧迫性语义 附件风险 HTML 结构异常。引擎C 行为基线 GMM 高斯混合模型 建模正常行为 孤立森林检测异常偏离。引擎D URL分析 链接信誉 重定向链分析 QR码URL提取 LOTS Living-off-Trusted-Sites 检测。引擎E 协议合规 邮件头完整性 MIME结构 Received链路一致性。引擎F 语义意图 通过 LLM 或规则分析邮件业务意图 付款转账 凭据索取等高风险操作识别。引擎G 身份异常 首次通信检测 通信模式突变 回复链异常 客户端指纹变化。引擎H 交易关联 提取银行账号 金额等业务实体 与已知模式比对 验证操作合理性。最终风险分数 Risk_single = b_final + η × u_final 其中 η = 0.7',
      },
      {
        heading: '对抗鲁棒性约束',
        plainText: '攻击者可能针对性地规避某个引擎。多样性约束确保系统不过度依赖任何单一引擎。约束条件 w_i ≤ 0.4 × Σw_j 任何单引擎权重不超过总权重的 40%。降级分析 模拟移除每个引擎后的最差情况检测率 确保去掉任何一个引擎后系统仍能有效检测。如果某引擎权重超过阈值 多余部分重新分配给其余引擎 按原有比例分配',
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
    category: '平台相关',
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
        plainText: '为每个发件人和域名维护一个持续衰减的风险累积值。R_entity(t) = α × R_entity(t-1) + (1-α) × r_new 其中 α = 0.92 衰减因子。这意味着每封新邮件的风险以 8% 的权重融入历史 同时历史风险以 92% 的速度衰减。当 R_entity 超过观察名单阈值 默认 0.3 时 该实体被列入持续监控名单。被监控的实体其后续邮件在时序分析中获得额外风险加成。衰减机制确保良性实体不会因为偶尔一封误报而永久受影响',
      },
      {
        heading: 'HMM 五状态攻击阶段推断',
        plainText: '隐马尔可夫模型 Hidden Markov Model 用于推断发件人-收件人对之间的攻击阶段。五个隐状态 S0 正常通信 S1 侦察阶段 S2 信任建立 S3 攻击实施 S4 收割获利。转移矩阵反映攻击的典型进程 正常状态自转移概率最高 0.97 偶尔转向侦察 0.02。侦察可转向信任建立 0.08。信任建立可升级为攻击实施 0.06。攻击实施可进入收割 0.15。观测向量 O = (risk_single, u_final, K_conflict, 时间间隔, 内容相似度变化)。每个状态有对应的发射概率分布 正常状态期望低风险低冲突 攻击状态期望高风险高冲突。前向算法在线推断后验概率 γ_t(s) = P(S_t=s | O₁...O_t)。时序风险 Risk_temporal = Σ γ_t(s) × w_s 其中权重 w = {0.0, 0.3, 0.5, 1.0, 1.0} 对应五个状态',
      },
      {
        heading: '通信图谱异常检测',
        plainText: '维护一个有向加权图 节点为邮箱地址 边为通信记录 包含频率和风险历史。三种异常模式。模式一 新发件人群发 一个首次出现的发件人短时间内向大量收件人发送邮件 典型的群发钓鱼。检测条件 发件人邮件数 < 阈值 且 出度 (唯一收件人数) > 阈值。模式二 已知发件人新增高风险边 一个历史正常的发件人突然向新收件人发送高风险邮件 疑似 BEC 横向移动。检测条件 发件人邮件数 > 阈值 且 新边风险 > 0.5。模式三 出度突增 已有发件人的唯一收件人数突然爆增 可能是数据外泄或账户被盗。检测条件 新出度 / 旧出度 > 突增比率阈值',
      },
      {
        heading: 'GPD 极值理论与尾部风险',
        plainText: '广义帕累托分布 Generalized Pareto Distribution 用于建模风险分数的极端尾部行为。仅对超过阈值 u 的观测值拟合 P(X > x | X > u) = (1 + ξ(x-u)/σ)^{-1/ξ}。阈值 u 取历史风险分数的 95 分位数。形状参数 ξ 决定尾部厚度 ξ > 0 为重尾 Frechet 分布 ξ = 0 为指数尾。尺度参数 σ 决定尾部展宽程度。参数通过 PWM 概率加权矩方法拟合。重现期 T 对应的 VaR VaR_T = u + (σ/ξ) × [(n/N_u × T)^ξ - 1]。条件风险价值 CVaR = VaR_T × (1 + (σ - ξ×u) / ((1-ξ) × VaR_T)) 是超越 VaR 的期望损失。高重现期意味着该风险水平在正常流量中极为罕见 T > 10000 表示万封邮件一遇',
      },
      {
        heading: 'P0-P3 动态告警分级',
        plainText: '基于期望损失和多维信号的四级告警体系。期望损失 EL = Risk_final × Impact_target 其中 Impact 根据收件人角色加权 高管 5.0 财务 4.5 IT管理 4.0。P0 最高优先级 触发条件 EL ≥ 3.0 或 K_conflict > 0.7 或 CUSUM + HMM 攻击阶段同时触发 或 EVT 重现期 T ≥ 10000。P1 高优先级 触发条件 EL ∈ [1.5, 3.0) 或 K_conflict > 0.6 或 EVT T ∈ [1000, 10000)。P2 中优先级 触发条件 EL ∈ [0.5, 1.5) 或 u_final > 0.6 或 CUSUM 单独报警。P3 低优先级 触发条件 Risk_final ≥ 0.15。告警级别从高到低取最严格级别。每个告警记录包含判定依据和相关联的 verdict 信息 支持分析人员快速定位和确认',
      },
    ],
  },
  {
    id: 'module-pipeline',
    title: '安全模块管线与融合实现',
    subtitle: 'Security Module Pipeline & D-S Fusion Integration',
    lead: 'Vigilyx 的安全分析管线由 14 个专业模块组成，通过 DAG 并行编排执行，每个模块输出 (score, confidence) 评分对。这些评分通过 BPA 转换进入八引擎 D-S Murphy 融合管线，最终产生统一的风险判定。本文详解模块如何运作以及如何与数学模型衔接。',
    tag: '风险模型',
    tagClass: 'sk-tag-red',
    iconType: 'analytics',
    category: '平台相关',
    keywords: ['模块', 'module', 'pipeline', '管线', 'SecurityModule', 'ModuleResult', '编排', 'orchestrator', 'DAG', '并行', 'parallel', 'timeout', '超时', 'score', 'confidence', 'BPA', '转换', 'conversion', '引擎映射', 'engine map', 'content_scan', 'domain_verify', 'link_scan', 'header_scan', 'semantic_scan', 'anomaly_detect', 'attach_scan', '融合管线', 'fusion pipeline', 'Dempster', 'Copula', 'Murphy', '信任折扣', 'trust discount', 'threat level', '威胁等级'],
    sections: [
      {
        heading: '模块系统架构',
        plainText: '每个安全模块实现 SecurityModule trait 包含三个核心方法。metadata 返回模块元数据包括 ID 名称 所属支柱 依赖列表和超时配置。analyze 接收 SecurityContext 执行分析返回 ModuleResult。should_run 可选的前置过滤器决定是否执行。SecurityContext 上下文包含完整的邮件会话数据 EmailSession 含邮件头 正文 附件 链接等 以及已完成模块的结果缓存 允许后续模块引用前序模块的输出。ModuleResult 是所有模块统一的输出结构 包含 module_id 模块标识 threat_level 威胁等级 confidence 置信度 categories 威胁分类标签 summary 人类可读摘要 evidence 详细证据列表 details JSON 扩展信息含 score 原始评分',
      },
      {
        heading: '十四个安全模块',
        plainText: '引擎A 发件人信誉 domain_verify 验证发件域名与 Received 链 DKIM 链接域名的一致性 输出 trust_score 0-1 用于最终判定折扣。引擎B 内容分析包含五个模块 content_scan 扫描正文中的钓鱼关键词 BEC 话术 DLP 敏感信息 外部冒充 语言不一致。html_scan 检测 HTML 特有威胁如隐藏文本 混淆标签 可疑表单 data URI。attach_scan 检查附件元数据如危险扩展名 双扩展名 伪装 exe。attach_content 深度检测附件内容如嵌入宏 脚本 PE 头 ZIP 炸弹。attach_hash 附件 SHA256 哈希与 IOC 黑名单匹配。引擎C 行为基线 anomaly_detect 检测行为异常如群发邮件 空主题带附件 全大写标题 spam cannon。引擎D URL 分析包含三个模块 link_scan 检测 URL 模式如 IP 地址 URL data URI javascript URI 文本链接不匹配 短链接 过多链接。link_reputation 外部信誉查询 VirusTotal URLhaus PhishTank。link_content 实时抓取 URL 目标页面分析着陆页风险。引擎E 协议合规包含两个模块 header_scan 邮件头验证如缺失 Date Message-ID SPF DKIM DMARC 失败 Received 链异常。mime_scan MIME 结构检查如畸形 multipart boundary 违规 编码错误 嵌套深度滥用。引擎F 语义意图 semantic_scan 无语义文本检测通过三个指标 CJK 罕用字符比率 Shannon 熵异常 Bigram 唯一性',
      },
      {
        heading: '管线编排器：DAG 并行分层执行',
        plainText: '编排器使用 Kahn 拓扑排序算法将模块依赖关系构建为有向无环图 DAG 然后分层执行。每一层中的模块无依赖关系 可以并行执行。层间是串行的 确保前层结果对后层可用。典型分层 第 0 层包含所有无依赖的基础模块如 content_scan link_scan header_scan domain_verify anomaly_detect 等约 12 个模块同时运行。第 1 层是依赖前序结果的模块如 verdict_module。每个模块有独立的超时配置 默认 3-5 秒。超时后模块返回 Safe 结果并标记超时 不影响其他模块继续执行。条件执行 每个模块可通过 should_run 方法跳过不适用的分析 如邮件无附件时跳过 attach_scan。ConditionConfig 支持最低威胁等级门槛 仅当前序模块已发现一定威胁时才运行高级分析',
      },
      {
        heading: '从评分到三元组：模块输出转换',
        plainText: '每个模块输出 score 原始风险评分 0-1 和 confidence 置信度 0-1。管线末端需要将这些传统评分转换为 D-S 三元组 BPA。转换公式 b = score × confidence 表示有多少证据支持 Threat。d = (1 - score) × confidence 表示有多少证据支持 Normal。u = 1 - confidence 表示模块对自己判断的不确定程度。举例 content_scan 发现多个钓鱼关键词 score=0.70 confidence=0.85 则 b=0.595 d=0.255 u=0.150 高信度高风险。domain_verify 域名验证通过 score=0.10 confidence=0.90 则 b=0.09 d=0.81 u=0.10 高信度低风险。semantic_scan 文本太短无法判断 score=0.30 confidence=0.20 则 b=0.06 d=0.14 u=0.80 低信度高不确定。第三个例子的关键价值 传统系统中 score=0.30 被视为低风险可忽略 但 D-S 框架下 u=0.80 意味着该模块基本没有有效信息 不应影响最终判定 由其他引擎主导',
      },
      {
        heading: '八引擎映射与引擎内合成',
        plainText: '16 个模块映射到 8 个概念引擎。引擎A domain_verify 1个模块。引擎B content_scan html_scan html_pixel_art attach_scan attach_content attach_hash 6个模块。引擎C anomaly_detect 1个模块。引擎D link_scan link_reputation link_content 3个模块。引擎E header_scan mime_scan 2个模块。引擎F semantic_scan 1个模块。引擎G identity_anomaly 1个模块。引擎H transaction_correlation 1个模块。对于多模块引擎 如 B 和 D 需要先进行引擎内 Dempster 合成。将同一引擎内各模块的 BPA 通过标准 Dempster 规则逐步合成为一个引擎级 BPA。例如引擎 B 的五个模块输出五个 BPA 先将 m1 与 m2 合成得到 m12 再与 m3 合成得到 m123 依此类推。引擎内合成过程中如果冲突因子 K 接近 1 说明同一引擎的子模块产生矛盾 合成退回 vacuous BPA 即完全不确定',
      },
      {
        heading: 'Copula 折扣与 Murphy 融合',
        plainText: '引擎内合成完成后 进入跨引擎 Murphy 融合管线。第一步 Copula 依赖折扣 对每个引擎找到与之最相关的引擎的相关系数 max_ρ 如果 max_ρ 大于 0.1 则对该引擎的 BPA 进行折扣 b_new = b × (1-max_ρ) d_new = d × (1-max_ρ) u_new = 1 - b_new - d_new 即将 (1-α) 的质量转移到不确定性。第二步 Jousselme 距离矩阵 计算每对引擎 BPA 之间的距离。第三步 可信度权重 similarity = 1 - distance 可信度 = 与其他引擎的相似度之和 权重 = 归一化可信度。第四步 多样性约束 对抗鲁棒性 任何单引擎权重不超过总权重 40% 超出部分按比例重分配。第五步 加权平均 m_avg = Σ w_i × m_i。第六步 自合成 N-1 次 m_final = m_avg ⊕ m_avg ⊕ ... 多次自合成增强一致证据的收敛',
      },
      {
        heading: '信任信号折扣机制',
        plainText: 'domain_verify 模块输出的 trust_score 0-1 作为特殊的信任信号 独立于 D-S 融合管线。当域名验证完全通过 SPF pass DKIM valid 域名一致 trust_score 接近 1.0 时 最终风险分数会被折扣。折扣公式 final_score = risk_score × (1 - trust_score × 0.4)。举例 risk_score=0.60 trust_score=1.0 则 final_score = 0.60 × 0.60 = 0.36 从 Medium 降级为 Low。直觉 如果发件人身份完全可信 SPF DKIM 都通过 域名未伪造 那么内容层面的风险需要打折。但折扣上限为 40% 即使完全可信也只能降低 40% 的风险 确保高风险内容仍能触发告警',
      },
      {
        heading: '最终判定：风险分数与威胁等级',
        plainText: '经过 D-S Murphy 融合和信任折扣后 最终风险分数通过固定阈值映射到五级威胁等级。Risk_single = b_final + η × u_final 其中 η=0.3。Critical 危急 risk ≥ 0.85 确认的高危攻击。High 高危 risk ≥ 0.65 多引擎交叉确认的威胁。Medium 中危 risk ≥ 0.40 部分引擎标记需人工复核。Low 低危 risk ≥ 0.15 轻微可疑但不足以告警。Safe 安全 risk 小于 0.15 正常邮件。完整的端到端流程 16个模块并行分析 → 各输出 score confidence → 转换为 BPA 三元组 → 按引擎映射分组 → 引擎内 Dempster 合成 → Copula 依赖折扣 → Murphy 加权平均 → 多样性约束 → 自合成 N-1 次 → 计算 Risk_single → 信任折扣 → 映射威胁等级 → 写入判定记录 + WebSocket 广播',
      },
    ],
  },
  // ============== Newly added articles (2026-03-19) ==============
  {
    id: 'phishing-detection' as TopicId,
    title: '钓鱼邮件检测技术',
    subtitle: '20 个检测模块的原理与协作',
    lead: 'Vigilyx 通过 20 个检测模块从内容、附件、链接、协议、语义、行为 6 个维度分析邮件，覆盖 75 种威胁类别。',
    tag: '检测',
    tagClass: 'sk-tag-red',
    iconType: 'shield' as const,
    category: '平台相关' as CategoryFilter,
    sections: [
      {
        heading: '多维检测架构',
        plainText: '邮件威胁不是单一维度能捕获的。一封精心制作的钓鱼邮件可能通过了 SPF/DKIM 验证（协议层无异常），使用了合法域名的子域名（发件人层难以判断），但在正文中包含紧迫性话术（内容层异常）+ 伪装成银行登录页的链接（链接层异常）。Vigilyx 的 16 个模块分属 8 个引擎，每个引擎独立输出证据，最终通过 D-S Murphy 融合产生裁决。没有任何单一模块能决定最终结果。',
      },
      {
        heading: '内容分析引擎 (B)',
        plainText: 'content_scan 是核心模块，维护三类检测规则库：钓鱼关键词库（如"账户异常""立即验证""密码过期"等），每命中一个关键词加 0.08 分，上限 0.50；BEC 商务欺诈短语库（如"紧急汇款""更改收款账户"等 27 个短语），每命中加 0.15 分，上限 0.50；DLP 敏感数据模式（信用卡 Luhn 校验、身份证号、API Key 正则匹配）。html_scan 检测恶意 HTML 元素（隐藏表单、脚本注入、事件处理器、Base64 嵌入）。html_pixel_art 检测 1px 追踪信标和隐藏图片。attach_scan 检测危险文件类型（PE 可执行文件、双扩展名如 .pdf.exe、加密压缩包、宏文档），通过 magic bytes 魔数识别 26 种文件类型。attach_content 对 ZIP/RAR 解压后提取文档文本再做内容分析。attach_hash 计算附件 SHA256 并查询本地黑名单 + 外部情报源。',
      },
      {
        heading: 'URL 链接分析引擎 (D)',
        plainText: 'link_scan 从 HTML 中提取所有 URL，检测 IP 地址直接访问链接、同形字攻击（如用 а(Cyrillic) 替代 a(Latin)）、Punycode 编码域名、短链服务、href 与显示文本不匹配（"点击这里"指向钓鱼站）。link_reputation 查询 OTX AlienVault 和 VirusTotal 情报，OTX 查看域名/IP/URL 关联的威胁脉冲数，VT 通过 Playwright 自动化抓取检测引擎共识比例。link_content 实际抓取链接目标页面，分析是否包含登录表单、JavaScript 载荷、可疑重定向链条。',
      },
      {
        heading: '语义与行为分析 (F/G/H)',
        plainText: 'semantic_scan 采用双层架构：Rust 本地引擎做 CJK 稀有字符比例、Shannon 熵、双字符唯一性分析，检测无语义乱码垃圾邮件；Python NLP 引擎使用 mDeBERTa 多语言模型做零样本或微调五分类（钓鱼/诈骗/BEC/垃圾/正常），输出恶意概率。identity_anomaly 检测首次联系人、显示名与域名不匹配（如显示"中国银行"但域名是 gmail.com）、通信模式突变。transaction_correlation 识别邮件中的银行账号（正则+上下文）、商业实体名称（NER 抽取）、紧迫性关键词与金融实体同时出现的 BEC 风险信号。',
      },
      {
        heading: '安全熔断器：防止融合漏报',
        plainText: 'D-S Murphy 融合可能将少数派引擎的威胁信号稀释。例如 content_scan 强烈报警但其余 7 个引擎均为安全→融合后风险≈0。熔断器机制：当任一规则模块的 belief ≥ 0.20 且 confidence ≥ 0.80 时，将融合后的风险拉回该模块 belief 值。当 3+ 独立模块同时报警时，按 1+0.15×(n-2) 放大地板值。当 2+ 高信念模块收敛时，至少保证 Medium 级别(0.40)。这确保了高信度的单引擎检测不会被多数"无信号"引擎完全压制。',
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
    category: '平台相关' as CategoryFilter,
    sections: [
      {
        heading: 'IOC 类型与来源',
        plainText: '系统支持 6 种 IOC 类型：IP 地址（Received 头中的外部 IP）、邮箱地址（mail_from 发件人）、域名（发件域名）、文件哈希（附件 SHA256）、URL（link_scan 标记的可疑链接）、邮件主题（特征主题模式）。每个 IOC 记录包含：indicator 值、类型、来源（auto/manual/admin_clean）、判定（malicious/suspicious/clean）、置信度 0-1、攻击类型推断、命中计数、过期时间。IOC 来源分三类：auto（引擎自动写入）、manual（管理员手动添加）、admin_clean（白名单保护，不被自动覆盖）。',
      },
      {
        heading: '自动记录与正反馈循环防护',
        plainText: '当邮件裁决达到 High 级别时，引擎自动从该邮件提取 IOC（IP、域名、哈希、URL、邮箱）并写入数据库。阈值设计原则：不能低于 High。原因：如果阈值是 Medium，一封 Medium 风险邮件的域名被写入 IOC → 后续该域名的正常邮件命中 IOC 加分 → 风险升到 High → UPSERT 提高置信度 → 循环放大。UPSERT 策略：新值直接覆盖旧值（不再用 MAX 只升不降），admin_clean 来源的条目受保护不被自动覆盖。IOC 默认 TTL 30 天，过期后不再命中。',
      },
      {
        heading: '外部情报源查询',
        plainText: '每封邮件检测时，intel 模块并行查询三个外部源：OTX AlienVault（10 次/分钟速率限制，通过 pulse_count 判定：≥10 脉冲→malicious，3-9→suspicious，<3→clean）；VirusTotal（6 次/分钟，通过 Playwright 抓取页面获取引擎检测共识：≥30% 检出→malicious，≥10%→suspicious）；AbuseIPDB（可选，IP 滥用分数）。查询结果缓存到本地 IOC 表，TTL：malicious 3天、suspicious 1天、clean 7天。Intel 查询先查本地 IOC 缓存，命中则直接返回不发起外部请求。',
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
    lead: 'Vigilyx 的 AI 服务使用 mDeBERTa 多语言预训练模型，支持零样本分类和基于分析师反馈的 LoRA 微调训练。',
    tag: 'AI',
    tagClass: 'sk-tag-purple',
    iconType: 'analytics' as const,
    category: '平台相关' as CategoryFilter,
    sections: [
      {
        heading: '双模型优先级',
        plainText: '推理时优先使用 Fine-tuned 五分类模型（如果已训练）。Fine-tuned 模型保存在 data/nlp_models/latest/ 目录，基于分析师的误报/漏报反馈训练而来，对本组织的邮件特征有更好的适应性。如果没有 Fine-tuned 模型或加载失败，回退到零样本分类模型。零样本模型使用 NLI（自然语言推理）机制，不需要训练数据即可工作，但准确率略低。两个模型共享同一个基座：MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7（约 550MB，支持 100+ 语言）。',
      },
      {
        heading: '零样本分类原理',
        plainText: '零样本分类将邮件内容与 5 个候选标签组成前提-假设对，通过 NLI 模型判断蕴含关系。候选标签（中文版）：钓鱼邮件试图窃取密码或个人信息、诈骗邮件包含虚假优惠或社交工程攻击、商务邮件欺诈要求紧急汇款、垃圾邮件或未经请求的营销广告、正常的工作邮件或个人通信。模型输出每个标签的概率分布，恶意概率 = P(phishing) + P(scam) + P(bec)。语言检测：CJK 字符占比 > 30% 使用中文标签集，否则用英文标签集。',
      },
      {
        heading: 'LoRA 微调训练',
        plainText: '管理员通过分析师反馈（在邮件详情页标记正确类别）积累训练样本。样本达到 30 条后可触发训练。训练使用 LoRA（低秩适配）技术：仅训练 DeBERTa 注意力层的 query_proj 和 value_proj（约 1.5% 参数），其余 98.5% 冻结。高级训练技巧：Focal Loss 聚焦难分样本（γ=2.0）；R-Drop 正则化（同一输入两次 forward pass 的 KL 散度约束）；自动类别加权平衡；稀有类别数据增强（词删除 + 词交换）。K-Fold 交叉验证评估质量，balanced_accuracy ≥ 0.50 且 macro_F1 ≥ 0.40 才通过。训练完成后模型热替换：零停机切换到新模型。',
      },
      {
        heading: 'NLP 与规则引擎的协作',
        plainText: 'semantic_scan 模块中，NLP 结果与 Rust 本地规则引擎结果融合。NLP 模块在断路器中被标记为"非规则模块"（is_rule_module=false），不能单独触发安全地板——因为 NLP 误判率较高（约 60%），允许其单独触发断路器会让 14 个规则模块的"安全"共识被 1 个噪音传感器否决。但 NLP 信号仍然参与 D-S 融合和收敛断路器（多模块共识），当 NLP + 规则模块同时检测到威胁时，收敛断路器自然触发。这种设计在保持 NLP 贡献的同时控制了误报风险。',
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
    category: '平台相关' as CategoryFilter,
    sections: [
      {
        heading: 'P0-P3 四级告警',
        plainText: 'P0 (Critical)：EL ≥ 3.0 或 K_conflict > 0.7 或 CUSUM alarm 或 EVT 回归期 T ≥ 10000 年。含义：确认的高危攻击或引擎严重矛盾，需立即处理。P1 (High)：EL ∈ [1.5, 3.0) 或 K_conflict > 0.6 或 EVT T ∈ [1000, 10000)。含义：多引擎交叉确认的威胁，需优先调查。P2 (Medium)：EL ∈ [0.5, 1.5) 或 u_final > 0.6 或 EVT T ∈ [100, 1000)。含义：部分引擎标记，建议常规审查。P3 (Low)：EL ∈ [0.2, 0.5) 或 Risk_final ≥ 0.15。含义：轻微可疑但不足以告警，低优先级。',
      },
      {
        heading: '期望损失与极值理论',
        plainText: 'EL（Expected Loss）是模块置信度加权的期望损失，综合考虑威胁严重程度和检测确定性。EVT（Extreme Value Theory）使用 GPD（广义 Pareto 分布）对风险尾部建模：收集最近 2000 个样本的超阈值（95 分位数以上）的超出量，通过概率加权矩法估计 GPD 参数（形状参数 ξ 和尺度参数 σ），计算 VaR（在险值）、CVaR（条件在险值，95 分位数以上的平均损失）和回归期 T（同等严重事件的平均间隔）。回归期 T 越大，该事件越罕见、越值得关注。',
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
    title: '数据安全与 HTTP 会话检测',
    subtitle: 'Webmail 流量捕获与数据泄露检测',
    lead: 'Vigilyx 除了分析 SMTP/POP3/IMAP 邮件协议外，还捕获 HTTP Webmail 流量，检测通过网页邮箱进行的数据泄露行为。',
    tag: '数据安全',
    tagClass: 'sk-tag-green',
    iconType: 'lock-closed' as const,
    category: '平台相关' as CategoryFilter,
    sections: [
      {
        heading: 'HTTP 流量捕获',
        plainText: 'Sniffer 通过 WEBMAIL_SERVERS 环境变量配置需要监控的 Webmail 服务器 IP。当捕获到目标 IP 的 HTTP 流量时，解析请求方法、URI、Host、Content-Type、Cookie，提取请求体（前 64KB）中的邮件字段（from/to/subject），支持 URL-encoded、JSON、Coremail 嵌套 JSON 三种格式。HTTP 会话通过 Redis 发布到 vigilyx:http_session:new channel，由数据安全引擎 (DataSecurityEngine) 独立处理。',
      },
      {
        heading: '三类数据泄露检测模式',
        plainText: '草稿箱滥用 (draft_box_abuse)：用户将敏感数据保存为邮件草稿而非直接发送，绕过出站邮件检测。检测方式：识别 Coremail compose.jsp 的保存草稿请求，提取草稿内容进行 DLP 扫描。文件中转滥用 (file_transit_abuse)：通过 Webmail 的文件上传功能中转敏感文件。检测方式：识别分块上传（Coremail chunked upload），重组完整文件内容后扫描。自发送检测 (self_sending)：用户给自己的邮箱发送包含敏感数据的邮件，绕过 DLP 策略。检测方式：比对 from 和 to 字段是否为同一用户（不区分大小写）。',
      },
      {
        heading: 'DLP 敏感数据扫描',
        plainText: '数据安全引擎对 HTTP 会话的请求体和上传文件执行 DLP 扫描，检测：银行卡号（16-19 位数字，Luhn 校验）、身份证号（18 位，含校验位验证）、手机号（中国大陆 11 位格式）、合同编号/发票号（特定格式模式）、金额数据（大于阈值的金融数字）。事件按严重程度分级：info（仅记录）、low（低风险）、medium（中等，可能需要审查）、high（高风险，建议阻断）、critical（严重，立即告警）。所有事件持久化到 data_security_incidents 表，通过 API 和 WebSocket 实时推送到前端展示。',
      },
    ],
    keywords: ['数据安全', 'HTTP', 'Webmail', 'DLP', '数据泄露', '草稿箱', '文件中转', '自发送', 'Coremail', '银行卡', '身份证', '敏感数据', '分块上传', 'chunked', 'DataSecurityEngine', '请求体'],
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
    category: '邮件安全知识' as CategoryFilter,
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
        plainText: 'content_scan 模块检测 BEC 关键词组合（紧急+转账+高管头衔）。identity_anomaly 模块检测显示名欺诈（显示名是内部高管但邮箱是外部域名）。transaction_correlation 模块关联紧迫性关键词与金融实体。NLP 模型分类中包含 nlp_bec 类别。首次通信检测标记从未联系过的"供应商"。',
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
    category: '邮件安全知识' as CategoryFilter,
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
    category: '邮件安全知识' as CategoryFilter,
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
    category: '邮件安全知识' as CategoryFilter,
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

export const topicEntries: TopicEntry[] = rawTopics.map(raw => {
  const searchableText = buildSearchableText(raw)
  return {
    ...raw,
    searchableText,
    readingTime: estimateReadingTime(searchableText),
  }
})

export function getTopicEntry(id: TopicId): TopicEntry | undefined {
  return topicEntries.find(t => t.id === id)
}
