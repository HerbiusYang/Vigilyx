/* ====== Topic: MTA ====== */
export function TopicMTA() {
  return (
    <article className="sk-article">
      <div className="sk-article-header">
        <span className="sk-tag sk-tag-blue">基础</span>
        <h1>什么是 MTA (Mail Transfer Agent)</h1>
        <p className="sk-lead">MTA 是负责在互联网上传递电子邮件的服务器软件。每封邮件从发送到接收，至少经过 2 个 MTA。</p>
      </div>

      <section className="sk-section">
        <h2>核心概念</h2>
        <p>MTA (Mail Transfer Agent，邮件传输代理) 是电子邮件基础设施的核心组件。它的职责是<strong>接收邮件并将其路由到下一个目的地</strong>，类似于现实中的邮局分拣中心。</p>
        <div className="sk-callout info">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </span>
          <div>
            <strong>常见的 MTA 软件：</strong>Postfix、Sendmail、Exim、Microsoft Exchange、Coremail
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>邮件投递流程</h2>
        <p>当你发送一封邮件时，它会经过以下路径：</p>
        <div className="sk-flow">
          <div className="sk-flow-node">
            <div className="sk-flow-icon sender">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            </div>
            <div className="sk-flow-label">发件人</div>
            <div className="sk-flow-sub">MUA (邮件客户端)</div>
          </div>
          <div className="sk-flow-arrow">
            <span>SMTP :587</span>
          </div>
          <div className="sk-flow-node">
            <div className="sk-flow-icon mta">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            </div>
            <div className="sk-flow-label">发件 MTA</div>
            <div className="sk-flow-sub">如 smtp.gmail.com</div>
          </div>
          <div className="sk-flow-arrow">
            <span>SMTP :25</span>
          </div>
          <div className="sk-flow-node">
            <div className="sk-flow-icon relay">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>
            </div>
            <div className="sk-flow-label">中继 MTA</div>
            <div className="sk-flow-sub">(可选) 网关/过滤</div>
          </div>
          <div className="sk-flow-arrow">
            <span>SMTP :25</span>
          </div>
          <div className="sk-flow-node">
            <div className="sk-flow-icon mta">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            </div>
            <div className="sk-flow-label">收件 MTA</div>
            <div className="sk-flow-sub">通过 MX 记录定位</div>
          </div>
          <div className="sk-flow-arrow">
            <span>POP3/IMAP</span>
          </div>
          <div className="sk-flow-node">
            <div className="sk-flow-icon sender">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            </div>
            <div className="sk-flow-label">收件人</div>
            <div className="sk-flow-sub">MUA (邮件客户端)</div>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>MTA 与 Vigilyx 的关系</h2>
        <p>Vigilyx 通过<strong>镜像抓包</strong>捕获 MTA 之间的 SMTP 通信。当邮件在中继链路上传递时，每一跳都会产生一个独立的 session。</p>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>术语</th><th>全称</th><th>角色</th></tr>
            </thead>
            <tbody>
              <tr><td><code>MTA</code></td><td>Mail Transfer Agent</td><td>服务器间转发邮件 (SMTP)</td></tr>
              <tr><td><code>MUA</code></td><td>Mail User Agent</td><td>用户的邮件客户端 (Outlook, Thunderbird)</td></tr>
              <tr><td><code>MDA</code></td><td>Mail Delivery Agent</td><td>将邮件投递到用户邮箱 (dovecot)</td></tr>
              <tr><td><code>MSA</code></td><td>Mail Submission Agent</td><td>接收用户提交的邮件 (端口 587)</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </article>
  )
}

/* ====== Topic: Opportunistic TLS ====== */
export function TopicOpportunisticTLS() {
  return (
    <article className="sk-article">
      <div className="sk-article-header">
        <span className="sk-tag sk-tag-amber">加密</span>
        <h1>什么是机会性 TLS (Opportunistic TLS)</h1>
        <p className="sk-lead">机会性 TLS 是一种"能加密就加密，不能就算了"的策略。它是当今 MTA 之间最主流的加密方式，但存在被降级攻击的风险。</p>
      </div>

      <section className="sk-section">
        <h2>工作原理</h2>
        <p>机会性 TLS 的流程如下：</p>
        <ol className="sk-steps">
          <li>
            <strong>发件 MTA 连接到收件 MTA</strong>
            <span>建立普通的 TCP 连接 (端口 25)，此时是<em>明文</em></span>
          </li>
          <li>
            <strong>EHLO 握手</strong>
            <span>发件方发送 <code>EHLO</code> 命令，收件方返回支持的扩展列表</span>
          </li>
          <li>
            <strong>检查是否支持 STARTTLS</strong>
            <span>如果收件方在响应中包含 <code>250-STARTTLS</code>，说明它支持 TLS 升级</span>
          </li>
          <li>
            <strong>发送 STARTTLS 命令</strong>
            <span>发件方发送 <code>STARTTLS</code>，收件方回复 <code>220 Ready to start TLS</code></span>
          </li>
          <li>
            <strong>TLS 握手</strong>
            <span>双方进行 TLS 协商，后续所有 SMTP 通信均通过加密信道传输</span>
          </li>
        </ol>
      </section>

      <section className="sk-section">
        <h2>机会性 TLS 的关键特征</h2>
        <div className="sk-cards-row">
          <div className="sk-info-card">
            <div className="sk-info-card-header good">优势</div>
            <ul>
              <li>无需预配置，自动协商</li>
              <li>向后兼容不支持 TLS 的服务器</li>
              <li>部署成本极低，广泛使用</li>
              <li>比完全不加密好得多</li>
            </ul>
          </div>
          <div className="sk-info-card">
            <div className="sk-info-card-header bad">风险</div>
            <ul>
              <li>可被 STRIPTLS 降级攻击</li>
              <li>通常不验证服务器证书</li>
              <li>中间人可篡改 EHLO 响应</li>
              <li>用户无法感知是否加密</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>降级攻击 (STRIPTLS Attack)</h2>
        <p>这是机会性 TLS 最大的安全隐患。攻击者在网络中间（如路由器、ISP）拦截流量，修改 EHLO 响应，删除 <code>250-STARTTLS</code> 行。发件 MTA 看不到 STARTTLS 支持，就会退回到<strong>明文传输</strong>。</p>
        <div className="sk-diagram">
          <div className="sk-diagram-row">
            <span className="sk-diagram-label">正常</span>
            <div className="sk-diagram-flow">
              <code>发件MTA</code>
              <span className="sk-arrow good">--STARTTLS--&gt;</span>
              <code>收件MTA</code>
            </div>
            <span className="sk-badge-inline good">加密</span>
          </div>
          <div className="sk-diagram-row">
            <span className="sk-diagram-label">攻击</span>
            <div className="sk-diagram-flow">
              <code>发件MTA</code>
              <span className="sk-arrow bad">--明文--&gt;</span>
              <code className="sk-attacker">攻击者</code>
              <span className="sk-arrow bad">--明文--&gt;</span>
              <code>收件MTA</code>
            </div>
            <span className="sk-badge-inline bad">明文</span>
          </div>
        </div>
        <div className="sk-callout warning">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </span>
          <div>
            <strong>Vigilyx 中的体现：</strong>如果你在 SMTP 对话中看到服务端支持 STARTTLS 但最终会话未加密，可能遭遇了降级攻击或客户端未发起 STARTTLS。
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>与 Vigilyx 抓包的关系</h2>
        <p>机会性 TLS 对 Vigilyx 的影响：</p>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>场景</th><th>Vigilyx 能看到什么</th></tr>
            </thead>
            <tbody>
              <tr><td>STARTTLS 成功</td><td>EHLO + STARTTLS 命令可见，之后为加密密文 (无法还原邮件内容)</td></tr>
              <tr><td>未发起 STARTTLS</td><td>全部 SMTP 对话明文可见，可完整还原邮件</td></tr>
              <tr><td>端口 465 (隐式 TLS)</td><td>从第一个包起就是加密，完全不可见</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </article>
  )
}

/* ====== Topic: Mandatory TLS ====== */
export function TopicMandatoryTLS() {
  return (
    <article className="sk-article">
      <div className="sk-article-header">
        <span className="sk-tag sk-tag-green">加密</span>
        <h1>什么是强制 TLS (Mandatory TLS)</h1>
        <p className="sk-lead">强制 TLS 要求 MTA 之间的通信<em>必须</em>加密。如果无法建立加密通道，邮件将被拒绝发送，而非降级为明文。</p>
      </div>

      <section className="sk-section">
        <h2>为什么需要强制 TLS</h2>
        <p>机会性 TLS 的根本问题是<strong>加密是可选的</strong>。攻击者可以通过 STRIPTLS 攻击强制降级为明文。强制 TLS 解决的正是这个问题：</p>
        <div className="sk-compare">
          <div className="sk-compare-col">
            <div className="sk-compare-header amber">机会性 TLS</div>
            <div className="sk-compare-body">
              <p>"尝试加密，失败则回退到明文"</p>
              <code>if (starttls_supported) encrypt() else plaintext()</code>
            </div>
          </div>
          <div className="sk-compare-vs">VS</div>
          <div className="sk-compare-col">
            <div className="sk-compare-header green">强制 TLS</div>
            <div className="sk-compare-body">
              <p>"必须加密，失败则拒绝发送"</p>
              <code>if (starttls_ok &amp;&amp; cert_valid) encrypt() else reject()</code>
            </div>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>实现方式</h2>
        <div className="sk-cards-col">
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">1</div>
            <div className="sk-detail-card-content">
              <h3>MTA-STS (RFC 8461)</h3>
              <p>收件域名发布一个 HTTPS 策略文件，声明"所有发往本域的邮件必须使用 TLS"。发件 MTA 在发送前查询此策略。</p>
              <div className="sk-code-block">
                <div className="sk-code-title">https://mta-sts.example.com/.well-known/mta-sts.txt</div>
                <pre>version: STSv1{'\n'}mode: enforce{'\n'}mx: mail.example.com{'\n'}max_age: 86400</pre>
              </div>
              <p className="sk-note">mode 可选值：<code>enforce</code> (强制)、<code>testing</code> (仅报告)、<code>none</code> (禁用)</p>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">2</div>
            <div className="sk-detail-card-content">
              <h3>DANE (RFC 7672)</h3>
              <p>通过 DNSSEC 在 DNS 中发布 TLSA 记录，绑定邮件服务器的 TLS 证书指纹。发件 MTA 通过 DNS 验证证书真实性。</p>
              <div className="sk-code-block">
                <div className="sk-code-title">DNS TLSA 记录</div>
                <pre>_25._tcp.mail.example.com. IN TLSA 3 1 1 2bb183af... </pre>
              </div>
              <p className="sk-note">依赖 DNSSEC，部署门槛较高，但安全性极强 (免疫 CA 被入侵的风险)</p>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">3</div>
            <div className="sk-detail-card-content">
              <h3>手动配置 (TLS Policy)</h3>
              <p>在 Postfix 等 MTA 中手动指定对特定域名强制 TLS：</p>
              <div className="sk-code-block">
                <div className="sk-code-title">Postfix smtp_tls_policy_maps</div>
                <pre>example.com     encrypt{'\n'}bank.com        verify  match=mail.bank.com</pre>
              </div>
              <p className="sk-note">适用于已知的合作方域名，无法覆盖所有收件域</p>
            </div>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>机会性 TLS vs 强制 TLS 完整对比</h2>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>对比项</th><th>机会性 TLS</th><th>强制 TLS</th></tr>
            </thead>
            <tbody>
              <tr><td>加密失败时</td><td>回退到明文</td><td>拒绝发送</td></tr>
              <tr><td>证书验证</td><td>通常不验证</td><td>必须验证</td></tr>
              <tr><td>防降级攻击</td><td>不能</td><td>能</td></tr>
              <tr><td>部署难度</td><td>极低 (默认行为)</td><td>较高 (需 DNS/策略配置)</td></tr>
              <tr><td>兼容性</td><td>最好 (全球适用)</td><td>一般 (需对方也支持)</td></tr>
              <tr><td>Vigilyx 可见性</td><td>STARTTLS 前明文可见</td><td>完全不可见</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </article>
  )
}

/* ====== Topic: STARTTLS ====== */
export function TopicSTARTTLS() {
  return (
    <article className="sk-article">
      <div className="sk-article-header">
        <span className="sk-tag sk-tag-purple">协议</span>
        <h1>STARTTLS 命令详解</h1>
        <p className="sk-lead">STARTTLS 是一种协议扩展命令，用于将已建立的明文连接就地升级为 TLS 加密连接。它是实现机会性 TLS 的核心机制。</p>
      </div>

      <section className="sk-section">
        <h2>SMTP 中的 STARTTLS 交互过程</h2>
        <p>以下是一次典型的 SMTP + STARTTLS 会话，Vigilyx 可以完整捕获加密前的明文部分：</p>
        <div className="sk-smtp-dialog">
          <div className="sk-smtp-line server"><span className="sk-smtp-dir">S:</span><code>220 mail.example.com ESMTP Postfix</code></div>
          <div className="sk-smtp-line client"><span className="sk-smtp-dir">C:</span><code>EHLO sender.example.org</code></div>
          <div className="sk-smtp-line server"><span className="sk-smtp-dir">S:</span><code>250-mail.example.com</code></div>
          <div className="sk-smtp-line server"><span className="sk-smtp-dir">S:</span><code>250-SIZE 52428800</code></div>
          <div className="sk-smtp-line server highlight"><span className="sk-smtp-dir">S:</span><code>250-STARTTLS</code><span className="sk-smtp-note">-- 服务器声明支持 STARTTLS</span></div>
          <div className="sk-smtp-line server"><span className="sk-smtp-dir">S:</span><code>250 8BITMIME</code></div>
          <div className="sk-smtp-line client highlight"><span className="sk-smtp-dir">C:</span><code>STARTTLS</code><span className="sk-smtp-note">-- 客户端请求升级加密</span></div>
          <div className="sk-smtp-line server highlight"><span className="sk-smtp-dir">S:</span><code>220 2.0.0 Ready to start TLS</code><span className="sk-smtp-note">-- 开始 TLS 握手</span></div>
          <div className="sk-smtp-line encrypted"><span className="sk-smtp-dir">&nbsp;</span><code>... TLS 握手 (密文) ...</code></div>
          <div className="sk-smtp-line encrypted"><span className="sk-smtp-dir">&nbsp;</span><code>... 后续 SMTP 命令均加密 (MAIL FROM / DATA 等) ...</code></div>
        </div>
        <div className="sk-callout info">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </span>
          <div>Vigilyx 的 <strong>SMTP 对话</strong> tab 会展示上述明文交互，并在分析摘要中标注 STARTTLS 支持状态和加密状态。</div>
        </div>
      </section>

      <section className="sk-section">
        <h2>STARTTLS vs 隐式 TLS</h2>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>对比项</th><th>STARTTLS (显式 TLS)</th><th>隐式 TLS</th></tr>
            </thead>
            <tbody>
              <tr><td>端口</td><td>25 (MTA 间) / 587 (提交)</td><td>465 (提交)</td></tr>
              <tr><td>连接方式</td><td>先明文，再升级加密</td><td>连接即加密 (TLS 包裹)</td></tr>
              <tr><td>握手可见性</td><td>EHLO/STARTTLS 明文可抓</td><td>第一个包即密文</td></tr>
              <tr><td>适用场景</td><td>MTA 之间 (端口 25)</td><td>MUA → MSA (端口 465)</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </article>
  )
}

/* ====== Topic: D-S Evidence Theory & Multi-Engine Fusion ====== */
export function TopicDSFusion() {
  return (
    <article className="sk-article">
      <div className="sk-article-header">
        <span className="sk-tag sk-tag-red">风险模型</span>
        <h1>D-S 证据理论与多引擎融合</h1>
        <p className="sk-lead">传统贝叶斯方法用单一概率 P(threat) 表示威胁程度，无法区分"确定安全"和"不确定"。D-S 证据理论通过三元组 <code>(b, d, u)</code> 显式建模不确定性，结合 Murphy 修正融合解决多源证据冲突，构成 Vigilyx 风险引擎的数学基础。</p>
      </div>

      <section className="sk-section">
        <h2>为什么需要 D-S 证据理论</h2>
        <p>传统<strong>贝叶斯方法</strong>用单一概率 P(threat) 表达威胁程度。当一个检测模块"无法判断"时，它只能输出 P=0.5 —— 但这与模块<em>明确认为</em>50%概率是威胁<strong>完全不同</strong>：</p>
        <div className="sk-cards-row">
          <div className="sk-info-card">
            <div className="sk-info-card-header bad">问题 1：无法表达不确定</div>
            <ul>
              <li>P(threat) = 0.5 → "模块不确定"？还是"确信50%风险"？</li>
              <li>贝叶斯框架下二者无法区分</li>
              <li>不确定性本身是重要的风险信号</li>
            </ul>
          </div>
          <div className="sk-info-card">
            <div className="sk-info-card-header bad">问题 2：冲突证据处理</div>
            <ul>
              <li>Noisy-OR 假设证据源独立</li>
              <li>两个模块剧烈冲突时简单相乘</li>
              <li>冲突本身可能揭示对抗行为</li>
            </ul>
          </div>
        </div>
        <div className="sk-callout info">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </span>
          <div>
            <strong>D-S 证据理论</strong>引入三值表示 (belief, disbelief, uncertainty)，显式区分"确定性判断"和"不确定状态"，为多源融合提供了理论基础。
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>BPA 三元组：显式不确定性建模</h2>
        <p>在辨识框架 <code>Θ = {'{'}Threat, Normal{'}'}</code> 上定义<strong>基本概率赋值</strong> (Basic Probability Assignment, BPA)，简化为三元组：</p>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>符号</th><th>名称</th><th>含义</th><th>范围</th></tr>
            </thead>
            <tbody>
              <tr><td><code>b</code></td><td>Belief (信度)</td><td>对 Threat 的信任质量</td><td>[0, 1]</td></tr>
              <tr><td><code>d</code></td><td>Disbelief (不信度)</td><td>对 Normal 的信任质量</td><td>[0, 1]</td></tr>
              <tr><td><code>u</code></td><td>Uncertainty (不确定度)</td><td>分配给 Θ 的质量，"看不清"</td><td>[0, 1]</td></tr>
            </tbody>
          </table>
        </div>
        <p><strong>约束条件：</strong><code>b + d + u = 1</code></p>

        <div className="sk-detail-card">
          <div className="sk-detail-card-num">{'→'}</div>
          <div className="sk-detail-card-content">
            <h3>从传统评分转换为 BPA</h3>
            <p>给定模块输出 <code>(score, confidence)</code>：</p>
            <div className="sk-code-block">
              <div className="sk-code-title">BPA 转换公式</div>
              <pre>b = score × confidence{'\n'}d = (1 - score) × confidence{'\n'}u = 1 - confidence</pre>
            </div>
            <p className="sk-note">例：score=0.8, confidence=0.6 → b=0.48, d=0.12, u=0.40（高威胁但不太确定）</p>
          </div>
        </div>

        <div className="sk-detail-card">
          <div className="sk-detail-card-num">{'→'}</div>
          <div className="sk-detail-card-content">
            <h3>风险分数计算</h3>
            <div className="sk-code-block">
              <div className="sk-code-title">Risk Score 公式</div>
              <pre>Risk = b + η × u{'\n'}{'\n'}η ∈ [0, 1] 为风险态度参数{'\n'}η = 0.7 → 将 70% 的不确定性视为威胁{'\n'}η = 0.5 → Pignistic 概率 P_bet(Threat) = b + u/2</pre>
            </div>
            <p className="sk-note"><code>η = 0.7</code> 的直觉：在安全领域，"看不清"比"确认安全"更危险，应该偏向保守</p>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>Dempster 合成规则与 Zadeh 悖论</h2>
        <p>给定两个 BPA <code>m₁</code> 和 <code>m₂</code>，Dempster 合成规则通过<strong>正交和</strong>计算联合信度：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">Dempster 合成规则 (二元框架)</div>
          <pre>冲突因子  K = m₁(T)·m₂(N) + m₁(N)·m₂(T){'\n'}{'\n'}m(T) = [m₁(T)·m₂(T) + m₁(T)·m₂(Θ) + m₁(Θ)·m₂(T)] / (1-K){'\n'}m(N) = [m₁(N)·m₂(N) + m₁(N)·m₂(Θ) + m₁(Θ)·m₂(N)] / (1-K){'\n'}m(Θ) = m₁(Θ)·m₂(Θ) / (1-K)</pre>
        </div>
        <div className="sk-callout warning">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </span>
          <div>
            <strong>Zadeh 悖论：</strong>当两个证据源高度冲突时 (K → 1)，分母趋近于零，合成结果将少量一致证据<em>放大到极端</em>，产生反直觉结论。例如：传感器A说 99% 是 Threat，传感器B说 99% 是 Normal，K = 0.98，合成后产生荒谬结果。<br/><strong>需要在融合前进行冲突预处理 → Murphy 修正。</strong>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>Murphy 修正融合算法</h2>
        <p>Murphy 修正通过<strong>证据距离加权平均</strong>预处理解决 Zadeh 悖论：</p>
        <div className="sk-cards-col">
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">1</div>
            <div className="sk-detail-card-content">
              <h3>Jousselme 证据距离</h3>
              <p>度量两个 BPA 之间的差异程度：</p>
              <div className="sk-code-block">
                <div className="sk-code-title">Jousselme 距离公式</div>
                <pre>d_J(m₁, m₂) = √(0.5 · (m₁-m₂)ᵀ · D · (m₁-m₂)){'\n'}{'\n'}D 矩阵基于焦元的 Jaccard 相似度：{'\n'}D(A,B) = |A ∩ B| / |A ∪ B|{'\n'}{'\n'}对二元框架 Θ={'{'}T,N{'}'}，D 为 3×3 矩阵：{'\n'}     T    N    Θ{'\n'}T  [1.0  0.0  0.5]{'\n'}N  [0.0  1.0  0.5]{'\n'}Θ  [0.5  0.5  1.0]</pre>
              </div>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">2</div>
            <div className="sk-detail-card-content">
              <h3>相似度与可信度权重</h3>
              <div className="sk-code-block">
                <div className="sk-code-title">可信度计算</div>
                <pre>相似度:   sim(i,j) = 1 - d_J(m_i, m_j){'\n'}可信度:   crd(i) = Σⱼ≠ᵢ sim(i,j){'\n'}归一化:   w_i = crd(i) / Σ crd(j)</pre>
              </div>
              <p className="sk-note">与多数证据一致的源获得更高权重，异常值被自动降权</p>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">3</div>
            <div className="sk-detail-card-content">
              <h3>加权平均 + 自合成</h3>
              <div className="sk-code-block">
                <div className="sk-code-title">Murphy 融合流程</div>
                <pre>加权平均: m_avg = Σ w_i · m_i{'\n'}{'\n'}自合成:   m_final = m_avg ⊕ m_avg ⊕ ... (共 N-1 次){'\n'}          N = 引擎数量{'\n'}{'\n'}多次自合成的作用: 增强证据收敛性，{'\n'}使一致的证据进一步强化，矛盾的证据相互抵消</pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>Copula 依赖校正</h2>
        <p>Dempster 合成规则假设证据源之间<strong>相互独立</strong>。但实际系统中引擎间存在特征共享：</p>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>引擎对</th><th>共享特征</th><th>相关系数 ρ</th></tr>
            </thead>
            <tbody>
              <tr><td>B (内容) ↔ F (语义)</td><td>共享邮件文本</td><td>0.30</td></tr>
              <tr><td>D (URL) ↔ B (内容)</td><td>共享钓鱼 URL</td><td>0.20</td></tr>
              <tr><td>其余引擎对</td><td>弱依赖</td><td>≤ 0.15</td></tr>
            </tbody>
          </table>
        </div>
        <div className="sk-code-block">
          <div className="sk-code-title">Copula 折扣公式</div>
          <pre>对相关系数 ρ_ij 较高的引擎对：{'\n'}{'\n'}b_new = b × (1 - ρ)     // 信度打折{'\n'}u_new = u + (b + d) × ρ // 不确定度增加{'\n'}{'\n'}直觉: 相关的引擎给出的证据要打折扣，{'\n'}      因为它们不是真正独立的信息源</pre>
        </div>
      </section>

      <section className="sk-section">
        <h2>八引擎架构设计</h2>
        <p>系统采用八个互补引擎覆盖邮件威胁的不同维度，确保无单一盲区：</p>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>引擎</th><th>名称</th><th>核心能力</th><th>覆盖威胁</th></tr>
            </thead>
            <tbody>
              <tr><td><strong>A</strong></td><td>发件人信誉</td><td>SPF/DKIM 验证、域名信誉、发送历史</td><td>伪造发件人</td></tr>
              <tr><td><strong>B</strong></td><td>内容分析</td><td>JS 散度、紧迫性语义、附件风险、HTML 结构</td><td>钓鱼内容</td></tr>
              <tr><td><strong>C</strong></td><td>行为基线</td><td>GMM 建模正常行为、孤立森林检测偏离</td><td>ATO/账户异常</td></tr>
              <tr><td><strong>D</strong></td><td>URL 分析</td><td>链接信誉、重定向链、QR码、LOTS 检测</td><td>恶意链接</td></tr>
              <tr><td><strong>E</strong></td><td>协议合规</td><td>邮件头完整性、MIME 结构、Received 链路</td><td>协议滥用</td></tr>
              <tr><td><strong>F</strong></td><td>语义意图</td><td>LLM/规则分析业务意图（付款、凭据索取）</td><td>BEC/社工</td></tr>
              <tr><td><strong>G</strong></td><td>身份异常</td><td>首次通信、模式突变、回复链异常、指纹变化</td><td>ATO/冒充</td></tr>
              <tr><td><strong>H</strong></td><td>交易关联</td><td>银行账号/金额提取、操作合理性验证</td><td>BEC/欺诈</td></tr>
            </tbody>
          </table>
        </div>
        <div className="sk-code-block">
          <div className="sk-code-title">最终风险分数</div>
          <pre>Risk_single = b_final + η × u_final{'\n'}{'\n'}其中 b_final, u_final 来自八引擎 Murphy 融合后的 BPA{'\n'}η = 0.7 (风险态度参数)</pre>
        </div>
      </section>

      <section className="sk-section">
        <h2>对抗鲁棒性约束</h2>
        <p>攻击者可能针对性地规避某个引擎。<strong>多样性约束</strong>确保系统不过度依赖任何单一引擎：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">多样性约束</div>
          <pre>约束: w_i ≤ 0.4 × Σw_j{'\n'}{'\n'}任何单引擎权重不超过总权重的 40%{'\n'}超出部分按比例重新分配给其余引擎</pre>
        </div>
        <div className="sk-callout info">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </span>
          <div>
            <strong>降级分析：</strong>模拟移除每个引擎后的最差情况检测率，确保去掉任何一个引擎后系统仍能有效检测。这意味着即使攻击者完美规避了一个维度的检测，其余引擎仍能以 ≥60% 的独立检出率覆盖威胁。
          </div>
        </div>
      </section>
    </article>
  )
}

/* ====== Topic: Temporal Analysis & EVT Alert ====== */
export function TopicTemporalEVT() {
  return (
    <article className="sk-article">
      <div className="sk-article-header">
        <span className="sk-tag sk-tag-red">风险模型</span>
        <h1>时序分析与尾部风险告警</h1>
        <p className="sk-lead">单封邮件的安全分析无法捕捉跨时间窗口的渐进攻击模式。时序分析层运行在单邮件判定之后，通过 CUSUM 变点检测、双速 EWMA 基线漂移、HMM 攻击阶段推断和通信图谱异常检测，识别"温水煮青蛙"式的高级威胁。</p>
      </div>

      <section className="sk-section">
        <h2>时序分析层的定位</h2>
        <p>旁路监测系统的独特优势在于可以观察到<strong>所有邮件流量的完整时间序列</strong>。</p>
        <div className="sk-compare">
          <div className="sk-compare-col">
            <div className="sk-compare-header amber">单邮件分析</div>
            <div className="sk-compare-body">
              <p>"这封邮件是否危险？"</p>
              <code>Risk = f(content, sender, url, ...)</code>
            </div>
          </div>
          <div className="sk-compare-vs">VS</div>
          <div className="sk-compare-col">
            <div className="sk-compare-header green">时序分析层</div>
            <div className="sk-compare-body">
              <p>"这个发件人的行为是否在逐渐变化？"</p>
              <code>Risk = g(r₁, r₂, ..., rₜ, Δt, graph)</code>
            </div>
          </div>
        </div>
        <div className="sk-callout warning">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </span>
          <div>
            <strong>BEC 和 ATO 攻击的典型模式：</strong>攻击者先建立信任再实施攻击。每一封邮件单独看可能风险不高，但时间维度上的模式揭示真实意图。时序分析在单邮件判定 (verdict) 产出后<em>异步运行</em>，不阻塞下一封邮件处理。
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>CUSUM 累积和变点检测</h2>
        <p><strong>CUSUM</strong> (Cumulative Sum) 是经典的序列变点检测算法，用于检测发件人风险水平的<em>突然偏移</em>：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">CUSUM 递推公式</div>
          <pre>S⁺(t) = max(0, S⁺(t-1) + r(t) - μ₀ - k){'\n'}{'\n'}r(t)  = 第 t 封邮件的风险分数{'\n'}μ₀    = 发件人历史正常风险均值{'\n'}k     = 容许偏差 (allowance)，取 0.5σ{'\n'}h     = 报警阈值，取 4σ{'\n'}{'\n'}报警条件: S⁺(t) {'>'} h</pre>
        </div>
        <div className="sk-callout info">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </span>
          <div>
            <strong>直觉解释：</strong>CUSUM 在每一步累积风险偏离正常水平的量。如果偏离是随机波动，<code>max(0, ...)</code> 会将累积和重置为零。只有<em>持续偏高</em>的风险才会使 S⁺ 不断累积并突破阈值。<code>k</code> 控制灵敏度（k 越小越灵敏），<code>h</code> 控制误报率（h 越大误报越少）。
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>双速 EWMA 基线漂移检测</h2>
        <p><strong>指数加权移动平均</strong> (EWMA) 用两个不同速度追踪发件人的行为基线：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">双速 EWMA 公式</div>
          <pre>快速 EWMA:  E_fast(t) = α_f × r(t) + (1-α_f) × E_fast(t-1){'\n'}            α_f = 0.05  (~20 封邮件记忆窗口){'\n'}{'\n'}慢速 EWMA:  E_slow(t) = α_s × r(t) + (1-α_s) × E_slow(t-1){'\n'}            α_s = 0.005 (~200 封邮件记忆窗口){'\n'}{'\n'}漂移分数:   drift = |E_fast - E_slow| / max(E_slow, ε)</pre>
        </div>
        <p>当快速基线显著偏离慢速基线时，说明发件人的行为正在发生变化：</p>
        <div className="sk-diagram">
          <div className="sk-diagram-row">
            <span className="sk-diagram-label">正常</span>
            <div className="sk-diagram-flow">
              <code>E_fast ≈ E_slow</code>
              <span className="sk-arrow good">→ drift ≈ 0</span>
            </div>
            <span className="sk-badge-inline good">稳定</span>
          </div>
          <div className="sk-diagram-row">
            <span className="sk-diagram-label">渐变</span>
            <div className="sk-diagram-flow">
              <code>E_fast {'>'} E_slow</code>
              <span className="sk-arrow bad">→ drift ↑</span>
            </div>
            <span className="sk-badge-inline bad">漂移</span>
          </div>
        </div>
        <div className="sk-callout warning">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </span>
          <div>
            <strong>"温水煮青蛙"的数学指纹：</strong>如果攻击者每天只略微提高风险，单日的变化不会触发 CUSUM，但快慢 EWMA 的分离会逐渐加大，漂移分数升高即可报警。
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>实体风险累积模型</h2>
        <p>为每个发件人和域名维护一个<strong>持续衰减的风险累积值</strong>：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">实体风险递推公式</div>
          <pre>R_entity(t) = α × R_entity(t-1) + (1-α) × r_new{'\n'}{'\n'}α = 0.92 (衰减因子){'\n'}{'\n'}每封新邮件的风险以 8% 的权重融入历史{'\n'}同时历史风险以 92% 的速度衰减{'\n'}{'\n'}观察名单阈值: R_entity {'>'} 0.3 → 列入持续监控</pre>
        </div>
        <p className="sk-note">衰减机制确保良性实体不会因为偶尔一封误报而永久受影响。被监控的实体其后续邮件在时序分析中获得额外风险加成。</p>
      </section>

      <section className="sk-section">
        <h2>HMM 五状态攻击阶段推断</h2>
        <p><strong>隐马尔可夫模型</strong> (Hidden Markov Model) 用于推断发件人-收件人对之间的攻击阶段演进：</p>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>状态</th><th>阶段</th><th>特征</th><th>风险权重 w</th></tr>
            </thead>
            <tbody>
              <tr><td><strong>S0</strong></td><td>正常通信</td><td>低风险、低冲突、稳定频率</td><td>0.0</td></tr>
              <tr><td><strong>S1</strong></td><td>侦察阶段</td><td>探测性邮件、试探边界</td><td>0.3</td></tr>
              <tr><td><strong>S2</strong></td><td>信任建立</td><td>频率增加、内容趋同</td><td>0.5</td></tr>
              <tr><td><strong>S3</strong></td><td>攻击实施</td><td>高风险操作、紧迫语气</td><td>1.0</td></tr>
              <tr><td><strong>S4</strong></td><td>收割获利</td><td>敏感数据索取、资金转移</td><td>1.0</td></tr>
            </tbody>
          </table>
        </div>
        <div className="sk-code-block">
          <div className="sk-code-title">前向算法在线推断</div>
          <pre>观测向量: O = (risk_single, u_final, K_conflict, Δt, Δcontent){'\n'}{'\n'}前向变量: α_t(s) = [Σ α_{'{'}t-1{'}'}(s{'\''}) · A(s{'\''}, s)] · P(O_t | s){'\n'}{'\n'}后验概率: γ_t(s) = α_t(s) / Σ α_t(s{'\''})  (归一化){'\n'}{'\n'}时序风险: Risk_temporal = Σ γ_t(s) × w_s{'\n'}         w = {'{'} 0.0, 0.3, 0.5, 1.0, 1.0 {'}'}</pre>
        </div>
        <p className="sk-note">每个 sender-recipient 对维护独立的 HMM 实例。转移矩阵反映攻击典型进程：正常状态自转移概率最高 (0.97)，攻击各阶段依次升级。</p>
      </section>

      <section className="sk-section">
        <h2>通信图谱异常检测</h2>
        <p>维护一个<strong>有向加权图</strong>：节点=邮箱地址，边=通信记录（含频率和风险历史）。检测三种异常模式：</p>
        <div className="sk-cards-col">
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">1</div>
            <div className="sk-detail-card-content">
              <h3>新发件人群发 (Mass Phishing)</h3>
              <p>一个首次出现的发件人短时间内向大量收件人发送邮件。</p>
              <div className="sk-code-block">
                <div className="sk-code-title">检测条件</div>
                <pre>sender_email_count {'<'} threshold (新发件人){'\n'}AND sender_out_degree {'>'} threshold (高出度)</pre>
              </div>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">2</div>
            <div className="sk-detail-card-content">
              <h3>已知发件人新增高风险边 (BEC Lateral)</h3>
              <p>一个历史正常的发件人突然向<em>新收件人</em>发送高风险邮件，疑似 BEC 横向移动。</p>
              <div className="sk-code-block">
                <div className="sk-code-title">检测条件</div>
                <pre>sender_email_count {'>'} threshold (已知发件人){'\n'}AND new_edge = true AND risk {'>'} 0.5</pre>
              </div>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">3</div>
            <div className="sk-detail-card-content">
              <h3>出度突增 (Exfiltration Burst)</h3>
              <p>已有发件人的唯一收件人数突然爆增，可能是数据外泄或账户被盗。</p>
              <div className="sk-code-block">
                <div className="sk-code-title">检测条件</div>
                <pre>new_out_degree / old_out_degree {'>'} burst_ratio</pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>GPD 极值理论与尾部风险</h2>
        <p><strong>广义帕累托分布</strong> (Generalized Pareto Distribution) 用于建模风险分数的极端尾部行为：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">GPD 超额分布</div>
          <pre>P(X {'>'} x | X {'>'} u) = (1 + ξ(x-u)/σ)^{'{-1/ξ}'}{'\n'}{'\n'}u = 历史风险分数的 95 分位数 (阈值){'\n'}ξ = 形状参数 (ξ{'>'}0 为重尾 Fréchet 分布){'\n'}σ = 尺度参数 (尾部展宽程度){'\n'}{'\n'}参数通过 PWM (概率加权矩) 方法拟合</pre>
        </div>
        <div className="sk-code-block">
          <div className="sk-code-title">重现期与 CVaR</div>
          <pre>VaR_T = u + (σ/ξ) × [(n/N_u × T)^ξ - 1]{'\n'}{'\n'}CVaR = VaR_T × (1 + (σ - ξ×u) / ((1-ξ) × VaR_T)){'\n'}{'\n'}T {'>'} 10000 → "万封邮件一遇"的极端风险</pre>
        </div>
        <div className="sk-callout info">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </span>
          <div>
            <strong>EVT 的核心价值：</strong>传统固定阈值告警无法适应不同流量特征。EVT 从实际数据分布出发，<em>自动确定</em>什么样的风险分数在当前环境下是"异常的"。高重现期 T 意味着该风险水平在正常流量中极为罕见。
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>P0-P3 动态告警分级</h2>
        <p>基于<strong>期望损失</strong>和多维信号的四级告警体系：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">期望损失公式</div>
          <pre>EL = Risk_final × Impact_target{'\n'}{'\n'}Impact 权重 (按收件人角色):{'\n'}  高管: 5.0 | 财务: 4.5 | IT管理: 4.0{'\n'}  客户经理: 3.5 | 一般员工: 1.0</pre>
        </div>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>级别</th><th>触发条件</th><th>响应要求</th></tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>P0</strong></td>
                <td>EL ≥ 3.0，或 K_conflict {'>'} 0.7，或 CUSUM+HMM 同时触发，或 EVT T ≥ 10000</td>
                <td>立即响应</td>
              </tr>
              <tr>
                <td><strong>P1</strong></td>
                <td>EL ∈ [1.5, 3.0)，或 K_conflict {'>'} 0.6，或 EVT T ∈ [1000, 10000)</td>
                <td>优先处理</td>
              </tr>
              <tr>
                <td><strong>P2</strong></td>
                <td>EL ∈ [0.5, 1.5)，或 u_final {'>'} 0.6，或 CUSUM 单独报警</td>
                <td>关注跟踪</td>
              </tr>
              <tr>
                <td><strong>P3</strong></td>
                <td>Risk_final ≥ 0.15</td>
                <td>记录备查</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div className="sk-callout info">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </span>
          <div>
            告警级别从高到低取<strong>最严格级别</strong>。当多个条件同时满足时，取 P 值最小（最严重）的级别。每个告警记录包含判定依据 (rationale) 和关联的 verdict 信息，支持分析人员快速定位和确认。
          </div>
        </div>
      </section>
    </article>
  )
}

/* ====== Topic: Module Pipeline & D-S Integration ====== */
export function TopicModulePipeline() {
  return (
    <article className="sk-article">
      <div className="sk-article-header">
        <span className="sk-tag sk-tag-red">风险模型</span>
        <h1>安全模块管线与融合实现</h1>
        <p className="sk-lead">Vigilyx 的安全分析管线由 <strong>14 个专业模块</strong>组成，通过 DAG 并行编排执行，每个模块输出 <code>(score, confidence)</code> 评分对。这些评分通过 BPA 转换进入八引擎 D-S Murphy 融合管线，最终产生统一的风险判定。</p>
      </div>

      <section className="sk-section">
        <h2>模块系统架构</h2>
        <p>每个安全模块实现 <code>SecurityModule</code> trait，包含三个核心方法：</p>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>方法</th><th>作用</th><th>返回值</th></tr>
            </thead>
            <tbody>
              <tr><td><code>metadata()</code></td><td>声明模块 ID、名称、所属支柱、依赖列表、超时时间</td><td><code>ModuleMetadata</code></td></tr>
              <tr><td><code>analyze(ctx)</code></td><td>执行安全分析逻辑</td><td><code>ModuleResult</code></td></tr>
              <tr><td><code>should_run(ctx)</code></td><td>前置过滤器，决定是否执行（可选）</td><td><code>bool</code></td></tr>
            </tbody>
          </table>
        </div>
        <p><strong>SecurityContext</strong> 上下文包含：</p>
        <ul>
          <li><code>session</code> — 完整的邮件会话数据（邮件头、正文、附件、链接、SMTP 对话）</li>
          <li><code>results</code> — 已完成模块的结果缓存，允许后续模块引用前序输出</li>
        </ul>
        <p><strong>ModuleResult</strong> 是所有模块统一的输出结构：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">ModuleResult 核心字段</div>
          <pre>module_id:    &quot;content_scan&quot;       // 模块标识{'\n'}threat_level: ThreatLevel::Medium  // 威胁等级{'\n'}confidence:   0.85                 // 置信度 ∈ [0, 1]{'\n'}categories:   [&quot;phishing&quot;, &quot;bec&quot;]  // 威胁分类标签{'\n'}summary:      &quot;发现 3 个钓鱼关键词&quot;  // 人类可读摘要{'\n'}evidence:     [...]                // 详细证据（位置 + 说明）{'\n'}details.score: 0.70                // 原始风险评分 ∈ [0, 1]{'\n'}bpa:          Option&lt;Bpa&gt;          // D-S 三元组（可选）{'\n'}engine_id:    Option&lt;&quot;B&quot;&gt;          // 所属引擎（可选）</pre>
        </div>
      </section>

      <section className="sk-section">
        <h2>十四个安全模块</h2>
        <p>模块按八引擎架构分组，覆盖邮件威胁的不同维度：</p>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>引擎</th><th>模块 ID</th><th>名称</th><th>检测能力</th></tr>
            </thead>
            <tbody>
              <tr><td rowSpan={1}><strong>A</strong></td><td><code>domain_verify</code></td><td>域名验证</td><td>发件域 vs Received/DKIM/链接域一致性，输出 trust_score</td></tr>
              <tr><td rowSpan={5}><strong>B</strong></td><td><code>content_scan</code></td><td>内容扫描</td><td>钓鱼关键词 (强:+0.08, 弱:+0.03)、BEC 话术 (+0.15)、DLP 敏感信息、外部冒充 (+0.40)</td></tr>
              <tr><td><code>html_scan</code></td><td>HTML 检测</td><td>隐藏文本、混淆标签、可疑表单、data URI</td></tr>
              <tr><td><code>attach_scan</code></td><td>附件元数据</td><td>危险扩展名、双扩展名、伪装 .exe</td></tr>
              <tr><td><code>attach_content</code></td><td>附件内容</td><td>嵌入宏、脚本、PE 头、ZIP 炸弹</td></tr>
              <tr><td><code>attach_hash</code></td><td>附件哈希</td><td>SHA256 与 IOC 黑名单匹配</td></tr>
              <tr><td rowSpan={1}><strong>C</strong></td><td><code>anomaly_detect</code></td><td>行为异常</td><td>群发 ({'>'}10 收件人)、空标题+附件、全大写标题、spam cannon ({'>'}50 rcpt)</td></tr>
              <tr><td rowSpan={3}><strong>D</strong></td><td><code>link_scan</code></td><td>链接模式</td><td>IP 地址 URL (+0.25)、data/javascript URI (+0.30)、href/文本不匹配 (+0.30)、短链接</td></tr>
              <tr><td><code>link_reputation</code></td><td>链接信誉</td><td>VirusTotal / URLhaus / PhishTank 查询</td></tr>
              <tr><td><code>link_content</code></td><td>着陆页分析</td><td>实时抓取 URL 目标页面，分析内容风险</td></tr>
              <tr><td rowSpan={2}><strong>E</strong></td><td><code>header_scan</code></td><td>邮件头验证</td><td>缺失 Date/Message-ID、SPF/DKIM/DMARC 失败、Received 链异常</td></tr>
              <tr><td><code>mime_scan</code></td><td>MIME 结构</td><td>畸形 multipart、boundary 违规、编码错误、嵌套深度滥用</td></tr>
              <tr><td rowSpan={1}><strong>F</strong></td><td><code>semantic_scan</code></td><td>语义检测</td><td>CJK 罕用字符率、Shannon 熵异常、Bigram 唯一性 (无语义乱码检测)</td></tr>
            </tbody>
          </table>
        </div>
        <div className="sk-callout info">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </span>
          <div>
            <strong>引擎 G (身份异常) 和 H (交易关联)</strong> 为预留引擎，将在后续版本中实现 IAM 行为关联和业务语义分析。当前这两个引擎不参与融合计算 (输出 vacuous BPA: u=1)。
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>管线编排器：DAG 并行分层执行</h2>
        <p>编排器使用 <strong>Kahn 拓扑排序</strong>将模块依赖关系构建为有向无环图 (DAG)，然后分层执行：</p>
        <div className="sk-flow">
          <div className="sk-flow-node">
            <div className="sk-flow-icon mta">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><polyline points="2,5 12,13 22,5"/></svg>
            </div>
            <div className="sk-flow-label">邮件输入</div>
            <div className="sk-flow-sub">EmailSession</div>
          </div>
          <div className="sk-flow-arrow">
            <span>ctx</span>
          </div>
          <div className="sk-flow-node">
            <div className="sk-flow-icon relay">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>
            </div>
            <div className="sk-flow-label">Layer 0</div>
            <div className="sk-flow-sub">~12 模块并行</div>
          </div>
          <div className="sk-flow-arrow">
            <span>results</span>
          </div>
          <div className="sk-flow-node">
            <div className="sk-flow-icon mta">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
            </div>
            <div className="sk-flow-label">D-S 融合</div>
            <div className="sk-flow-sub">八引擎 Murphy</div>
          </div>
          <div className="sk-flow-arrow">
            <span>verdict</span>
          </div>
          <div className="sk-flow-node">
            <div className="sk-flow-icon sender">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <div className="sk-flow-label">判定输出</div>
            <div className="sk-flow-sub">Risk + ThreatLevel</div>
          </div>
        </div>

        <div className="sk-cards-row">
          <div className="sk-info-card">
            <div className="sk-info-card-header good">并行执行特性</div>
            <ul>
              <li>同一层模块通过 <code>tokio::join_all</code> 并行执行</li>
              <li>典型场景: Layer 0 中 ~12 个模块同时运行</li>
              <li>层间串行，确保前层结果对后层可用</li>
            </ul>
          </div>
          <div className="sk-info-card">
            <div className="sk-info-card-header bad">容错机制</div>
            <ul>
              <li>每个模块独立超时 (默认 3-5s)</li>
              <li>超时返回 <code>Safe</code> + 错误摘要</li>
              <li>单模块失败不影响其他模块继续</li>
              <li><code>should_run()</code> 跳过不适用模块</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>从评分到三元组：模块输出转换</h2>
        <p>每个模块输出 <code>score</code> (风险评分) 和 <code>confidence</code> (置信度)。融合管线将其转换为 D-S 三元组 <code>(b, d, u)</code>：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">BPA 转换公式</div>
          <pre>b = score × confidence      // Threat 信度{'\n'}d = (1 - score) × confidence // Normal 信度{'\n'}u = 1 - confidence           // 不确定度</pre>
        </div>
        <p>三个典型场景展示 D-S 框架的核心价值：</p>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>场景</th><th>模块</th><th>score</th><th>conf</th><th>b</th><th>d</th><th>u</th><th>解读</th></tr>
            </thead>
            <tbody>
              <tr>
                <td>高危确认</td>
                <td>content_scan</td>
                <td>0.70</td><td>0.85</td>
                <td><strong>0.595</strong></td><td>0.255</td><td>0.150</td>
                <td>高信度高风险，证据充分</td>
              </tr>
              <tr>
                <td>安全确认</td>
                <td>domain_verify</td>
                <td>0.10</td><td>0.90</td>
                <td>0.090</td><td><strong>0.810</strong></td><td>0.100</td>
                <td>高信度低风险，域名可信</td>
              </tr>
              <tr>
                <td>无法判断</td>
                <td>semantic_scan</td>
                <td>0.30</td><td>0.20</td>
                <td>0.060</td><td>0.140</td><td><strong>0.800</strong></td>
                <td>低信度，基本没有有效信息</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div className="sk-callout warning">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </span>
          <div>
            <strong>第三个场景的关键价值：</strong>传统系统中 score=0.30 被视为低风险可忽略。但 D-S 框架下 <code>u=0.80</code> 意味着该模块基本没有有效信息 —— 它<em>不应影响最终判定</em>，由其他引擎主导。这正是"不确定性"与"低风险"的本质区别。
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>八引擎映射与引擎内合成</h2>
        <p>14 个模块按功能映射到 8 个概念引擎。对于<strong>多模块引擎</strong>（如 B 有 5 个模块、D 有 3 个），需要先在引擎内部通过 Dempster 合成规则逐步合成：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">引擎 B 内部合成（5 个模块）</div>
          <pre>m_content   = BPA(content_scan){'\n'}m_html      = BPA(html_scan){'\n'}m_attach    = BPA(attach_scan){'\n'}m_acontent  = BPA(attach_content){'\n'}m_ahash     = BPA(attach_hash){'\n'}{'\n'}m_B = m_content ⊕ m_html ⊕ m_attach ⊕ m_acontent ⊕ m_ahash{'\n'}{'\n'}// ⊕ 为 Dempster 合成规则{'\n'}// 如果 K → 1 (子模块严重冲突), 退回 vacuous BPA</pre>
        </div>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>引擎</th><th>包含模块</th><th>模块数</th><th>合成方式</th></tr>
            </thead>
            <tbody>
              <tr><td><strong>A</strong></td><td>domain_verify</td><td>1</td><td>直接使用</td></tr>
              <tr><td><strong>B</strong></td><td>content + html + attach×3</td><td>5</td><td>逐步 Dempster 合成</td></tr>
              <tr><td><strong>C</strong></td><td>anomaly_detect</td><td>1</td><td>直接使用</td></tr>
              <tr><td><strong>D</strong></td><td>link_scan + reputation + content</td><td>3</td><td>逐步 Dempster 合成</td></tr>
              <tr><td><strong>E</strong></td><td>header_scan + mime_scan</td><td>2</td><td>一次 Dempster 合成</td></tr>
              <tr><td><strong>F</strong></td><td>semantic_scan</td><td>1</td><td>直接使用</td></tr>
            </tbody>
          </table>
        </div>
        <p className="sk-note">引擎内合成后，每个引擎只输出一个 BPA，接下来进入跨引擎 Murphy 融合。</p>
      </section>

      <section className="sk-section">
        <h2>Copula 折扣与 Murphy 融合全流程</h2>
        <p>引擎内合成完成后，进入<strong>跨引擎 Murphy 融合管线</strong>，共 6 步：</p>
        <div className="sk-cards-col">
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">1</div>
            <div className="sk-detail-card-content">
              <h3>Copula 依赖折扣</h3>
              <p>对每个引擎，找到与之最相关引擎的相关系数 <code>max_ρ</code>。如果 <code>max_ρ {'>'} 0.1</code>，对其 BPA 进行折扣：</p>
              <div className="sk-code-block">
                <div className="sk-code-title">折扣公式 (discount factor α = 1 - max_ρ)</div>
                <pre>b{'\''} = b × α{'\n'}d{'\''} = d × α{'\n'}u{'\''} = 1 - b{'\''} - d{'\''}{'\n'}{'\n'}例: 引擎B 与引擎F 相关 ρ=0.30{'\n'}    b=0.6 → b{'\''} = 0.6 × 0.7 = 0.42{'\n'}    (1-α)=0.30 的质量转移到不确定性</pre>
              </div>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">2</div>
            <div className="sk-detail-card-content">
              <h3>Jousselme 证据距离矩阵</h3>
              <p>计算每对引擎 BPA 之间的距离，上三角优化 (O(N²/2))：</p>
              <div className="sk-code-block">
                <div className="sk-code-title">Jousselme 距离</div>
                <pre>d_J(m₁, m₂) = √[½ · (Δb² + Δd² + Δu² + Δb·Δu + Δd·Δu)]</pre>
              </div>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">3</div>
            <div className="sk-detail-card-content">
              <h3>可信度权重</h3>
              <div className="sk-code-block">
                <div className="sk-code-title">Murphy 权重计算</div>
                <pre>sim(i,j)  = 1 - d_J(m_i, m_j){'\n'}support_i = Σⱼ≠ᵢ sim(i,j)   // 与其他引擎的一致性{'\n'}w_i       = support_i / Σ support</pre>
              </div>
              <p className="sk-note">与多数引擎一致的获得更高权重，异常值被自动降权</p>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">4</div>
            <div className="sk-detail-card-content">
              <h3>多样性约束 (对抗鲁棒性)</h3>
              <div className="sk-code-block">
                <div className="sk-code-title">权重裁剪</div>
                <pre>约束: w_i ≤ 0.4 × Σw_j{'\n'}超出部分按比例重分配给未触顶的引擎{'\n'}重新归一化使 Σw_i = 1.0</pre>
              </div>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">5</div>
            <div className="sk-detail-card-content">
              <h3>加权平均</h3>
              <div className="sk-code-block">
                <div className="sk-code-title">Murphy 加权平均</div>
                <pre>m̄.b = Σ w_i × m_i.b{'\n'}m̄.d = Σ w_i × m_i.d{'\n'}m̄.u = Σ w_i × m_i.u</pre>
              </div>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">6</div>
            <div className="sk-detail-card-content">
              <h3>自合成 N-1 次</h3>
              <div className="sk-code-block">
                <div className="sk-code-title">Dempster 自合成</div>
                <pre>m_final = m̄ ⊕ m̄ ⊕ ... (共 N-1 次, N=活跃引擎数){'\n'}{'\n'}多次自合成增强证据收敛: 一致的证据被放大，{'\n'}矛盾的证据相互抵消，不确定性被逐步消解</pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>信任信号折扣机制</h2>
        <p><code>domain_verify</code> 模块输出的 <code>trust_score</code> 作为特殊的信任信号，<strong>独立于 D-S 融合管线</strong>：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">信任折扣公式</div>
          <pre>final_score = risk_score × (1 - trust_score × 0.4){'\n'}{'\n'}trust_score 范围 [0, 1]:{'\n'}  1.0 = SPF pass + DKIM valid + 域名完全一致{'\n'}  0.0 = 全部验证失败{'\n'}{'\n'}折扣上限: 40%{'\n'}即使完全可信也只能降低 40% 的风险</pre>
        </div>
        <div className="sk-diagram">
          <div className="sk-diagram-row">
            <span className="sk-diagram-label">折扣前</span>
            <div className="sk-diagram-flow">
              <code>risk=0.60, trust=1.0</code>
            </div>
            <span className="sk-badge-inline bad">Medium</span>
          </div>
          <div className="sk-diagram-row">
            <span className="sk-diagram-label">折扣后</span>
            <div className="sk-diagram-flow">
              <code>0.60 × (1 - 1.0×0.4) = 0.36</code>
            </div>
            <span className="sk-badge-inline good">Low</span>
          </div>
        </div>
        <div className="sk-callout info">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </span>
          <div>
            <strong>直觉：</strong>如果发件人身份完全可信（SPF/DKIM 都通过、域名未伪造），那么内容层面的风险需要打折。但折扣有上限 —— 确保真正高风险的内容（如 risk=0.90）即使发件人可信，仍能触发 <code>0.90 × 0.60 = 0.54</code> 的中危告警。
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>最终判定：风险分数与威胁等级</h2>
        <p>经过 D-S Murphy 融合和信任折扣后，最终风险分数映射到五级威胁等级：</p>
        <div className="sk-code-block">
          <div className="sk-code-title">最终风险计算</div>
          <pre>Risk_single = b_final + η × u_final  (η = 0.7)</pre>
        </div>
        <div className="sk-table-wrap">
          <table className="sk-table">
            <thead>
              <tr><th>等级</th><th>阈值</th><th>含义</th></tr>
            </thead>
            <tbody>
              <tr><td><strong>Critical</strong></td><td>risk ≥ 0.85</td><td>确认的高危攻击，多引擎强共识</td></tr>
              <tr><td><strong>High</strong></td><td>risk ≥ 0.65</td><td>多引擎交叉确认的威胁</td></tr>
              <tr><td><strong>Medium</strong></td><td>risk ≥ 0.40</td><td>部分引擎标记，需人工复核</td></tr>
              <tr><td><strong>Low</strong></td><td>risk ≥ 0.15</td><td>轻微可疑但不足以告警</td></tr>
              <tr><td><strong>Safe</strong></td><td>risk {'<'} 0.15</td><td>正常邮件</td></tr>
            </tbody>
          </table>
        </div>
        <p><strong>完整的端到端流程：</strong></p>
        <ol className="sk-steps">
          <li><strong>并行分析</strong><span>14 个模块通过 DAG 编排并行执行，各输出 (score, confidence)</span></li>
          <li><strong>BPA 转换</strong><span>每个模块的 (score, confidence) 转换为三元组 (b, d, u)</span></li>
          <li><strong>引擎映射</strong><span>按八引擎架构分组 → 引擎内 Dempster 合成</span></li>
          <li><strong>Murphy 融合</strong><span>Copula 折扣 → Jousselme 距离 → 可信度权重 → 多样性约束 → 加权平均 → 自合成</span></li>
          <li><strong>风险判定</strong><span>Risk = b + ηu → 信任折扣 → ThreatLevel 映射 → DB 写入 + WebSocket 广播</span></li>
        </ol>
      </section>
    </article>
  )
}

/* ====== Topic: SPF/DKIM/DMARC ====== */
export function TopicSPF() {
  return (
    <article className="sk-article">
      <div className="sk-article-header">
        <span className="sk-tag sk-tag-cyan">认证</span>
        <h1>SPF / DKIM / DMARC</h1>
        <p className="sk-lead">这三种机制共同解决一个问题：<strong>这封邮件真的是它声称的发件人发送的吗？</strong></p>
      </div>

      <section className="sk-section">
        <h2>三者关系</h2>
        <div className="sk-cards-col">
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">1</div>
            <div className="sk-detail-card-content">
              <h3>SPF (Sender Policy Framework)</h3>
              <p>在 DNS 中声明"哪些 IP 有权代表我的域名发送邮件"。收件 MTA 检查发件 IP 是否在授权列表中。</p>
              <div className="sk-code-block">
                <div className="sk-code-title">DNS TXT 记录</div>
                <pre>example.com. IN TXT "v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all"</pre>
              </div>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">2</div>
            <div className="sk-detail-card-content">
              <h3>DKIM (DomainKeys Identified Mail)</h3>
              <p>发件 MTA 使用私钥对邮件头和正文签名，收件方通过 DNS 获取公钥验证。可确保邮件在传输中未被篡改。</p>
              <div className="sk-code-block">
                <div className="sk-code-title">邮件头中的 DKIM 签名</div>
                <pre>DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1;{'\n'}  h=from:to:subject:date; bh=abc123...; b=xyz789...</pre>
              </div>
            </div>
          </div>
          <div className="sk-detail-card">
            <div className="sk-detail-card-num">3</div>
            <div className="sk-detail-card-content">
              <h3>DMARC (Domain-based Message Authentication)</h3>
              <p>基于 SPF 和 DKIM 的策略层。域名所有者声明"如果 SPF 和 DKIM 都未通过，应该如何处理 (放行/隔离/拒绝)"。</p>
              <div className="sk-code-block">
                <div className="sk-code-title">DNS TXT 记录</div>
                <pre>_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"</pre>
              </div>
              <p className="sk-note">p=reject 表示验证失败直接拒收；rua 是报告接收地址</p>
            </div>
          </div>
        </div>
      </section>

      <section className="sk-section">
        <h2>与传输加密 (TLS) 的区别</h2>
        <div className="sk-callout warning">
          <span className="sk-callout-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </span>
          <div>
            <strong>SPF/DKIM/DMARC 解决的是"认证"问题，TLS 解决的是"加密"问题。</strong><br/>
            一封邮件可以是加密传输 (TLS) 但发件人是伪造的 (无 SPF/DKIM)；也可以是明文传输但发件人是真实的。两者互补，缺一不可。
          </div>
        </div>
      </section>
    </article>
  )
}

// ═══════════════════════════════════════════════════════
// Newly added articles (2026-03-19)
// ═══════════════════════════════════════════════════════

export function TopicPhishingDetection() {
  return (
    <article className="sk-article">
      <section id="多维检测架构"><h2>多维检测架构</h2>
        <p>邮件威胁不是单一维度能捕获的。一封精心制作的钓鱼邮件可能通过了 SPF/DKIM 验证（协议层无异常），使用了合法域名的子域名（发件人层难以判断），但在正文中包含紧迫性话术（内容层异常）+ 伪装成银行登录页的链接（链接层异常）。</p>
        <p>Vigilyx 的 <strong>16 个模块</strong>分属 <strong>8 个引擎</strong>，每个引擎独立输出证据，最终通过 D-S Murphy 融合产生裁决。没有任何单一模块能决定最终结果——这是证据融合的核心优势。</p>
        <div className="sk-callout sk-callout--info">系统覆盖 <strong>75 种</strong>威胁类别，从钓鱼/BEC/恶意软件到协议异常/数据泄露，每种类别有对应的检测模块和评分规则。</div>
      </section>
      <section id="内容分析引擎"><h2>引擎 B: 内容分析（6 个模块）</h2>
        <p><strong>content_scan</strong> — 核心规则引擎，维护三类检测规则库：</p>
        <ul>
          <li><strong>钓鱼关键词库</strong>：如"账户异常""立即验证""密码过期"，每命中 +0.08，上限 0.50</li>
          <li><strong>BEC 商务欺诈短语库</strong>：如"紧急汇款""更改收款账户"（27 个短语），每命中 +0.15，上限 0.50</li>
          <li><strong>DLP 敏感数据模式</strong>：信用卡 Luhn 校验、身份证号、API Key 正则匹配</li>
        </ul>
        <p><strong>html_scan</strong> — 检测恶意 HTML 元素（隐藏表单、脚本注入、事件处理器、Base64 嵌入）。<strong>html_pixel_art</strong> — 检测 1px 追踪信标和隐藏图片。</p>
        <p><strong>attach_scan</strong> — 通过 magic bytes 魔数识别 26 种文件类型，检测 PE 可执行文件、双扩展名（.pdf.exe）、加密压缩包、宏文档。<strong>attach_content</strong> — 对 ZIP/RAR 解压后提取文档文本再做内容分析。<strong>attach_hash</strong> — 计算附件 SHA256 查询本地黑名单 + 外部情报源。</p>
      </section>
      <section id="URL链接分析引擎"><h2>引擎 D: URL 链接分析（3 个模块）</h2>
        <p><strong>link_scan</strong> — 从 HTML 中提取所有 URL，检测：IP 地址直接访问链接、同形字攻击（用 а(Cyrillic) 替代 a(Latin)）、Punycode 编码域名、短链服务、href 与显示文本不匹配。</p>
        <p><strong>link_reputation</strong> — 查询 OTX AlienVault 和 VirusTotal 情报。<strong>link_content</strong> — 实际抓取目标页面，分析是否包含登录表单、JavaScript 载荷、可疑重定向链。</p>
      </section>
      <section id="语义与行为分析"><h2>引擎 F/G/H: 语义、身份、交易</h2>
        <p><strong>semantic_scan</strong> — 双层架构：Rust 本地引擎做 CJK 稀有字符/Shannon 熵/双字符唯一性分析；Python NLP 引擎做零样本或微调五分类。</p>
        <p><strong>identity_anomaly</strong> — 检测首次联系人、显示名与域名不匹配（显示"中国银行"但域名 gmail.com）、通信模式突变。</p>
        <p><strong>transaction_correlation</strong> — 识别银行账号、商业实体、紧迫性关键词与金融实体同时出现的 BEC 风险信号。</p>
      </section>
      <section id="安全熔断器"><h2>安全熔断器：防止融合漏报</h2>
        <p>D-S Murphy 融合可能将少数派引擎的威胁信号稀释——例如 content_scan 强烈报警但其余 7 个引擎均为安全时，融合后风险 ≈ 0。</p>
        <div className="sk-callout sk-callout--warn">
          <strong>熔断器机制</strong>：当任一规则模块 belief ≥ 0.20 且 confidence ≥ 0.80 时，将风险拉回该模块 belief 值。3+ 模块收敛时按 <code>1 + 0.15 × (n-2)</code> 放大。2+ 高信念模块收敛保证至少 Medium（0.40）。
        </div>
      </section>
    </article>
  )
}

export function TopicIocIntel() {
  return (
    <article className="sk-article">
      <section id="IOC类型与来源"><h2>IOC 类型与来源</h2>
        <p>系统支持 6 种 IOC 类型：<strong>IP 地址</strong>、<strong>邮箱地址</strong>、<strong>域名</strong>、<strong>文件哈希</strong> (SHA256)、<strong>URL</strong>、<strong>邮件主题</strong>。</p>
        <p>每个 IOC 记录包含：指标值、类型、来源（auto/manual/admin_clean）、判定（malicious/suspicious/clean）、置信度、攻击类型推断、命中计数、过期时间。来源为 <code>admin_clean</code> 的条目受保护，不被自动覆盖。</p>
      </section>
      <section id="自动记录与防护"><h2>自动记录与正反馈循环防护</h2>
        <p>裁决达到 <strong>High</strong> 级别时，引擎自动提取邮件中的 IOC 写入数据库。</p>
        <div className="sk-callout sk-callout--warn">
          <strong>阈值不能低于 High</strong>。如果用 Medium：Medium 邮件域名写入 IOC → 后续正常邮件命中加分 → 风险升 High → UPSERT 提高置信度 → <strong>循环放大</strong>。UPSERT 使用新值直接覆盖（不再 MAX 只升不降），admin_clean 条目受保护。IOC 默认 TTL 30 天。
        </div>
      </section>
      <section id="外部情报源"><h2>外部情报源查询</h2>
        <p>Intel 模块并行查询：<strong>OTX AlienVault</strong>（10 次/分钟，≥10 脉冲→malicious）、<strong>VirusTotal</strong>（6 次/分钟，≥30% 引擎检出→malicious）、<strong>AbuseIPDB</strong>（可选）。结果缓存到本地 IOC 表，TTL：malicious 3天、suspicious 1天、clean 7天。</p>
      </section>
      <section id="白名单管理"><h2>白名单与情报放行</h2>
        <p>情报白名单 = verdict=clean、source=admin_clean 的 IOC 条目。典型场景：QQ 邮箱域名 qq.com 被 OTX 误标可疑时，加入白名单即可。通过 <code>/api/security/intel-whitelist</code> 管理。</p>
      </section>
    </article>
  )
}

export function TopicAiNlp() {
  return (
    <article className="sk-article">
      <section id="双模型优先级"><h2>双模型优先级</h2>
        <p>推理时优先使用 <strong>Fine-tuned 五分类模型</strong>（data/nlp_models/latest/）。没有或加载失败时回退到<strong>零样本分类模型</strong>。两者共享基座：<code>mDeBERTa-v3-base-xnli-multilingual-nli-2mil7</code>（~550MB，100+ 语言）。</p>
      </section>
      <section id="零样本分类"><h2>零样本分类原理</h2>
        <p>将邮件内容与 5 个候选标签组成前提-假设对，通过 NLI 模型判断蕴含关系。中文标签：钓鱼邮件/诈骗邮件/商务欺诈/垃圾邮件/正常邮件。恶意概率 = P(phishing) + P(scam) + P(bec)。CJK 占比 &gt; 30% 用中文标签集。</p>
      </section>
      <section id="LoRA微调"><h2>LoRA 微调训练</h2>
        <p>分析师在邮件详情页标记正确类别积累样本，≥ 30 条可触发训练。LoRA 仅训练注意力层的 query_proj/value_proj（约 1.5% 参数）。</p>
        <div className="sk-callout sk-callout--info">
          <strong>高级技巧</strong>：Focal Loss (γ=2.0) 聚焦难分样本；R-Drop 正则化 (α=0.7)；自动类别加权；稀有类别数据增强。K-Fold 交叉验证质量门控：balanced_accuracy ≥ 0.50 且 macro_F1 ≥ 0.40。训练完成后<strong>零停机热替换</strong>。
        </div>
      </section>
      <section id="NLP与规则协作"><h2>NLP 与规则引擎的协作</h2>
        <p>NLP 模块标记为"非规则模块"，<strong>不能单独触发断路器</strong>（因误判率约 60%）。但 NLP 信号参与 D-S 融合和收敛断路器——当 NLP + 规则模块同时检测到威胁时，收敛断路器自然触发。</p>
      </section>
    </article>
  )
}

export function TopicSoarAlerts() {
  return (
    <article className="sk-article">
      <section id="P0-P3四级告警"><h2>P0-P3 四级告警</h2>
        <table className="sk-table">
          <thead><tr><th>级别</th><th>条件</th><th>含义</th></tr></thead>
          <tbody>
            <tr><td><strong>P0</strong></td><td>EL ≥ 3.0 / K &gt; 0.7 / CUSUM alarm / T ≥ 10000</td><td>立即处理</td></tr>
            <tr><td><strong>P1</strong></td><td>EL ∈ [1.5, 3.0) / K &gt; 0.6 / T ∈ [1000, 10000)</td><td>优先调查</td></tr>
            <tr><td><strong>P2</strong></td><td>EL ∈ [0.5, 1.5) / u &gt; 0.6 / T ∈ [100, 1000)</td><td>常规审查</td></tr>
            <tr><td><strong>P3</strong></td><td>EL ∈ [0.2, 0.5) / Risk ≥ 0.15</td><td>低优先级</td></tr>
          </tbody>
        </table>
      </section>
      <section id="期望损失与极值理论"><h2>期望损失与极值理论 (EVT)</h2>
        <p>EVT 使用 GPD 对风险尾部建模：收集最近 2000 样本的 95 分位数以上超出量，估计 GPD 参数，计算 VaR、CVaR 和回归期 T。T 越大，事件越罕见、越值得关注。</p>
      </section>
      <section id="SOAR处置规则"><h2>SOAR 处置规则引擎</h2>
        <p>每条规则：触发条件（min_threat_level + categories + modules，AND 关系）+ 处置动作列表。</p>
        <p>三种动作：<strong>webhook</strong>（POST 到 SIEM，SSRF 防护 + 10s 超时）、<strong>log</strong>（结构化日志）、<strong>alert</strong>（SMTP 邮件告警，异步发送）。规则按 priority 排序。邮件告警支持配置 SMTP 服务器/TLS/最低等级/通知收件人或管理员。</p>
      </section>
    </article>
  )
}

export function TopicDataSecurity() {
  return (
    <article className="sk-article">
      <section id="HTTP流量捕获"><h2>HTTP 流量捕获</h2>
        <p>通过 <code>WEBMAIL_SERVERS</code> 环境变量配置监控的 Webmail 服务器 IP。捕获到目标 HTTP 流量后解析请求方法、URI、Host、请求体（前 64KB），提取邮件字段（from/to/subject），支持 URL-encoded、JSON、Coremail 嵌套 JSON。</p>
      </section>
      <section id="三类泄露检测"><h2>三类数据泄露检测模式</h2>
        <ul>
          <li><strong>草稿箱滥用</strong> (draft_box_abuse)：将敏感数据保存为草稿绕过出站检测，识别 Coremail compose.jsp 的保存请求</li>
          <li><strong>文件中转滥用</strong> (file_transit_abuse)：通过 Webmail 文件上传中转敏感文件，识别分块上传并重组内容</li>
          <li><strong>自发送检测</strong> (self_sending)：给自己发送敏感数据绕过 DLP，比对 from/to 是否同一用户</li>
        </ul>
      </section>
      <section id="DLP扫描"><h2>DLP 敏感数据扫描</h2>
        <p>对请求体和上传文件检测：银行卡号（Luhn 校验）、身份证号（校验位验证）、手机号、合同/发票号、大额金融数据。事件分 5 级严重程度（info → critical），持久化到数据库并通过 WebSocket 实时推送。</p>
      </section>
    </article>
  )
}
