export interface EnglishTopicSection {
  heading: string
  plainText: string
}

export interface EnglishTopicContent {
  titleEn: string
  subtitleEn: string
  leadEn: string
  tagEn: string
  sectionsEn: EnglishTopicSection[]
}

export const englishTopics = {
  'mta': {
    titleEn: 'What Is an MTA',
    subtitleEn: 'Mail Transfer Agent',
    leadEn: 'An MTA is the server software responsible for moving email across the Internet. A single message usually passes through at least two MTAs before it reaches the recipient.',
    tagEn: 'Basics',
    sectionsEn: [
      {
        heading: 'Core concept',
        plainText: 'MTA, short for Mail Transfer Agent, is a core component of email infrastructure. Its job is to receive mail and route it to the next destination, much like a sorting center in the physical postal system. Common MTA software includes Postfix, Sendmail, Exim, Microsoft Exchange, and Coremail.',
      },
      {
        heading: 'Mail delivery flow',
        plainText: 'When you send an email, the path usually looks like this: the sender MUA, or mail client, submits the message over SMTP port 587 to a sending MTA such as smtp.gmail.com; that server relays it over SMTP port 25 through one or more relay MTAs or filtering gateways; the recipient MTA is located through MX records; and the final recipient reads it through POP3 or IMAP from the recipient MUA.',
      },
      {
        heading: 'How MTAs relate to Vigilyx',
        plainText: 'Vigilyx supports two mail-traffic access modes. In mirror mode it observes SMTP sessions between MTAs through packet capture, which is suitable for post-event auditing and alerting. In MTA proxy mode it acts as an SMTP relay directly, receives the message before delivery, and performs parsing, verdicting, and optional quarantine or blocking inline. Both modes share the same parser and detection engine; the difference is where Vigilyx sits in the mail path. MTA handles server-to-server transfer, MUA is the user client such as Outlook or Thunderbird, MDA handles local delivery, and MSA receives user submissions, commonly on port 587.',
      },
    ],
  },
  'opportunistic-tls': {
    titleEn: 'What Is Opportunistic TLS',
    subtitleEn: 'Opportunistic TLS and STARTTLS upgrade',
    leadEn: 'Opportunistic TLS follows the rule "encrypt when possible, continue when not." It is the most common MTA-to-MTA transport pattern today, but it can be downgraded.',
    tagEn: 'Encryption',
    sectionsEn: [
      {
        heading: 'How it works',
        plainText: 'The flow is: the sending MTA connects to the receiving MTA on TCP port 25 in cleartext, sends EHLO, receives the advertised extension list, checks whether 250-STARTTLS is present, issues STARTTLS if supported, receives 220 Ready to start TLS, and then performs the TLS handshake. All later SMTP traffic travels inside the encrypted channel.',
      },
      {
        heading: 'Key properties of opportunistic TLS',
        plainText: 'Advantages: it requires no pre-coordination, negotiates automatically, remains backward-compatible with servers that do not support TLS, costs very little to deploy, and is still much better than fully cleartext transport. Risks: it can be downgraded by STRIPTLS, usually does not verify the peer certificate strictly, allows an on-path attacker to tamper with the EHLO response, and gives end users no obvious signal about whether encryption was actually used.',
      },
      {
        heading: 'Downgrade attack (STRIPTLS)',
        plainText: 'This is the biggest security weakness of opportunistic TLS. An attacker in the middle, such as a hostile router or ISP, intercepts the traffic, edits the EHLO response, and removes the 250-STARTTLS line. The sending MTA no longer sees STARTTLS support and falls back to cleartext delivery. In Vigilyx terms, if the server advertised STARTTLS in the SMTP dialogue but the final session still remained unencrypted, you should suspect downgrade interference or a client that never issued STARTTLS.',
      },
      {
        heading: 'What Vigilyx can capture',
        plainText: 'If STARTTLS succeeds, the EHLO and STARTTLS negotiation remain visible, but everything after the upgrade becomes ciphertext and the mail body cannot be reconstructed. If STARTTLS is never used, the full SMTP dialogue remains visible in cleartext and can be reconstructed. Port 465 implicit TLS is encrypted from the first packet, so mirror-mode capture cannot see the content at all.',
      },
    ],
  },
  'mandatory-tls': {
    titleEn: 'What Is Mandatory TLS',
    subtitleEn: 'Mandatory TLS, DANE, and MTA-STS',
    leadEn: 'Mandatory TLS requires encrypted transport between MTAs. If a secure channel cannot be established, the message is refused instead of being downgraded to cleartext.',
    tagEn: 'Encryption',
    sectionsEn: [
      {
        heading: 'Why mandatory TLS exists',
        plainText: 'The core weakness of opportunistic TLS is that encryption is optional. An attacker can use STRIPTLS to force a downgrade to cleartext. Mandatory TLS solves exactly that problem: opportunistic TLS tries encryption and falls back to cleartext when it fails, while mandatory TLS requires encryption and refuses delivery when it fails.',
      },
      {
        heading: 'Implementation approaches',
        plainText: 'MTA-STS, defined in RFC 8461, lets the receiving domain publish an HTTPS policy stating that all mail sent to the domain must use TLS; the sending MTA retrieves the policy before delivery, and the mode can be enforce, testing, or none. DANE, defined in RFC 7672, publishes TLSA records in DNS and binds the mail server certificate fingerprint through DNSSEC; the sending MTA validates the certificate through DNS, which raises the deployment bar but provides strong security and avoids dependence on public CA trust alone. A third option is a manually configured TLS policy in Postfix or similar MTAs, which is practical for known partner domains but cannot cover the whole Internet.',
      },
      {
        heading: 'Opportunistic TLS vs mandatory TLS',
        plainText: 'When encryption fails, opportunistic TLS falls back to cleartext while mandatory TLS refuses delivery. Opportunistic TLS usually does not validate the certificate strictly; mandatory TLS must validate it. Opportunistic TLS cannot stop downgrade attacks; mandatory TLS can. Opportunistic TLS is extremely easy to deploy and works globally by default, while mandatory TLS is harder because the receiving side also needs stronger policy support. In Vigilyx, opportunistic TLS still leaves the pre-STARTTLS dialogue visible in mirror mode, while fully enforced transport leaves no readable payload at all.',
      },
    ],
  },
  'starttls': {
    titleEn: 'STARTTLS Command Explained',
    subtitleEn: 'Protocol upgrade from cleartext to TLS',
    leadEn: 'STARTTLS is a protocol extension command that upgrades an already established cleartext connection into a TLS-encrypted connection. It is the core mechanism behind opportunistic TLS.',
    tagEn: 'Protocol',
    sectionsEn: [
      {
        heading: 'SMTP STARTTLS interaction',
        plainText: 'A typical SMTP STARTTLS exchange looks like this, and Vigilyx can capture the cleartext phase before encryption begins: 220 mail.example.com ESMTP Postfix, EHLO sender.example.org, 250-mail.example.com, 250-SIZE 52428800, 250-STARTTLS, 250 8BITMIME, STARTTLS, 220 2.0.0 Ready to start TLS. After that comes the TLS handshake, and later SMTP commands such as MAIL FROM and DATA are encrypted.',
      },
      {
        heading: 'STARTTLS vs implicit TLS',
        plainText: 'STARTTLS, or explicit TLS, is commonly used on port 25 for MTA-to-MTA transport and on port 587 for submission. The connection begins in cleartext and is upgraded in place, so EHLO and STARTTLS remain observable. Implicit TLS is commonly used on port 465, starts encrypted from the first packet, and therefore appears as ciphertext immediately.',
      },
    ],
  },
  'spf-dkim-dmarc': {
    titleEn: 'SPF, DKIM, and DMARC',
    subtitleEn: 'The three core sender-authentication controls',
    leadEn: 'These three mechanisms answer one question together: did this message really come from the sender it claims to represent?',
    tagEn: 'Authentication',
    sectionsEn: [
      {
        heading: 'How the three work together',
        plainText: 'SPF, or Sender Policy Framework, declares in DNS which IP addresses are authorized to send on behalf of a domain, and the receiving MTA checks whether the source IP is in that list, for example v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all. DKIM, or DomainKeys Identified Mail, signs headers and body content with a private key and lets the receiver fetch the public key from DNS to verify that the message was not altered, for example DKIM-Signature: v=1; a=rsa-sha256; d=example.com. DMARC, or Domain-based Message Authentication, Reporting, and Conformance, adds policy on top of SPF and DKIM and lets the domain owner declare what to do if both fail, such as allow, quarantine, or reject, for example v=DMARC1; p=reject; rua=mailto:dmarc@example.com.',
      },
      {
        heading: 'How this differs from transport encryption',
        plainText: 'SPF, DKIM, and DMARC solve authentication. TLS solves transport encryption. A message can be encrypted in transit but still spoof the sender identity, and a message can also be sent in cleartext while the sender identity remains authentic. The two groups of controls are complementary and neither replaces the other.',
      },
    ],
  },
  'ds-fusion': {
    titleEn: 'D-S Evidence Theory and Multi-Engine Fusion',
    subtitleEn: 'Dempster-Shafer evidence theory and Murphy correction',
    leadEn: 'A traditional Bayesian pipeline uses a single probability P(threat) to represent risk, but that cannot distinguish "known safe" from "unknown." Vigilyx uses D-S evidence theory to model uncertainty explicitly through the triplet (b, d, u), then applies Murphy-style fusion to resolve conflicts among multiple evidence sources.',
    tagEn: 'Risk Model',
    sectionsEn: [
      {
        heading: 'Why D-S evidence theory is needed',
        plainText: 'Traditional Bayesian scoring uses a single P(threat) value. When a detector cannot decide, it may output P = 0.5, but that is very different from a detector that explicitly believes the threat probability is 50 percent. The former means uncertainty; the latter means a confident medium-risk judgment. Noisy-OR also assumes independence among evidence sources and does not model conflict well. If one module reports high risk and another reports safe, simply multiplying probabilities loses the fact that the conflict itself is informative. Dempster-Shafer evidence theory introduces belief, disbelief, and uncertainty as separate quantities, which gives the platform a cleaner basis for multi-source fusion.',
      },
      {
        heading: 'BPA triplet: explicit uncertainty modeling',
        plainText: 'On the frame of discernment Theta = {Threat, Normal}, Basic Probability Assignment can be simplified into the triplet b, d, and u. b, or belief, is support for Threat. d, or disbelief, is support for Normal. u, or uncertainty, is mass assigned to the whole frame Theta. The constraint is b + d + u = 1. A conventional detector output with score and confidence is converted by b = score x confidence, d = (1 - score) x confidence, and u = 1 - confidence. The risk score can then be computed as Risk = b + eta x u. With eta = 0.7, seventy percent of uncertainty is treated as threatening. The pignistic probability is P_bet(Threat) = b + u / 2, which distributes uncertainty evenly.',
      },
      {
        heading: 'Dempster combination and the Zadeh paradox',
        plainText: 'Given two BPAs m1 and m2, Dempster combination performs an orthogonal sum. The conflict factor is K = m1(T) x m2(N) + m1(N) x m2(T). The merged masses are m(T) = [m1(T) x m2(T) + m1(T) x m2(Theta) + m1(Theta) x m2(T)] / (1 - K), m(N) = [m1(N) x m2(N) + m1(N) x m2(Theta) + m1(Theta) x m2(N)] / (1 - K), and m(Theta) = m1(Theta) x m2(Theta) / (1 - K). The Zadeh paradox appears when evidence sources conflict so strongly that K approaches 1, the denominator becomes tiny, and a tiny overlap gets amplified into an absurdly confident conclusion. For example, if sensor A says 99 percent Threat and sensor B says 99 percent Normal, K becomes 0.98 and naive fusion can yield a nonsense result. That is why conflict needs preprocessing before fusion.',
      },
      {
        heading: 'Murphy-corrected fusion algorithm',
        plainText: 'Murphy correction addresses the Zadeh paradox by weighting and averaging evidence before repeated self-combination. Step one is the Jousselme distance: d_J(m1, m2) = sqrt(0.5 x (m1 - m2)^T x D x (m1 - m2)), where D is built from Jaccard similarity between focal elements. In the binary case D is a 3 x 3 matrix whose diagonal is 1, with |T intersect N| / |T union N| = 0 and |T intersect Theta| / |T union Theta| = 0.5. Step two computes similarity sim(i,j) = 1 - d_J(i,j), credibility crd(i) = sum of similarities to other evidence sources, and normalized weight w_i = crd(i) / sum crd(j). Step three produces the weighted average m_avg = sum w_i x m_i. Step four self-combines that average N - 1 times, where N is the number of engines, to make consistent evidence converge more strongly.',
      },
      {
        heading: 'Copula dependency correction',
        plainText: 'Dempster combination assumes independent evidence sources, but real detectors are not fully independent. The content engine and semantic-intent engine may rely on the same text features, and URL analysis may observe the same phishing URL that content analysis already surfaced. Copula dependency correction uses a correlation matrix R to quantify these relationships. For a strongly correlated pair with coefficient rho_ij, uncertainty is injected before fusion: b_i_new = b_i x (1 - rho_ij), and u_i_new = u_i + (b_i + d_i) x rho_ij. Intuitively, correlated engines receive a discount because they do not represent fully independent evidence. In the default matrix, content engine B and semantic engine F have correlation 0.30, URL engine D and content engine B have 0.20, and the remaining engine pairs stay at or below 0.15.',
      },
      {
        heading: 'Eight-engine architecture',
        plainText: 'The system uses eight complementary engines to cover different threat dimensions. Engine A models sender reputation through SPF, DKIM, domain reputation, and sending history. Engine B focuses on content analysis such as JS divergence in character distribution, urgency semantics, attachment risk, and HTML structure anomalies. Engine C captures behavioral baselines through GMM and isolation-forest style anomaly detection. Engine D handles URL analysis, including link reputation, redirect chains, QR-code URL extraction, and LOTS detection. Engine E checks protocol compliance, including header integrity, MIME structure, and Received-chain consistency. Engine F models semantic intent such as payment transfer or credential requests through LLM or rules. Engine G captures identity anomalies like first-contact detection, reply-chain anomalies, and client fingerprint changes. Engine H correlates transactional entities such as bank accounts and amounts against known business patterns. The final risk score is Risk_single = b_final + eta x u_final with eta = 0.7.',
      },
      {
        heading: 'Adversarial robustness constraints',
        plainText: 'An attacker may deliberately evade one engine. Diversity constraints prevent the platform from relying too heavily on any single engine. The rule is w_i <= 0.4 x sum w_j, which means no single engine may exceed 40 percent of the total fusion weight. The system also performs degradation analysis by simulating the removal of each engine and checking the worst-case detection performance. If one engine exceeds the allowed share, the excess weight is redistributed proportionally to the others. That keeps the fusion layer resilient even when attackers bypass or poison a subset of detectors.',
      },
    ],
  },
  'temporal-evt': {
    titleEn: 'Temporal Analysis and Tail-Risk Alerts',
    subtitleEn: 'Temporal analysis, HMM attack phases, and EVT alerting',
    leadEn: 'Single-message verdicting cannot capture progressive attacks across time windows. The temporal layer runs after per-message verdicting and uses CUSUM change detection, dual-speed EWMA drift analysis, HMM attack-phase inference, and communication-graph anomalies to detect slow-burn attacks.',
    tagEn: 'Risk Model',
    sectionsEn: [
      {
        heading: 'Role of the temporal layer',
        plainText: 'A passive monitoring system has one unique advantage: it can observe the full time series of mail traffic. Single-message analysis answers whether one message is dangerous. The temporal layer asks whether a sender is gradually changing behavior. That matters especially for BEC and ATO attacks, where the attacker often builds trust first and attacks later. Any individual message may look low-risk, but the timeline reveals the real intent. Temporal analysis runs asynchronously after the verdict is produced so it does not block the next message.',
      },
      {
        heading: 'CUSUM change detection',
        plainText: 'CUSUM, or cumulative sum, is a classic change-point detector for abrupt shifts in sender risk. The positive cumulative sum is S_plus(t) = max(0, S_plus(t-1) + r(t) - mu_0 - k), where r(t) is the risk score of message t, mu_0 is the historical normal mean for the sender, and k is the allowance term, typically 0.5 sigma. An alert fires when S_plus(t) > h, with h often set to 4 sigma. The intuition is that random noise gets reset by max(0, ...), but sustained elevation keeps accumulating until it crosses the threshold. Smaller k increases sensitivity; larger h reduces false positives.',
      },
      {
        heading: 'Dual-speed EWMA drift detection',
        plainText: 'Exponential weighted moving averages track sender behavior at two speeds. The fast EWMA is E_fast(t) = alpha_f x r(t) + (1 - alpha_f) x E_fast(t-1), with alpha_f = 0.05 and a memory of roughly 20 messages. The slow EWMA is E_slow(t) = alpha_s x r(t) + (1 - alpha_s) x E_slow(t-1), with alpha_s = 0.005 and a memory of roughly 200 messages. The drift score is |E_fast - E_slow| / max(E_slow, epsilon), where epsilon prevents division by zero. When the fast baseline diverges strongly from the slow baseline, sender behavior is changing. This is the mathematical signature of a boiling-frog style attack: the daily change may not trigger CUSUM, but the separation between fast and slow baselines grows over time.',
      },
      {
        heading: 'Entity risk accumulation',
        plainText: 'Each sender and domain keeps a decaying accumulated risk R_entity(t) = alpha x R_entity(t-1) + (1 - alpha) x r_new, with alpha = 0.92. That means each new message contributes 8 percent of its risk while historical risk decays by 92 percent each step. When R_entity exceeds the watchlist threshold, commonly 0.3, the entity is marked for continued monitoring and later messages receive an additional temporal risk premium. The decay term ensures that a benign entity is not permanently tainted by a single false positive.',
      },
      {
        heading: 'HMM five-state attack-phase inference',
        plainText: 'A Hidden Markov Model estimates the attack phase of a sender-recipient pair. The five hidden states are S0 normal communication, S1 reconnaissance, S2 trust building, S3 attack execution, and S4 monetization. The transition matrix reflects a typical attack path: the normal state self-transitions with probability 0.97 and occasionally moves to reconnaissance at 0.02; reconnaissance can move to trust building at 0.08; trust building can escalate to attack execution at 0.06; and attack execution can move to monetization at 0.15. The observation vector is O = (risk_single, u_final, K_conflict, time interval, content similarity change). Each state has its own emission distribution. Online inference computes gamma_t(s) = P(S_t = s | O_1...O_t), and the temporal risk becomes Risk_temporal = sum gamma_t(s) x w_s with weights {0.0, 0.3, 0.5, 1.0, 1.0}.',
      },
      {
        heading: 'Communication-graph anomaly detection',
        plainText: 'The platform maintains a directed weighted graph where nodes are email addresses and edges store communication history and risk. Three anomaly patterns are emphasized. Pattern one: mass mailing by a brand-new sender, where a first-seen sender contacts many recipients in a short period, a common phishing pattern. Pattern two: a new high-risk edge from an already known sender, where a historically normal sender suddenly sends risky mail to a new recipient, which can indicate BEC-style lateral movement. Pattern three: sudden fan-out growth, where an established sender rapidly increases the number of unique recipients, which can indicate data leakage or account takeover.',
      },
      {
        heading: 'GPD, EVT, and tail risk',
        plainText: 'Generalized Pareto Distribution models the extreme tail of the risk score distribution. Only observations above threshold u are fitted: P(X > x | X > u) = (1 + xi(x-u)/sigma)^(-1/xi). The threshold u is usually the 95th percentile of historical scores. The shape parameter xi controls tail heaviness, with xi > 0 for heavy tails and xi = 0 for an exponential tail. The scale parameter sigma controls tail spread. The parameters are estimated by probability-weighted moments. The return-period VaR is VaR_T = u + (sigma / xi) x [(n / N_u x T)^xi - 1]. The conditional value at risk is CVaR = VaR_T x (1 + (sigma - xi x u) / ((1 - xi) x VaR_T)). A large return period means the event is extremely rare under normal traffic; T > 10000 means roughly one event in ten thousand messages.',
      },
      {
        heading: 'Dynamic P0-P3 alert levels',
        plainText: 'The platform uses four alert priorities derived from expected loss and multiple auxiliary signals. Expected loss is EL = Risk_final x Impact_target, where the impact weight depends on the recipient role, such as 5.0 for executives, 4.5 for finance, and 4.0 for IT management. P0 is the highest priority and fires when EL >= 3.0, K_conflict > 0.7, both CUSUM and HMM attack-phase alarms trigger, or the EVT return period T >= 10000. P1 fires when EL is in [1.5, 3.0), K_conflict > 0.6, or T is in [1000, 10000). P2 fires when EL is in [0.5, 1.5), u_final > 0.6, or CUSUM alone alarms. P3 fires when Risk_final >= 0.15. The most severe matching level wins, and each alert record carries the reasoning and linked verdict context for analysts.',
      },
    ],
  },
  'module-pipeline': {
    titleEn: 'Security Module Pipeline and Fusion Implementation',
    subtitleEn: 'Security module pipeline and D-S fusion integration',
    leadEn: 'The default Vigilyx mail-analysis pipeline contains 20 entries: 19 analysis modules plus the final verdict stage. The pipeline runs as a DAG, converts each module output from (score, confidence) into BPA evidence, and then performs eight-engine D-S Murphy fusion. QR scanning, landing-page scanning, AITM detection, and sandboxing can also be registered at runtime.',
    tagEn: 'Risk Model',
    sectionsEn: [
      {
        heading: 'Module system architecture',
        plainText: 'Each security module implements the SecurityModule trait and exposes three core methods. metadata returns module metadata such as ID, name, pillar, dependency list, and timeout settings. analyze receives SecurityContext and returns ModuleResult. should_run is an optional gate that decides whether the module should execute. SecurityContext carries the full EmailSession, including headers, body, attachments, and links, plus a cache of already completed module outputs so later modules can reuse earlier findings. ModuleResult is the common output structure and includes module_id, threat_level, confidence, categories, summary, evidence, and JSON details such as the raw score.',
      },
      {
        heading: 'Default pipeline and extension modules',
        plainText: 'The default pipeline includes content_scan, html_scan, html_pixel_art, attach_scan, attach_content, attach_hash, mime_scan, header_scan, link_scan, link_reputation, link_content, anomaly_detect, semantic_scan, domain_verify, identity_anomaly, transaction_correlation, av_eml_scan, av_attach_scan, yara_scan, and verdict. The runtime registry can additionally enable attachment_qr_scan, landing_page_scan, aitm_detect, and sandbox_scan depending on the environment. In other words, 20 entries are a snapshot of the default pipeline, not the upper bound of platform capability. verdict is the final aggregation stage and should not be confused with the analysis modules that precede it.',
      },
      {
        heading: 'Pipeline orchestrator: layered DAG execution',
        plainText: 'The orchestrator uses Kahn topological sorting to turn dependencies into a directed acyclic graph and then executes the graph layer by layer. Modules inside the same layer have no unresolved dependencies and can run in parallel. Layers themselves remain sequential so later stages can depend on earlier results. Layer 0 usually contains most basic analysis modules, such as content, links, protocol, identity, and behavior. verdict and some expensive extension modules that depend on previous results run later. Every module has its own timeout and returns a safe placeholder result on timeout instead of blocking the whole pipeline. ConditionConfig can dynamically enable expensive modules, for example only running landing-page or sandbox analysis after suspicious links were found upstream.',
      },
      {
        heading: 'From scores to BPA triplets',
        plainText: 'Each module produces a raw risk score in [0,1] and a confidence value in [0,1]. At the end of the pipeline these outputs are converted into D-S triplets. The formula is b = score x confidence, which measures support for Threat; d = (1 - score) x confidence, which measures support for Normal; and u = 1 - confidence, which measures how uncertain the module is about its own judgment. For example, if content_scan finds multiple phishing phrases with score = 0.70 and confidence = 0.85, then b = 0.595, d = 0.255, u = 0.150. If domain_verify strongly validates the domain with score = 0.10 and confidence = 0.90, then b = 0.09, d = 0.81, u = 0.10. If semantic_scan cannot decide because the text is too short and outputs score = 0.30 with confidence = 0.20, then b = 0.06, d = 0.14, u = 0.80. In a conventional pipeline the third example may look like mild risk; in D-S terms it means the module contributes almost no useful evidence.',
      },
      {
        heading: 'Eight-engine mapping and intra-engine fusion',
        plainText: 'The default detection evidence maps into eight conceptual engines. Engine A corresponds to domain_verify. Engine B aggregates content_scan, html_scan, html_pixel_art, attach_scan, attach_content, attach_hash, and optionally attachment_qr_scan. Engine C corresponds to anomaly_detect. Engine D aggregates link_scan, link_reputation, link_content, and optionally landing_page_scan and aitm_detect. Engine E contains header_scan and mime_scan. Engine F corresponds to semantic_scan. Engine G corresponds to identity_anomaly. Engine H corresponds to transaction_correlation. av_eml_scan, av_attach_scan, and yara_scan are high-value sources that participate in the final fusion directly, while verdict is the terminal aggregation stage and is not treated as an independent evidence engine. Multi-module engines such as B and D first run intra-engine Dempster fusion before cross-engine fusion begins.',
      },
      {
        heading: 'Copula discount and Murphy fusion',
        plainText: 'After intra-engine merging, the pipeline enters cross-engine Murphy fusion. Step one applies Copula dependency discounting. For each engine the platform finds the strongest correlation max_rho; if max_rho exceeds 0.1, the engine BPA is discounted by b_new = b x (1 - max_rho), d_new = d x (1 - max_rho), and u_new = 1 - b_new - d_new, effectively moving mass into uncertainty. Step two computes the Jousselme distance matrix. Step three derives credibility weights from similarity = 1 - distance and then normalizes them. Step four applies the diversity constraint so that no single engine can exceed 40 percent of the total weight. Step five computes the weighted average m_avg = sum w_i x m_i. Step six self-combines m_avg N - 1 times so that consistent evidence converges more strongly.',
      },
      {
        heading: 'Trust-signal discount',
        plainText: 'The trust_score from domain_verify is handled as a dedicated trust signal outside the main D-S fusion path. When SPF passes, DKIM validates, the domains align, and trust_score approaches 1.0, the final risk score is discounted by final_score = risk_score x (1 - trust_score x 0.4). For example, if risk_score = 0.60 and trust_score = 1.0, the final score becomes 0.36, which downgrades Medium to Low. The intuition is that a fully validated sender identity should reduce suspicion, but the reduction is capped at 40 percent so strong malicious content can still surface.',
      },
      {
        heading: 'Final verdict: risk score and threat level',
        plainText: 'After D-S Murphy fusion and trust discounting, the final score is mapped to five threat levels. Risk_single = b_final + eta x u_final, with eta = 0.3. Critical is risk >= 0.85. High is risk >= 0.65. Medium is risk >= 0.40. Low is risk >= 0.15. Safe is below 0.15. End to end, the flow is: analyze the default 20 entries in dependency order and parallel layers, convert each module output into BPA, aggregate by engine or detection domain, perform intra-engine Dempster fusion, apply Copula dependency discounting, compute Murphy weighted fusion, enforce diversity constraints, self-combine N - 1 times, calculate Risk_single, apply trust discounting, and finally let verdict write the result and broadcast it over WebSocket.',
      },
    ],
  },
  'phishing-detection': {
    titleEn: 'Phishing Detection Techniques',
    subtitleEn: 'How the default 20-entry pipeline and extended modules cooperate',
    leadEn: 'The default Vigilyx mail-analysis pipeline contains 20 entries and can additionally enable QR scanning, landing-page scanning, AITM detection, and sandbox analysis. It evaluates messages across content, attachments, links, protocol, semantics, identity, and behavior.',
    tagEn: 'Detection',
    sectionsEn: [
      {
        heading: 'Multi-dimensional detection architecture',
        plainText: 'Mail threats cannot be captured from one dimension alone. A carefully crafted phishing message may pass SPF and DKIM, use a seemingly normal sender domain, include urgency language in the body, hide a QR code in the attachment, or expose an OAuth device-code lure on the landing page. The default 20-entry pipeline is grouped into eight conceptual engines. Each engine emits its own evidence, the final verdict is produced through D-S Murphy fusion, and deeper modules such as landing-page scanning, AITM detection, and sandboxing act as expensive second-stage analysis when needed.',
      },
      {
        heading: 'Content-analysis engine (B)',
        plainText: 'content_scan is the central rule module and maintains phishing keywords, BEC phrases, and DLP-style patterns. html_scan detects hidden forms, script injection, event handlers, and data URI abuse. html_pixel_art identifies 1-pixel tracking beacons and pixel-based disguises. attach_scan identifies risky file types through extensions and magic bytes. attach_content decompresses attachments and extracts text for deeper inspection. attach_hash compares attachment SHA256 values against local and external intelligence. When attachment_qr_scan is enabled, the system also decodes QR codes from image attachments and evaluates whether they point to device-code phishing or fake login pages.',
      },
      {
        heading: 'URL-analysis engine (D)',
        plainText: 'link_scan extracts URLs from HTML and checks for direct-to-IP links, homograph abuse, Punycode domains, shorteners, mismatches between href and visible text, and at-sign abuse. link_reputation queries local IOC cache and external intelligence sources. link_content fetches the target page and inspects login forms, JavaScript payloads, and suspicious path keywords. When landing_page_scan and aitm_detect are enabled, the platform can go further and detect device-code phishing flows, CAPTCHA-gated lure pages, and adversary-in-the-middle login pages.',
      },
      {
        heading: 'Semantic and behavioral analysis (F/G/H)',
        plainText: 'semantic_scan uses a dual-layer architecture: the Rust local engine handles CJK rare-character ratio, Shannon entropy, and bigram uniqueness, while the Python AI service performs NLP classification when enabled. The zero-shot path uses the labels phishing, scam, bec, spam, and legitimate. The fine-tuned path uses legitimate, phishing, spoofing, social_engineering, and other_threat. identity_anomaly detects first-contact behavior, display-name and domain mismatches, reply-chain anomalies, and communication-pattern shifts. transaction_correlation identifies BEC-style signals where bank-account entities, business entities, urgency language, and financial entities appear together.',
      },
      {
        heading: 'Safety circuit breaker: preventing fusion false negatives',
        plainText: 'D-S Murphy fusion can dilute the warning from a minority engine. For example, content_scan may alert strongly while the other seven conceptual engines remain safe, which can drive the fused score close to zero. The circuit-breaker logic prevents that. When any rule module has belief >= 0.20 and confidence >= 0.80, the fused risk floor is pulled back up to at least that module belief. When three or more independent modules fire, the floor is amplified by 1 + 0.15 x (n - 2). When two or more high-belief modules converge, the final result is forced to at least Medium, or 0.40. This prevents a high-confidence detector from being erased by a majority of "no signal" engines.',
      },
    ],
  },
  'ioc-intel': {
    titleEn: 'IOC Threat Intelligence Management',
    subtitleEn: 'Indicator ingestion, intelligence lookups, and false-positive control',
    leadEn: 'IOC, or Indicators of Compromise, are markers of known malicious activity, such as IP addresses, domains, file hashes, URLs, or email addresses. Vigilyx supports automatic IOC recording, external intelligence lookups, and whitelist protection.',
    tagEn: 'Intelligence',
    sectionsEn: [
      {
        heading: 'IOC types and sources',
        plainText: 'The system supports six IOC types: IP addresses from external Received headers, sender email addresses from mail_from, sender domains, attachment SHA256 hashes, URLs marked by link_scan, and message-subject patterns. Each IOC record stores the indicator value, type, source (auto, manual, or admin_clean), verdict (malicious, suspicious, or clean), confidence in [0,1], inferred attack type, hit count, and expiry time. Sources are grouped into auto, manual, and admin_clean, where admin_clean represents whitelist-protected entries that automated writes cannot overwrite.',
      },
      {
        heading: 'Automatic recording and protection against feedback loops',
        plainText: 'When a mail verdict reaches High, the engine automatically extracts IOC values such as IPs, domains, hashes, URLs, and sender addresses and writes them into the database. The threshold must not be lower than High. Otherwise a Medium-risk message could insert its domain into IOC storage, later benign mail from that domain would gain IOC score, the verdict would rise to High, UPSERT would further strengthen confidence, and the system would amplify itself in a loop. The UPSERT policy now replaces old values directly instead of using a MAX-only ratchet, and entries with source admin_clean are protected from automated overwrite. IOC entries expire after 30 days by default.',
      },
      {
        heading: 'External intelligence lookups',
        plainText: 'During message analysis, the intel module can query three external sources in parallel. OTX AlienVault is rate-limited to 10 requests per minute and uses pulse_count thresholds where 10 or more pulses means malicious, 3 through 9 means suspicious, and less than 3 means clean. VirusTotal is rate-limited to 6 requests per minute and uses Playwright-based page scraping to estimate engine consensus, where 30 percent or more detections means malicious and 10 percent or more means suspicious. AbuseIPDB is optional and contributes IP abuse scores. The results are cached locally in the IOC table with TTLs of 3 days for malicious, 1 day for suspicious, and 7 days for clean. Local IOC cache is always checked first to avoid unnecessary outbound calls.',
      },
      {
        heading: 'Whitelist and intelligence release',
        plainText: 'The intelligence whitelist is used to exclude known-safe domains or IPs that would otherwise be labeled suspicious. Adding a whitelist entry is equivalent to creating an IOC item with verdict = clean and source = admin_clean. admin_clean entries are protected, so later automated analysis cannot overwrite them even if the same indicator is later observed as suspicious. The whitelist is managed through /api/security/intel-whitelist and supports creation, deletion, and bulk listing. Typical examples include qq.com, internal company domains, or partner infrastructure that appears noisy in external feeds.',
      },
    ],
  },
  'ai-nlp': {
    titleEn: 'AI and NLP Phishing Models',
    subtitleEn: 'Dual-model architecture: zero-shot plus fine-tuned',
    leadEn: 'The Vigilyx AI service uses the multilingual mDeBERTa backbone and supports both zero-shot classification and LoRA fine-tuning from analyst feedback.',
    tagEn: 'AI',
    sectionsEn: [
      {
        heading: 'Dual-model priority',
        plainText: 'At inference time, the platform prefers the fine-tuned five-class model if one has been trained. The fine-tuned model lives under data/nlp_models/latest/ and is trained from analyst feedback, so it adapts better to organization-specific mail. If the fine-tuned model is missing or fails to load, the service falls back to zero-shot classification. The zero-shot path uses NLI and therefore needs no local training data, but its accuracy is typically lower. Both paths share the same base model: MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7, roughly 550 MB and covering more than 100 languages.',
      },
      {
        heading: 'Zero-shot classification',
        plainText: 'Zero-shot classification turns the mail content into premise-hypothesis pairs against five candidate labels. The labels are phishing, scam, bec, spam, and legitimate. When the CJK character ratio exceeds 30 percent, the system uses the Chinese label set; otherwise it uses the English label set. The platform sums the probabilities of phishing, scam, and bec into the malicious probability. These labels are intentionally different from the fine-tuned model, which uses legitimate, phishing, spoofing, social_engineering, and other_threat because that better matches the analyst labeling workflow inside the platform.',
      },
      {
        heading: 'LoRA fine-tuning',
        plainText: 'Administrators accumulate training data through analyst feedback, such as correcting the category on the mail detail page. Training can be triggered once 30 samples are available. The model is fine-tuned with LoRA, which updates only the DeBERTa attention query_proj and value_proj layers, roughly 1.5 percent of the total parameters, while freezing the other 98.5 percent. Additional training techniques include focal loss with gamma = 2.0 to emphasize hard examples, R-Drop regularization by constraining the KL divergence of two forward passes, automatic class weighting, and rare-class augmentation through token deletion and token swapping. Quality is gated by K-fold cross-validation; balanced_accuracy must be at least 0.50 and macro_F1 must be at least 0.40. After training, the new model is hot-swapped with zero downtime.',
      },
      {
        heading: 'How NLP cooperates with the rule engine',
        plainText: 'Inside semantic_scan, NLP output is fused with the Rust local rules. NLP is explicitly marked as a non-rule signal in the circuit-breaker logic, so it cannot raise the safety floor on its own. Otherwise one noisy semantic sensor could override a strong safe consensus from multiple rule modules. Even so, the NLP signal still participates in D-S fusion and in convergence logic. When NLP and rule-driven modules such as content, links, or identity all flag risk together, the final score rises naturally while keeping false positives under control.',
      },
    ],
  },
  'soar-alerts': {
    titleEn: 'Alert Prioritization and Automated Response',
    subtitleEn: 'P0-P3 alerts and the SOAR disposition engine',
    leadEn: 'Vigilyx uses dynamic alert prioritization built on extreme value theory and expected loss, together with a configurable automated response engine.',
    tagEn: 'Alerts',
    sectionsEn: [
      {
        heading: 'P0-P3 alert levels',
        plainText: 'P0, or Critical, fires when EL >= 3.0, K_conflict > 0.7, a CUSUM alarm triggers, or the EVT return period T >= 10000 years. It represents confirmed high-risk attacks or severe inter-engine contradiction and requires immediate handling. P1, or High, fires when EL is in [1.5, 3.0), K_conflict > 0.6, or T is in [1000, 10000). It represents threats confirmed by multiple engines and deserves priority investigation. P2, or Medium, fires when EL is in [0.5, 1.5), u_final > 0.6, or T is in [100, 1000). It represents partial confirmation and should be reviewed in normal workflow. P3, or Low, fires when EL is in [0.2, 0.5) or Risk_final >= 0.15. It captures mild suspicion that does not yet justify a stronger alert.',
      },
      {
        heading: 'Expected loss and extreme value theory',
        plainText: 'Expected loss, or EL, is a confidence-weighted measure that combines threat severity with detection certainty. EVT, or Extreme Value Theory, fits a Generalized Pareto Distribution to the tail of the risk-score distribution: it collects exceedances above the 95th percentile from the most recent 2000 samples, estimates the GPD shape parameter xi and scale parameter sigma by probability-weighted moments, and computes VaR, CVaR, and the return period T. A larger T means the event is rarer under normal traffic and therefore deserves more attention.',
      },
      {
        heading: 'SOAR disposition rule engine',
        plainText: 'Administrators can define automated response rules. Each rule combines trigger conditions such as min_threat_level, category list, and flagged_modules list with an action list, all under AND semantics. Three action types are supported: webhook, which sends an HTTP POST to an external SIEM or ticketing system and is protected by SSRF checks plus a 10-second timeout; log, which emits structured logs; and alert, which sends SMTP warning mail asynchronously without blocking the detection pipeline. Rules are ordered by priority and can be enabled or disabled. The SMTP alert system supports configurable server, port, TLS mode, minimum alert level, and whether to notify recipients or administrators.',
      },
    ],
  },
  'data-security': {
    titleEn: 'Data Security and HTTP Session Detection',
    subtitleEn: 'Webmail traffic capture and data-leak detection',
    leadEn: 'In addition to SMTP, POP3, and IMAP analysis, Vigilyx can capture webmail HTTP traffic and detect data leakage behavior performed through browser-based mail systems.',
    tagEn: 'Data Security',
    sectionsEn: [
      {
        heading: 'HTTP traffic capture',
        plainText: 'The sniffer uses the WEBMAIL_SERVERS environment variable to define which webmail server IPs should be monitored. When matching HTTP traffic is seen, the sniffer parses the method, URI, Host, Content-Type, and Cookie fields, then extracts the first 64 KB of the request body to recover mail fields such as from, to, and subject. It supports URL-encoded payloads, JSON payloads, and nested Coremail JSON structures. HTTP sessions are written into the Redis Stream vigilyx:stream:http_sessions, and the engine reads them through consumer groups for downstream data-security analysis.',
      },
      {
        heading: 'Three data-leak detection patterns',
        plainText: 'draft_box_abuse detects users who save sensitive data into drafts instead of sending it, which can bypass outbound monitoring; the platform recognizes Coremail compose.jsp draft-save requests and scans the recovered content with DLP. file_transit_abuse detects abuse of webmail upload workflows as a temporary file-transfer channel; the platform recognizes chunked uploads, reconstructs the full file, and scans it. self_sending detects cases where a user sends sensitive data to the same mailbox, which can bypass certain DLP policies; the platform compares from and to fields case-insensitively.',
      },
      {
        heading: 'DLP scanning of sensitive data',
        plainText: 'The data-security engine scans HTTP request bodies and uploaded files for bank-card numbers with Luhn validation, Chinese resident identity numbers with check-digit validation, Mainland China mobile numbers, contract or invoice IDs that match specific patterns, and financial amounts above configured thresholds. Incidents are graded into info, low, medium, high, and critical. All incidents are persisted to the data_security_incidents table and then exposed to the frontend through API queries and WebSocket updates.',
      },
    ],
  },
  'mirror-vs-mta': {
    titleEn: 'Mirror Mode and MTA Proxy Mode',
    subtitleEn: 'The two Vigilyx deployment paths and when to use them',
    leadEn: 'Vigilyx supports both passive mirror deployment and MTA proxy deployment. They share the same parser and detection engine, but their insertion point, blocking capability, and operational requirements are very different.',
    tagEn: 'Architecture',
    sectionsEn: [
      {
        heading: 'Mirror mode',
        plainText: 'Mirror mode captures live SMTP, POP3, IMAP, and optional HTTP traffic from a SPAN port, network TAP, or switch mirror port. Its main advantage is minimal intrusion: it does not alter the mail path and is well suited for post-event auditing and alerting. Its main limitation is that analysis happens after the traffic has already passed through production infrastructure, so it is naturally stronger at observation, forensics, and alerting than at pre-delivery blocking.',
      },
      {
        heading: 'MTA proxy mode',
        plainText: 'MTA proxy mode inserts Vigilyx directly into the SMTP relay path. A client or upstream MTA delivers mail to vigilyx-mta first; the proxy then completes the SMTP conversation, parses MIME, calls the inline security engine, and accepts, forwards, quarantines, or rejects the message based on the verdict. The mode supports TLS termination, inline timeout control, and fail-open or fail-closed policy, making it the foundation for realtime blocking.',
      },
      {
        heading: 'How to choose',
        plainText: 'If the goal is to observe traffic with minimal production impact, validate rules, and tune down false positives, mirror mode is the safer starting point. If the goal is to block before delivery, quarantine high-risk mail, and accept SMTP-path changes, MTA proxy mode is the better fit. Many teams start in mirror mode and then migrate gradually to MTA proxy mode once they trust the detection stack.',
      },
    ],
  },
  'message-bus': {
    titleEn: 'Message Bus and Reliable Delivery',
    subtitleEn: 'Redis Streams for the data plane and Pub/Sub for the control plane',
    leadEn: 'The Vigilyx messaging layer is intentionally split. Session data uses Redis Streams, while control commands and notifications use Pub/Sub. That separation gives reliable delivery where it matters and lightweight fan-out where it is acceptable.',
    tagEn: 'Architecture',
    sectionsEn: [
      {
        heading: 'Data plane: Redis Streams',
        plainText: 'The sniffer writes email sessions into vigilyx:stream:sessions and HTTP sessions into vigilyx:stream:http_sessions. The engine reads these streams through consumer groups and acknowledges them only after successful processing with XACK, which gives the platform at-least-once delivery semantics. Compared with plain Pub/Sub, Streams are a better fit for raw analysis inputs that must not be silently dropped.',
      },
      {
        heading: 'Failure recovery: PEL and XAUTOCLAIM',
        plainText: 'If a consumer crashes while processing, unacknowledged messages remain in the Pending Entries List. When the engine starts again, it can reclaim entries that have been idle beyond the threshold by using XAUTOCLAIM and continue the interrupted work. That gives the ingestion path a practical recovery mechanism after abnormal restarts.',
      },
      {
        heading: 'Control plane: Pub/Sub',
        plainText: 'Control-plane messages such as reload and rescan commands, plus broadcasts like verdict, status, and heartbeat notifications, still use Pub/Sub. These messages are closer to realtime notifications or idempotent commands, so fire-and-forget semantics are acceptable. Pub/Sub is also a natural fit for broadcasting into the API WebSocket layer and multiple internal components. The core architectural principle is simple: the data plane optimizes for reliability, and the control plane optimizes for lightness.',
      },
    ],
  },
  'mta-quarantine': {
    titleEn: 'Quarantine and Message Release',
    subtitleEn: 'Inline verdicting, quarantine storage, and release flow',
    leadEn: 'In MTA proxy mode, Vigilyx does not have to choose only between allow and reject. Quarantine provides a third path: receive the message, preserve the original content, and let an administrator review and release it later.',
    tagEn: 'Response',
    sectionsEn: [
      {
        heading: 'When mail enters quarantine',
        plainText: 'In MTA proxy mode, the inline engine performs a fast verdict after the DATA phase. A typical policy is: Safe and Low are forwarded directly, Medium and High are written into the quarantine table while the sender still receives success, and Critical is rejected immediately. That preserves realtime response while avoiding leakage of detection details back to the attacker and leaving room for analyst review.',
      },
      {
        heading: 'What the quarantine stores',
        plainText: 'A quarantine record typically preserves session_id, mail_from, rcpt_to, subject, threat_level, reason, status, created_at, released_at, released_by, ttl_days, and the original raw_eml. The goal is not to keep only a short summary, but to preserve the information needed for later investigation, replay, and manual release.',
      },
      {
        heading: 'Release and deletion',
        plainText: 'Administrators can list entries and statistics through /api/security/quarantine, release a message through POST /api/security/quarantine/:id/release, and delete a record through DELETE /api/security/quarantine/:id. released_by is taken from the authenticated JWT user rather than any client-supplied field. In other words, the quarantine is both a response queue and part of the audit trail.',
      },
    ],
  },
  'bec-attack': {
    titleEn: 'Business Email Compromise',
    subtitleEn: 'BEC attack workflow and defensive signals',
    leadEn: 'BEC is one of the most financially destructive email attack classes. Attackers impersonate executives or partners and try to convince finance staff to transfer money.',
    tagEn: 'Attack Technique',
    sectionsEn: [
      {
        heading: 'Typical attack flow',
        plainText: 'The usual sequence is: reconnaissance, where the attacker collects the organization chart, executive names, and finance process from sources such as LinkedIn and public websites; mailbox compromise, where the attacker gains access to an executive or supplier account through phishing or password spraying; quiet observation, where the attacker watches real conversations to understand payment habits and approval flow; attack launch, where a fake payment instruction is inserted into a real transaction and the receiving account is replaced with one controlled by the attacker; and fund transfer, where the victim sends money to the attacker and discovers the problem only days later.',
      },
      {
        heading: 'Five common BEC variants',
        plainText: 'CEO fraud impersonates the CEO or CFO and demands an urgent transfer. Invoice fraud impersonates a supplier and changes the receiving account on a real invoice. Lawyer impersonation claims a confidential M and A or legal matter requires urgent payment. Data theft impersonates HR and requests employee W-2 forms or personal data. Account takeover hijacks an already compromised mailbox and inserts a fraudulent request into an existing thread.',
      },
      {
        heading: 'How Vigilyx detects BEC',
        plainText: 'content_scan looks for BEC keyword combinations such as urgency plus transfer plus executive title. identity_anomaly checks for display-name fraud, for example when the display name belongs to an internal executive but the email address uses an external domain. transaction_correlation ties urgency language to financial entities. In the AI path, the zero-shot model exposes a dedicated bec label, while the fine-tuned model expresses similar risk through spoofing, social_engineering, or other_threat. First-contact detection also highlights never-before-seen external suppliers.',
      },
    ],
  },
  'social-engineering': {
    titleEn: 'Social Engineering Attacks',
    subtitleEn: 'Attack techniques that exploit human weakness',
    leadEn: 'Social engineering does not depend on software vulnerabilities. It exploits trust, fear, curiosity, and urgency, and it is often the first step in an APT intrusion path.',
    tagEn: 'Attack Technique',
    sectionsEn: [
      {
        heading: 'Common social-engineering language',
        plainText: 'Fear-based lures say things like "your account will be closed," "abnormal login detected," or "failure to act will freeze your access." Authority impersonation pretends to be Microsoft, Apple, a bank, or a tax authority. Curiosity lures promise performance reviews, salary changes, or delivery exceptions. Urgency lures use phrases such as "limited time," "act now," or "within 24 hours." Greed lures promise tax refunds, prizes, or free gifts.',
      },
      {
        heading: 'Social engineering in APT mail',
        plainText: 'APT spear-phishing messages are highly customized. They use the target real name and title, reference actual internal projects or events, disguise attachments as legitimate work files such as weekly reports, contracts, or invoices, and impersonate co-workers or partners. Attackers may spend weeks performing reconnaissance so the message looks entirely plausible.',
      },
      {
        heading: 'How Vigilyx detects it',
        plainText: 'The account_security_phishing combination checks for threat description plus action pressure in the same message. content_scan covers Chinese and English phishing keywords, simplified and traditional variants, and Unicode normalization. NLP semantics based on mDeBERTa recognizes phishing or scam intent. SPF, DKIM, and DMARC results validate sender identity. First-contact detection highlights never-before-seen external senders.',
      },
    ],
  },
  'attachment-weaponization': {
    titleEn: 'Attachment Weaponization',
    subtitleEn: 'Malicious attachment types, disguise tactics, and detection',
    leadEn: 'Malicious attachments remain one of the most common email attack carriers. Attackers hide trojans, ransomware, and infostealers inside files that look like normal business documents.',
    tagEn: 'Attack Technique',
    sectionsEn: [
      {
        heading: 'Common malicious attachment types',
        plainText: 'Examples include macro-enabled Office documents such as .docm or .xlsm, PDFs with embedded JavaScript or phishing links, HTML smuggling files that reconstruct malware in the browser, double-extension executables such as invoice.pdf.exe, nested ZIP or RAR archives that hide executables, and ISO or IMG disk images that can bypass Mark-of-the-Web protections.',
      },
      {
        heading: 'Detection challenges',
        plainText: 'Password-protected ZIP, RAR, or PDF files cannot be inspected easily. Polymorphic malware changes on every build and defeats simple signatures. Attackers often host payloads on legitimate cloud services such as Google Drive, OneDrive, or Dropbox. Some attachments are only clean-looking downloaders that fetch the real payload later from a C2 server.',
      },
      {
        heading: 'How Vigilyx detects it',
        plainText: 'attach_scan detects double extensions, executable file types, and nested archives. attach_hash computes SHA-256 and queries VirusTotal reputation. attach_content extracts text from the attachment for phishing-keyword analysis. html_pixel_art detects QR codes embedded in HTML and extracts the target URL. Magic-byte detection identifies the real file type from the file header so fake extensions do not bypass the pipeline.',
      },
    ],
  },
  'link-obfuscation': {
    titleEn: 'Link Obfuscation and Redirects',
    subtitleEn: 'URL confusion, redirect chains, and homograph attacks',
    leadEn: 'Attackers use many techniques to hide the true destination of a malicious link so the user believes a click leads to a legitimate site.',
    tagEn: 'Attack Technique',
    sectionsEn: [
      {
        heading: 'URL obfuscation techniques',
        plainText: 'Common patterns include href and visible text mismatch, short links from services such as bit.ly or tinyurl.com, redirect chains that pass through several benign domains before reaching the phishing page, URL encoding such as percent-encoded delimiters, at-sign abuse like https://legitimate.com@evil.com where the real host is evil.com, and data URIs that carry the page content directly in the URL.',
      },
      {
        heading: 'IDN homograph attacks',
        plainText: 'Attackers can register domains with visually similar Unicode characters. For example, "apple.com" can be mimicked with a Cyrillic character that looks the same to a human but belongs to a different code point. The Punycode form may look like xn--..., while some browsers render the Unicode form directly, making the fake domain difficult for users to distinguish.',
      },
      {
        heading: 'How Vigilyx detects it',
        plainText: 'link_scan checks for direct-to-IP links, shorteners, href-text mismatch, at-sign abuse, redirect parameters, and tokenized URLs. link_content detects IDN homograph tricks through mixed-script analysis, overly long URLs, double encoding, and suspicious path keywords. link_reputation adds DGA-style random-domain checks, suspicious TLD heuristics, and external intelligence lookups such as OTX or VT scraping. Trusted URL allowlists prevent noisy but legitimate long-parameter links from common services such as QQ Mail from being misclassified.',
      },
    ],
  },
} as const satisfies Record<string, EnglishTopicContent>
