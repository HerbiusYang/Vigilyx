interface EnglishTopicSection {
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
    subtitleEn: 'D-S uncertainty theory, clustered fusion, and legacy Murphy',
    leadEn: 'The default mail pipeline schedules detectors and final verdict through a DAG. Authoritative clustered_ds_v2 performs evidence admission, causal-artifact deduplication, one-sided BPA fusion and named constraints. V1/Murphy implementations are removed; historical configuration selectors migrate to V2 on load. Conditions, external services and explicit opt-in settings still control module execution.',
    tagEn: 'Risk Model',
    sectionsEn: [
      {
        heading: 'Why D-S evidence theory is needed',
        plainText: 'Traditional Bayesian scoring uses a single P(threat) value and does not distinguish a confident 50 percent threat estimate from uncertainty. Dempster-Shafer evidence theory represents belief, disbelief, and uncertainty separately. This article covers the mathematical background; the current default verdict path is clustered_ds_v2, the older Murphy runtime implementation has been removed and its mathematics is historical background.',
      },
      {
        heading: 'BPA triplet: explicit uncertainty modeling',
        plainText: 'On the frame of discernment Theta = {Threat, Normal}, Basic Probability Assignment can be simplified into the triplet b, d, and u. b, or belief, is support for Threat. d, or disbelief, is support for Normal. u, or uncertainty, is mass assigned to the whole frame Theta. The constraint is b + d + u = 1. A conventional detector output with score and confidence is converted by b = score x confidence, d = (1 - score) x confidence, and u = 1 - confidence. The risk score can then be computed as Risk = b + eta x u. Eta is configurable; Vigilyx currently compiles with a default of 0.30. The pignistic probability is P_bet(Threat) = b + u / 2, which distributes uncertainty evenly.',
      },
      {
        heading: 'Dempster combination and the Zadeh paradox',
        plainText: 'Given two BPAs m1 and m2, Dempster combination performs an orthogonal sum. The conflict factor is K = m1(T) x m2(N) + m1(N) x m2(T). The merged masses are m(T) = [m1(T) x m2(T) + m1(T) x m2(Theta) + m1(Theta) x m2(T)] / (1 - K), m(N) = [m1(N) x m2(N) + m1(N) x m2(Theta) + m1(Theta) x m2(N)] / (1 - K), and m(Theta) = m1(Theta) x m2(Theta) / (1 - K). The Zadeh paradox appears when evidence sources conflict so strongly that K approaches 1, the denominator becomes tiny, and a tiny overlap gets amplified into an absurdly confident conclusion. For example, if sensor A says 99 percent Threat and sensor B says 99 percent Normal, K becomes 0.98 and naive fusion can yield a nonsense result. That is why conflict needs preprocessing before fusion.',
      },
      {
        heading: 'Legacy Murphy-corrected fusion (retired Murphy)',
        plainText: 'This algorithm is historical mathematical background; its runtime implementation has been removed. Murphy correction addresses the Zadeh paradox by weighting and averaging evidence before repeated self-combination. Step one is the Jousselme distance: d_J(m1, m2) = sqrt(0.5 x (m1 - m2)^T x D x (m1 - m2)), where D is built from Jaccard similarity between focal elements. In the binary case D is a 3 x 3 matrix whose diagonal is 1, with |T intersect N| / |T union N| = 0 and |T intersect Theta| / |T union Theta| = 0.5. Step two computes similarity sim(i,j) = 1 - d_J(i,j), credibility crd(i) = sum of similarities to other evidence sources, and normalized weight w_i = crd(i) / sum crd(j). Step three produces the weighted average m_avg = sum w_i x m_i. Step four self-combines that average N - 1 times, where N is the number of engines, to make consistent evidence converge more strongly.',
      },
      {
        heading: 'Copula dependency correction in the legacy path',
        plainText: 'Dempster combination assumes independent evidence sources, but real detectors are not fully independent. The content engine and semantic-intent engine may rely on the same text features, and URL analysis may observe the same phishing URL that content analysis already surfaced. The older retired Murphy path uses Copula dependency correction with a correlation matrix R to quantify these relationships; the current clustered_ds_v2 default does not run this step. For a strongly correlated pair with coefficient rho_ij, uncertainty is injected before fusion: b_i_new = b_i x (1 - rho_ij), and u_i_new = u_i + (b_i + d_i) x rho_ij. Intuitively, correlated engines receive a discount because they do not represent fully independent evidence. Those correlation examples belong to the legacy A-H engine configuration; they are not parameters of the default clustered_ds_v2 path.',
      },
      {
        heading: 'The eight evidence clusters in the current default path',
        plainText: 'The default path maps normalized detector signals into eight EvidenceClusterId values: inherited_gateway_prior, delivery_integrity, sender_identity_authenticity, link_and_html_deception, payload_malware, external_reputation_ioc, social_engineering_intent, and business_sensitivity. The system first deduplicates stable causal keys and assigns each artifact to one fusion cluster. Artifact mass combines within each cluster; clusters and qualified normal evidence then combine once. Scenario constraints separately inspect normalized source views and causal keys.',
      },
      {
        heading: 'Legacy fusion diversity constraint',
        plainText: 'The retired Murphy path includes an engine-diversity weight constraint; the current clustered_ds_v2 default does not enforce a 40 percent per-engine weight cap. The default path instead addresses duplicate evidence through causal-key deduplication, one-sided artifact fusion, and risk floors that require admitted independent evidence.',
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
        plainText: 'Each message updates one long-lived baseline key: ordinary senders aggregate by registrable domain, while public mailbox providers such as qq.com and gmail.com use the complete sender address so unrelated users do not share a baseline. The default alpha is 0.92. When risk rises, a new observation contributes 8 percent. When risk falls, a clean observation contributes half that weight (4 percent), or one quarter (2 percent) while the entity remains on the watchlist (default threshold 0.30). This asymmetric washout prevents a short burst of clean traffic from quickly erasing prior risk. The first observation initializes the value directly.',
      },
      {
        heading: 'HMM five-state attack-phase inference',
        plainText: 'A Hidden Markov Model estimates the attack phase of a sender-recipient pair. The five hidden states are S0 normal communication, S1 reconnaissance, S2 trust building, S3 attack execution, and S4 monetization. The default transition matrix assigns S0→S0 = 0.990, S0→S1 = 0.008, S1→S2 = 0.050, S2→S3 = 0.030, and S3→S4 = 0.100; the remaining probability in each row is assigned to other transitions and self-loops. The model supports observations (risk_single, u_final, K_conflict, time interval, content similarity change), but the production path currently passes content similarity change as 0.0, so that feature does not contribute to live inference. Each state has its own emission distribution. Online inference computes gamma_t(s) = P(S_t = s | O_1...O_t), and the temporal risk becomes Risk_temporal = sum gamma_t(s) x w_s with weights {0.0, 0.3, 0.5, 1.0, 1.0}.',
      },
      {
        heading: 'Communication-graph anomaly detection',
        plainText: 'The platform maintains a directed weighted graph where nodes are email addresses and edges store communication history and risk. Three anomaly patterns are emphasized. Pattern one: mass mailing by a brand-new sender, where a first-seen sender contacts many recipients in a short period, a common phishing pattern. Pattern two: a new high-risk edge from an already known sender, where a historically normal sender suddenly sends risky mail to a new recipient, which can indicate BEC-style lateral movement. Pattern three: sudden fan-out growth, where an established sender rapidly increases the number of unique recipients, which can indicate data leakage or account takeover.',
      },
      {
        heading: 'GPD, EVT, and tail risk',
        plainText: 'Generalized Pareto Distribution models the extreme tail of the risk score distribution. Only observations above threshold u are fitted: P(X > x | X > u) = (1 + xi(x-u)/sigma)^(-1/xi). The threshold u is usually the 95th percentile of historical scores. The shape parameter xi controls tail heaviness, with xi > 0 for heavy tails and xi = 0 for an exponential tail. The scale parameter sigma controls tail spread. The parameters are estimated by probability-weighted moments. Let N be the sample-window size and N_u the number of observations above threshold u; the exceedance rate is p_u = N_u / N. The implementation computes the return period in samples as T = 1 / (p_u x P(X > x | X > u)). Inverting this gives VaR_T = u + (sigma / xi) x [(p_u x T)^xi - 1] (with the exponential limit when xi approaches 0). For xi < 1, the conditional mean beyond VaR_T is CVaR_T = VaR_T + [sigma + xi x (VaR_T - u)] / (1 - xi). T is an interval in observations, not years.',
      },
      {
        heading: 'Dynamic P0-P3 alert levels',
        plainText: 'An alert is created only when Risk_final >= 0.15. Expected loss is EL = Risk_final x recipient impact weight; the default is 1.0, with ceo@ = 5.0, cfo@/finance@ = 4.5, it-admin@ = 4.0, and admin@ = 3.5, using the highest recipient weight. P0 fires for EL >= 3, K_conflict > 0.7, EVT T >= 10000, or (when Risk_final >= 0.4) a CUSUM alarm or Hawkes ratio > 5. P1 fires for EL >= 1.5, EVT T >= 1000, HMM attack phase gamma(S3) > 0.3, Hawkes ratio > 3, Novelty > 0.6, or K_cross > 0.5. P2 fires for EL >= 0.5, u_final > 0.6, EVT T >= 100, HMM trust-building phase gamma(S2) > 0.25, a communication-graph anomaly, Novelty > 0.3, or a CUSUM alarm when Risk_final < 0.4. A message with Risk_final >= 0.15 and no higher-level signal is P3. P3 database inserts are rate-limited globally to 30 per minute; excess individual alerts are suppressed and a summary alert is emitted in the next window. The most severe matching level wins; EVT T is measured in samples.',
      },
    ],
  },
  'module-pipeline': {
    titleEn: 'Security Module Pipeline and Fusion Implementation',
    subtitleEn: 'Security module pipeline and D-S fusion integration',
    leadEn: 'The default mail pipeline schedules detectors and final verdict through a DAG. Authoritative clustered_ds_v2 performs evidence admission, causal-artifact deduplication, one-sided BPA fusion and named constraints. V1/Murphy implementations are removed; historical configuration selectors migrate to V2 on load. Conditions, external services and explicit opt-in settings still control module execution.',
    tagEn: 'Risk Model',
    sectionsEn: [
      {
        heading: 'Module system architecture',
        plainText: 'Module score and confidence remain the original detector output. Authoritative D-S V2 deduplicates causal artifacts, then forms one-sided malicious mass from strength, confidence and cluster reliability. Without independently qualified normal evidence, d=0 and remaining mass stays uncertain. A low detector score does not create normal evidence; module BPA and V2 artifact BPA have separate meanings.',
      },
      {
        heading: 'Default pipeline and extension modules',
        plainText: 'The compiled default configuration contains 29 entries: content_scan, html_scan, html_pixel_art, attach_scan, attach_content, attach_qr_scan, attach_hash, mime_scan, header_scan, link_scan, link_reputation, link_content, landing_page_scan, url_sandbox_scan, process_sandbox_scan, anomaly_detect, aitm_detect, rmm_detect, prompt_injection_scan, toad_detect, semantic_scan, domain_verify, identity_anomaly, transaction_correlation, av_eml_scan, av_attach_scan, sandbox_scan, yara_scan, and verdict. QR, landing-page, AITM, and sandbox modules are already present in the default configuration. Module conditions, external services, and explicit opt-ins govern whether some modules execute; configured entries do not imply that every message runs every module. verdict is the final aggregation stage, not an independent detector.',
      },
      {
        heading: 'Pipeline orchestrator: event-driven DAG scheduling',
        plainText: 'The full asynchronous pipeline builds a DAG from module metadata depends_on edges and configured ConditionConfig dependencies, then uses topological sorting to reject cycles. Runtime scheduling is event-driven: all root nodes start concurrently, and a successor starts as soon as its dependencies complete. A condition’s depends_module creates the dependency edge and selects the result checked by min_threat_level; a node is skipped and marks inspection incomplete if a hard dependency was disabled and produced no result. In MTA inline mode, a detector that depends on a deferred module is also skipped and marks inspection incomplete; the final verdict node waits only for dependencies selected into the inline pipeline. A blocking module failure or timeout, or an unavailable required dependency, returns a temporary failure (451 by default; with fail-open enabled, relay may still proceed subject to outbound DLP enforcement). For a dependency skip with no inline module still timed out, the engine returns the inline result to the MTA handler and then starts the full pipeline to persist diagnostics; those later results are for audit/UI and do not change the delivery action the handler chose from the inline result. A completed verdict marked with incomplete inspection coverage quarantines an otherwise acceptable Safe/Low result. An advisory link_reputation availability failure does not by itself block disposition. The API rejects duplicate or unknown enabled module IDs, dependency cycles, and min_threat_level without depends_module so concurrent completion order cannot change the decision. should_run and ConditionConfig can also skip modules that do not apply to the current message. Each running module has its own timeout, and failures or timeouts record a placeholder result and status. MTA inline verdict uses a separately bounded set of prioritized modules, not the full asynchronous pipeline.',
      },
      {
        heading: 'Source normalization and BPA triplets',
        plainText: 'Module score and confidence remain the original detector output. Authoritative D-S V2 deduplicates causal artifacts, then forms one-sided malicious mass from strength, confidence and cluster reliability. Without independently qualified normal evidence, d=0 and remaining mass stays uncertain. A low detector score does not create normal evidence; module BPA and V2 artifact BPA have separate meanings.',
      },
      {
        heading: 'Eight evidence clusters and causal sources',
        plainText: 'The current default path first maps normalized signals to eight EvidenceClusterId values: inherited_gateway_prior, delivery_integrity, sender_identity_authenticity, link_and_html_deception, payload_malware, external_reputation_ioc, social_engineering_intent, and business_sensitivity. V2 first deduplicates by stable causal key and retains the strongest complete strength/reliability pair per artifact. Artifact mass combines within each cluster, then clusters and qualified normal evidence combine once. Named scenario constraints separately inspect normalized source views and causal keys. Module IDs describe configuration and analysis results; configured entries do not imply execution on every message, and modules do not vote through the old A-H engine grouping.',
      },
      {
        heading: 'Default clustered_ds_v2 source fusion',
        plainText: 'Authoritative clustered_ds_v2 retains the strongest complete strength/reliability pair per artifact; several detectors of one artifact do not gain extra votes. Distinct artifacts combine within clusters, then clusters and qualified normal evidence combine once through symmetric n-ary fusion. Threat/normal conflict transfers to uncertainty. There is no weighted-mean self-combination. Normal mass requires complete coverage and qualified provenance such as cryptographically verified aligned identity.',
      },
      {
        heading: 'Identity and scenario adjustments in the default path',
        plainText: 'Named risk floors and caps inspect admitted causal sources and message context. The identity review policy requires at least Medium for a random sender domain or From/Reply-To domain mismatch while preserving raw Bel. V2 does not apply a universal trust_score x 0.4 discount; that adjustment belongs to noisy_or.',
      },
      {
        heading: 'Final verdict: default-path risk score and threat level',
        plainText: 'V2 base risk is Bel(Threat); unknown mass is not converted to threat through eta. Named attack constraints and explicit review policies produce final risk. Levels are Critical >=85%, High >=65%, Medium >=40%, Low >=15%. A random sender domain or From/Reply-To domain mismatch requires at least Medium under the identity review policy without changing raw Bel. Unknown means insufficient evidence, not established safety.',
      },
    ],
  },
  'phishing-detection': {
    titleEn: 'Phishing Detection Techniques',
    subtitleEn: 'How configured detection modules cover multiple areas',
    leadEn: 'The compiled default Vigilyx mail-analysis pipeline contains 29 configuration entries across content, attachments, links, protocol, semantics, identity, and behavior. Conditions, external services, and explicit opt-ins determine which modules actually run.',
    tagEn: 'Detection',
    sectionsEn: [
      {
        heading: 'Multi-dimensional detection architecture',
        plainText: 'Mail threats cannot be captured from one dimension alone. A carefully crafted phishing message may pass SPF and DKIM, use a seemingly normal sender domain, include urgency language in the body, hide a QR code in the attachment, or expose an OAuth device-code lure on the landing page. The 29-entry compiled default configuration contains detector modules plus the final verdict stage. Runtime signals are deduplicated by stable causal key, then assigned to eight evidence clusters. Artifact mass combines within each cluster before the single clustered_ds_v2 combination. A-H engine_id values only categorize modules. Landing-page, AITM, and sandbox modules are present in the default configuration, while conditions, external services, and explicit opt-in gates determine whether they run for a message.',
      },
      {
        heading: 'Content-analysis engine (B)',
        plainText: 'content_scan is the central rule module and maintains phishing keywords, BEC phrases, and DLP-style patterns. html_scan detects hidden forms, script injection, event handlers, and data URI abuse. html_pixel_art identifies 1-pixel tracking beacons and pixel-based disguises. attach_scan identifies risky file types through extensions and magic bytes. attach_content decompresses attachments and extracts text for deeper inspection. attach_hash compares attachment SHA256 values against local and external intelligence. The default configuration includes attach_qr_scan, which decodes QR codes from image attachments and evaluates whether they point to device-code phishing or fake login pages; execution remains condition-gated.',
      },
      {
        heading: 'URL-analysis engine (D)',
        plainText: 'link_scan extracts URLs from HTML and checks for direct-to-IP links, homograph abuse, Punycode domains, shorteners, mismatches between href and visible text, and at-sign abuse. link_reputation queries local IOC cache and external intelligence sources. link_content fetches the target page and inspects login forms, JavaScript payloads, and suspicious path keywords. When landing_page_scan and aitm_detect are enabled, the platform can go further and detect device-code phishing flows, CAPTCHA-gated lure pages, and adversary-in-the-middle login pages.',
      },
      {
        heading: 'Semantic and behavioral analysis (F/G/H)',
        plainText: 'semantic_scan defaults to local Rust semantic rules that retain provenance, speech acts, requested targets, and bounded relation proofs. An optional CPU ONNX bge/e5 intent ensemble loads through SEMANTIC_INTENT_MODEL_DIR and records shadow diagnostics by default. An explicit SEMANTIC_INTENT_SCORE_THRESHOLD replaces local rules and the later Python NLP/OCR path; a hit contributes a Low module score of 0.20 to fusion, not a guaranteed final verdict or action. Python AI is a separate optional NLP/OCR service. identity_anomaly analyzes first contact and identity shifts, while transaction_correlation provides cross-session business-risk clues.',
      },
      {
        heading: 'Safety circuit breaker: preventing fusion false negatives',
        plainText: 'The generic circuit breaker in default clustered_ds_v2 accepts only native source views marked floor-eligible: source score must be at least 0.55 and confidence at least 0.70. Its floor is source score x alert_floor_factor (default 1.0; validation prevents discounting). The convergence breaker defaults to at least two independent causal keys at source score threshold `convergence_belief_threshold=0.10`, from at least two evidence clusters, with one native floor-eligible anchor. Its base floor is 0.40 and each additional independent source adds 0.05, up to 0.15. A dedicated cap applies when verified identity is paired only with low-confidence contextual signals, so two arbitrary modules do not guarantee Medium.',
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
        plainText: 'The system supports six IOC types: IP addresses from external Received headers, sender email addresses from mail_from, sender domains, attachment SHA256 hashes, URLs marked by link_scan, and message-subject patterns that can be maintained manually. Automatic IOC extraction does not record subjects. Each IOC record stores the indicator value, type, source (auto, auto_reference, manual, or admin_clean), verdict (malicious, suspicious, or clean), confidence in [0,1], inferred attack type, hit count, and expiry time. auto_reference is a short-lived suspicious observation from a Low-or-higher message verdict; it informs later analysis but is not a whitelist. admin_clean represents an explicit whitelist entry that automated writes cannot overwrite.',
      },
      {
        heading: 'Automatic recording and protection against feedback loops',
        plainText: 'The engine records indicators from Low-or-higher verdicts as short-lived auto_reference/suspicious observations. A later message may reuse that reference as weak threat evidence, but it still runs the complete detector pipeline. Critical verdicts can use the stronger auto/malicious path; a specific domain-impersonation path writes a malicious IOC at High or above when its similarity gate passes. Safe verdicts do not create general automatic IOCs. This separates low-risk threat direction from confirmed maliciousness and bounds feedback loops with a 24-hour reference TTL, source protection, and an IP frequency gate. Entries with source admin_clean remain explicit whitelist authority and are protected from automated overwrite.',
      },
      {
        heading: 'External intelligence lookups',
        plainText: 'IP lookups can query OTX AlienVault, VirusTotal, and optional AbuseIPDB in parallel; domain lookups use OTX and VirusTotal. OTX is rate-limited to 10 requests per minute. Pulse counts of 25 or more and 3–24 both yield suspicious (confidence 0.45 and 0.31–0.38 respectively); fewer than 3 yields clean. OTX alone never returns malicious. With an official VirusTotal API key, the engine prefers the official API (4 requests per minute, 500 per day): at least 3 malicious engines yields malicious; at least 1 malicious engine or 3 suspicious engines yields suspicious. If the API fails for a non-quota reason and Playwright scraping is enabled, the engine falls back to scraping (6 requests per minute); without an API key, scraping is also queried only when explicitly enabled. The scrape path uses a malicious ratio of at least 30% or a count of 5, and a suspicious ratio of at least 10% or a count of 2. External results are cached in the local IOC table for 30 days when malicious, 1 day when suspicious/unknown, and 3 days when clean/safe. Ordinary lookups prefer the local external-intel cache; callers with local detection signals revalidate cached external clean results, while admin_clean/system whitelist entries remain authoritative.',
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
    leadEn: 'The optional Python AI service supports zero-shot classification and approved fine-tuned model inference; training is offline. The Rust CPU ONNX intent ensemble is a separate integration.',
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
        heading: 'Offline training and model approval',
        plainText: 'Administrators can collect analyst feedback and export samples for offline training. The current AI service has removed in-service training: legacy POST /training/train returns 410 TRAINING_REMOVED, and no 30-sample online trigger is available. After offline validation and staging as pending, an administrator must explicitly approve through POST /api/admin/nlp/approve (internally POST /model/approve) before hot loading. Inference uses the previous model until approval. This Python NLP approval flow is separate from packaging, configuring, and restarting the Rust ONNX intent-model integration.',
      },
      {
        heading: 'How NLP cooperates with the rule engine',
        plainText: 'The local-rule path can use Python NLP as auxiliary evidence. Scenario observations, coverage gaps, and malicious evidence must be interpreted separately; overall fusion and policy determine the outcome. The ONNX intent ensemble is shadow-only by default. Explicit scored mode replaces local rules and the later Python NLP/OCR path instead of stacking all model outputs together. A model score alone cannot guarantee maliciousness or disposition.',
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
        plainText: 'No alert is created when Risk_final < 0.15. P0, or Critical, fires for EL >= 3.0, K_conflict > 0.7, EVT T >= 10000, or (when risk >= 0.4) a CUSUM alarm or Hawkes ratio > 5. P1, or High, fires for EL >= 1.5, EVT T >= 1000, HMM attack phase gamma(S3) > 0.3, Hawkes ratio > 3, Novelty > 0.6, or K_cross > 0.5. P2, or Medium, fires for EL >= 0.5, u_final > 0.6, EVT T >= 100, HMM trust-building phase gamma(S2) > 0.25, a communication-graph anomaly, Novelty > 0.3, or a CUSUM alarm when risk < 0.4. Other created alerts are P3, or Low. The most severe matching level wins; EVT T is measured in samples.',
      },
      {
        heading: 'Expected loss and extreme value theory',
        plainText: 'Expected loss, or EL, is the final risk score multiplied by the highest recipient impact weight; it is not a module-confidence-weighted score. EVT, or Extreme Value Theory, fits a Generalized Pareto Distribution to exceedances above a threshold from a rolling risk window, then computes return period T and CVaR. T is a recurrence interval measured in samples; larger T indicates a rarer observation under the fitted window model.',
      },
      {
        heading: 'SOAR disposition rule engine',
        plainText: 'Administrators can define automated response rules. Each rule combines trigger conditions such as min_threat_level, category list, and flagged_modules list with an action list, all under AND semantics. Three action types are supported: webhook, which sends an HTTP POST to an external SIEM or ticketing system and is protected by SSRF checks plus a 10-second timeout; log, which emits structured logs; and alert, which sends SMTP warning mail asynchronously without blocking the detection pipeline. Rules are ordered by priority and can be enabled or disabled. The SMTP alert system supports configurable server, port, TLS mode, minimum alert level, and whether to notify recipients or administrators.',
      },
    ],
  },
  'data-security': {
    titleEn: 'Data Security and Outbound Email Reviews',
    subtitleEn: 'HTTP/Webmail DLP, SMTP outbound reviews, and privacy access',
    leadEn: 'HTTP/Webmail incidents and SMTP outbound reviews record data-security risks separately. Mirror mode audits; MTA can enforce outbound DLP on relay candidates. POP3/IMAP currently provide metadata and coverage signals only.',
    tagEn: 'Data Security',
    sectionsEn: [
      {
        heading: 'HTTP traffic capture',
        plainText: 'At startup, the sniffer reads environment values and then loads API settings. The API returns saved PostgreSQL settings or built-in defaults, which override matching environment fields. Standard Compose does not pass WEBMAIL_SERVERS, and the API default Webmail list is empty, so configure a non-empty server list through the UI/API to enable HTTP capture. A non-empty API port list replaces the environment port list. Matching traffic is parsed for the method, URI, Host, Content-Type, and Cookie, and the first 64 KB of the request body is inspected for mail fields such as from, to, and subject. URL-encoded payloads, JSON payloads, and nested Coremail JSON structures are supported. HTTP sessions are written to the Redis Stream vigilyx:stream:http_sessions, which the engine reads through a consumer group for data-security analysis.',
      },
      {
        heading: 'Three data-leak detection patterns',
        plainText: 'draft_box_abuse detects users who save sensitive data into drafts instead of sending it, which can bypass outbound monitoring; the platform recognizes Coremail compose.jsp draft-save requests and scans the recovered content with DLP. file_transit_abuse detects abuse of webmail upload workflows as a temporary file-transfer channel; the platform recognizes chunked uploads, reconstructs the full file, and scans it. self_sending detects cases where a user sends sensitive data to the same mailbox, which can bypass certain DLP policies; the platform compares from and to fields case-insensitively.',
      },
      {
        heading: 'DLP scanning of sensitive data',
        plainText: 'The data-security engine scans HTTP request bodies and uploaded files for bank-card numbers with Luhn validation, Chinese resident identity numbers with check-digit validation, Mainland China mobile numbers, contract or invoice IDs that match specific patterns, and financial amounts above configured thresholds. Incidents are graded into info, low, medium, high, and critical. All incidents are persisted to the data_security_incidents table and then exposed to the frontend through API queries and WebSocket updates.',
      },
      {
        heading: 'SMTP outbound reviews and mode boundaries',
        plainText: 'SMTP outbound reviews are separate from HTTP incidents and mail threat verdicts. List, statistics, and detail routes live under /api/data-security/email-reviews. Mirror mode only audits inspectable payloads; MTA outbound DLP can alert, quarantine, or block relay candidates. Direction requires trusted source, domain, and recipient evidence; a local-looking MAIL FROM alone is insufficient. Encrypted traffic, unknown direction, incomplete payloads, and failed checks remain explicit unknowns.',
      },
      {
        heading: 'Privacy and temporary content access',
        plainText: 'Privacy mode masks content by default while retaining security analysis. An administrator requests an exact resource and scopes with a purpose and their verification factor. An independent audit user approves with a separate factor. The requester then obtains a lease bound to their user, JWT session, exact resource, and scopes, valid for at most five minutes. System Settings → Privacy manages policy and requests. Missing or unreadable policy defaults to masking; credentials remain masked when privacy is disabled, and redacted persisted review evidence cannot be reconstructed.',
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
    leadEn: 'Vigilyx uses different channels for different jobs: sessions and current rescan requests use Redis Streams, while statistics, verdict notifications, and reload controls use Pub/Sub. Streams support acknowledgements and recovery, but exhausted publish retries or approximate trimming can still lose messages.',
    tagEn: 'Architecture',
    sectionsEn: [
      {
        heading: 'Data plane: Redis Streams',
        plainText: 'The sniffer writes email and HTTP sessions to vigilyx:stream:sessions and vigilyx:stream:http_sessions. API historical rescan requests also use vigilyx:stream:rescan_requests. The engine reads through consumer groups and sends XACK after successful processing. This provides at-least-once processing for entries that were published and have not been trimmed; exhausted sniffer retries, a full producer queue, or approximate MAXLEN trimming can still lose messages.',
      },
      {
        heading: 'Failure recovery: PEL and XAUTOCLAIM',
        plainText: 'If a consumer crashes while processing, unacknowledged entries that remain in the Stream stay in the Pending Entries List. The engine can use XAUTOCLAIM to reclaim entries idle beyond the threshold and continue processing; entries already removed by MAXLEN trimming cannot be recovered from the PEL.',
      },
      {
        heading: 'Control plane: Pub/Sub',
        plainText: 'Reload commands and notifications for sniffer statistics, verdicts, alerts, data-security incidents, and engine status use Pub/Sub. Current single, batch, and quarantine-release rescan requests use Redis Streams; the engine retains its older Pub/Sub rescan subscriber for compatibility. Pub/Sub does not retain messages while subscribers are offline, so it is suitable for notification fan-out but does not provide queue-style retries.',
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
        plainText: 'In MTA proxy mode, the inline engine performs a fast verdict after DATA completes or BDAT LAST arrives. By default, Safe and Low messages with complete inspection proceed to the downstream relay; a completed verdict with incomplete coverage quarantines an otherwise acceptable result. A blocking module failure or timeout, or an unavailable required dependency, returns a temporary failure (451 by default); fail-open may attempt relay. Medium and High are written to the quarantine table while the sender receives success, and Critical is rejected. Outbound DLP scans messages for audit, but enforcement runs only when the delivery plan would relay the message, including fail-open relay: allow_and_alert continues relay, quarantine stores the message, and block rejects it. DLP enforcement does not change a threat verdict that already quarantines or rejects the message. That preserves realtime response while avoiding leakage of detection details back to the attacker and leaving room for analyst review.',
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
