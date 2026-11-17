#!/usr/bin/env python3
"""Build labels.json for the red-team EML corpus.

Label schema (one entry per .eml):
  file            relative path under redteam_cases/
  case_id         short id (ctrl01 / ev42 / inc02 / ham07)
  group           control | evasion | incident | ham
  round           0=original suite, 1..7=red-team rounds, "incident"/"ham"
  label           malicious | benign
  family          lure/attack family (see FAMILIES below)
  language        zh | zh-hant | zh-yue | en | ja | ru | vi | th | id
  techniques      attack/feature tags
  expected        block | deliver | regression_contract
  engine_status   blocked | delivered | not_in_harness
                  (snapshot of the last complete harness run, 2026-08-24)
  open            true when expected=block but engine currently delivers
  note            optional

Run:  python3 build_labels.py     (writes labels.json, validates, prints stats)
"""
import json
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# engine_status snapshot: last COMPLETE harness run on the remote builder.
# Everything is "blocked" except the seven round-7 open cases.
DELIVERED_NOW = {
    "ev69_giftcard_bec.eml",
    "ev70_tax_rebate_paraphrase.eml",
    "ev71_pii_harvest_reply.eml",
    "ev72_trusted_open_redirect.eml",
    "ev76_paraphrase_no_keyword.eml",
    "ev77_display_internal_domain.eml",
    "ev81_chain_vi_redirect.eml",
}

FAMILIES = {
    "account_phishing": "账户/凭证类钓鱼（异常登录、冻结、验证话术）",
    "bec": "商务邮件欺诈（付款变更、礼品卡、退税、权威冒充）",
    "subsidy_fraud": "补贴/退税类欺诈",
    "pii_harvest": "回复式个人信息收割（证件、人脸）",
    "quishing": "二维码钓鱼",
    "toad": "电话诱导（TOAD）",
    "malware_attachment": "恶意/危险附件（exe、docm、iso、lnk、rtlo）",
    "credential_harvest": "凭据收集表单（HTML 附件或正文表单）",
    "redirect_attachment": "附件重定向（meta refresh、快捷方式）",
    "identity_spoof": "身份伪造（显示名、同形字、伪造认证头、假线程）",
    "social_trust": "低信号纯社工信任诱导",
    "structure_evasion": "结构级绕过（稀释、超长窗口、嵌套、百段）",
    "language_coverage": "语言/方言覆盖缺口",
    "sanitizer_evasion": "横幅剥离器反转",
    "link_obfuscation": "链接隐藏/混淆载体（实体、base、裸域、重定向）",
    "encoding_evasion": "字符集/编码绕过",
    "visual_lure": "像素级视觉载荷（图片文字、隐藏 CSS）",
    "coverage_gap_contract": "采集覆盖缺口回归契约（非攻击样本）",
    "incident_replay": "真实事件回放",
    "ham_business": "良性商务/系统邮件",
    "ham_personal": "良性个人邮件",
}


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_capability_manifest(entries):
    """Freeze every labeled family without binding to mutable engine status."""
    case_ids_by_family = {}
    for entry in entries:
        case_ids_by_family.setdefault(entry["family"], []).append(entry["case_id"])
    case_ids_by_family = {
        family: sorted(case_ids)
        for family, case_ids in sorted(case_ids_by_family.items())
    }
    capabilities = [
        {
            "id": family,
            "case_set_sha256": "sha256:" + hashlib.sha256(
                canonical_json(case_ids).encode("utf-8")
            ).hexdigest(),
            "minimum_cases": len(case_ids),
        }
        for family, case_ids in case_ids_by_family.items()
    ]
    manifest_seed = canonical_json(case_ids_by_family).encode("utf-8")
    return {
        "schema_version": 1,
        "manifest_version": "sha256:" + hashlib.sha256(manifest_seed).hexdigest(),
        "capabilities": capabilities,
    }

# (file, id, group, round, label, family, lang, techniques, expected, note)
TABLE = [
    # ---- controls (must be blocked) ----
    ("ctrl01_plain_cn_phishing.eml", "ctrl01", "control", 0, "malicious", "account_phishing", "zh",
     ["plain_cn_lure", "ip_url", "hotline"], "block", "基线中文账户钓鱼"),
    ("ctrl02_bec_payment_change.eml", "ctrl02", "control", 0, "malicious", "bec", "en",
     ["payment_change", "iban"], "block", "基线英文付款变更 BEC"),
    ("ctrl03_qp_split_keyword.eml", "ctrl03", "control", 0, "malicious", "account_phishing", "zh",
     ["quoted_printable_soft_break"], "block", "QP 软换行拆关键词"),
    ("ctrl04_utf8_ja_control.eml", "ctrl04", "control", 1, "malicious", "account_phishing", "ja",
     ["utf8_plain"], "block", "ev16 的 UTF-8 对照组"),
    ("ctrl05_cp1251_ru_control.eml", "ctrl05", "control", 3, "malicious", "account_phishing", "ru",
     ["declared_windows1251"], "block", "ev19 的声明字符集对照组"),
    ("ctrl06_raster_qr_control.eml", "ctrl06", "control", 4, "malicious", "quishing", "zh",
     ["raster_png_datauri_qr", "ip_payload"], "block", "ev20 的光栅二维码对照组"),
    ("ctrl07_plain_ip_href.eml", "ctrl07", "control", 5, "malicious", "link_obfuscation", "zh",
     ["plain_ip_href", "neutral_text"], "block", "明文 IP 链接校准基线"),

    # ---- original evasion suite (round 0) ----
    ("ev01_entity_hairsp_break.eml", "ev01", "evasion", 0, "malicious", "account_phishing", "zh",
     ["html_entity_hairsp"], "block", ""),
    ("ev02_css_hidden_char_break.eml", "ev02", "evasion", 0, "malicious", "visual_lure", "zh",
     ["inline_css_hidden_char"], "block", ""),
    ("ev03_traditional_chinese.eml", "ev03", "evasion", 0, "malicious", "account_phishing", "zh-hant",
     ["common_traditional_forms"], "block", "常用繁体折叠已覆盖"),
    ("ev04_trusted_platform_lure.eml", "ev04", "evasion", 0, "malicious", "account_phishing", "zh",
     ["trusted_hosted_platform_lure"], "block", ""),
    ("ev05_userinfo_url.eml", "ev05", "evasion", 0, "malicious", "link_obfuscation", "zh",
     ["userinfo_url"], "block", ""),
    ("ev06_html_attachment_phish.eml", "ev06", "evasion", 0, "malicious", "credential_harvest", "zh",
     ["html_attachment_form"], "block", ""),
    ("ev07_dilution.eml", "ev07", "evasion", 0, "malicious", "structure_evasion", "zh",
     ["benign_dilution"], "block", ""),
    ("ev08_nested_rfc822.eml", "ev08", "evasion", 0, "malicious", "structure_evasion", "zh",
     ["nested_message_rfc822"], "block", ""),
    ("ev09_alt_clean_text.eml", "ev09", "evasion", 0, "malicious", "account_phishing", "zh",
     ["multipart_alternative_differential"], "block", ""),
    ("ev10_image_only_phish.eml", "ev10", "evasion", 0, "malicious", "visual_lure", "zh",
     ["image_only_body"], "block", ""),
    ("ev11_plain_contact_lure.eml", "ev11", "evasion", 0, "malicious", "bec", "zh",
     ["wechat_contact_lure"], "block", ""),
    ("ev12_rtlo_exe.eml", "ev12", "evasion", 0, "malicious", "malware_attachment", "zh",
     ["rtlo_filename_exe"], "block", ""),
    ("ev13_english_spaced.eml", "ev13", "evasion", 0, "malicious", "account_phishing", "en",
     ["letter_spaced_latin"], "block", ""),
    ("ev14_recipient_targeted_cn_account_lure.eml", "ev14", "evasion", 0, "malicious", "account_phishing", "zh",
     ["recipient_tokenized_url"], "block", ""),
    ("ev15_body_coverage_gap_2026_procedure_notice.eml", "ev15", "evasion", 0, "malicious",
     "coverage_gap_contract", "zh", ["missing_body_entity"], "regression_contract",
     "真实事件回放：正文实体未保留，断言不得给出内容安全结论"),

    # ---- round 1: encoding ----
    ("ev16_iso2022jp_body_lure.eml", "ev16", "evasion", 1, "malicious", "encoding_evasion", "ja",
     ["iso2022jp_body", "declared_charset_ignored_by_utf8_fastpath"], "block",
     "UTF-8 快速路径先于 charset 标签查找"),

    # ---- round 2: css/window ----
    ("ev17_class_hidden_pair_break.eml", "ev17", "evasion", 2, "malicious", "visual_lure", "zh",
     ["class_css_hidden", "two_letter_cjk_break"], "block", "三缺口链"),
    ("ev18_window_gap_lure.eml", "ev18", "evasion", 2, "malicious", "structure_evasion", "zh",
     ["2mib_window_gap"], "block", "场景检测器全文扫描 + fail-closed 兜住"),

    # ---- round 3: russian / fallback charset ----
    ("ev19_no_charset_ru_lure.eml", "ev19", "evasion", 3, "malicious", "encoding_evasion", "ru",
     ["undeclared_charset_cp1251", "gb18030_fallback_mojibake"], "block", ""),

    # ---- round 4: visual ----
    ("ev20_svg_vector_qr.eml", "ev20", "evasion", 4, "malicious", "quishing", "zh",
     ["svg_vector_qr"], "block", "SVG 矢量二维码，现已被 svg_vector_qr 类别覆盖"),
    ("ev21_image_text_lure.eml", "ev21", "evasion", 4, "malicious", "visual_lure", "zh",
     ["pixel_text_png", "benign_text_over_50"], "block", "ocr_unavailable fail-closed 兜住"),

    # ---- round 5: 20-vector sweep ----
    ("ev22_tab_entity_scheme.eml", "ev22", "evasion", 5, "malicious", "link_obfuscation", "zh",
     ["numeric_tab_entity_scheme"], "block", ""),
    ("ev23_named_tab_scheme.eml", "ev23", "evasion", 5, "malicious", "link_obfuscation", "zh",
     ["named_tab_entity_scheme"], "block", "实体白名单曾缺 &Tab;"),
    ("ev24_forged_auth_results.eml", "ev24", "evasion", 5, "malicious", "identity_spoof", "zh",
     ["forged_authentication_results", "forged_received"], "block", ""),
    ("ev25_base_href_relative.eml", "ev25", "evasion", 5, "malicious", "link_obfuscation", "zh",
     ["base_href_relative"], "block", ""),
    ("ev26_form_action_button.eml", "ev26", "evasion", 5, "malicious", "link_obfuscation", "zh",
     ["form_action_button"], "block", ""),
    ("ev27_svg_xlink_anchor.eml", "ev27", "evasion", 5, "malicious", "link_obfuscation", "zh",
     ["svg_xlink_href", "tab_entity"], "block", ""),
    ("ev28_attach_meta_refresh.eml", "ev28", "evasion", 5, "malicious", "redirect_attachment", "zh",
     ["attachment_meta_refresh_ip"], "block", ""),
    ("ev29_attach_js_form.eml", "ev29", "evasion", 5, "malicious", "credential_harvest", "zh",
     ["js_fragment_assembled_form"], "block", ""),
    ("ev30_url_shortcut_attach.eml", "ev30", "evasion", 5, "malicious", "redirect_attachment", "zh",
     ["internet_shortcut_url"], "block", ""),
    ("ev31_display_authority.eml", "ev31", "evasion", 5, "malicious", "identity_spoof", "zh",
     ["display_name_internal_authority"], "block", ""),
    ("ev32_latin_diacritics.eml", "ev32", "evasion", 5, "malicious", "account_phishing", "en",
     ["latin1_diacritics_keywords"], "block", ""),
    ("ev33_bec_paraphrase.eml", "ev33", "evasion", 5, "malicious", "bec", "en",
     ["bec_paraphrase"], "block", ""),
    ("ev34_folded_url_text.eml", "ev34", "evasion", 5, "malicious", "link_obfuscation", "zh",
     ["folded_url_plain_text"], "block", ""),
    ("ev35_attach_trusted_refresh.eml", "ev35", "evasion", 5, "malicious", "redirect_attachment", "zh",
     ["attachment_meta_refresh_trusted"], "block", ""),
    ("ev36_attach_hidden_pair.eml", "ev36", "evasion", 5, "malicious", "credential_harvest", "zh",
     ["attachment_class_hidden_pair"], "block", "附件管线曾缺 body 的二次扫描"),
    ("ev37_rfc2231_pct_filename.eml", "ev37", "evasion", 5, "malicious", "malware_attachment", "zh",
     ["rfc2231_percent_filename_exe"], "block", ""),
    ("ev38_ceo_homoglyph_lure.eml", "ev38", "evasion", 5, "malicious", "identity_spoof", "zh",
     ["ceo_localpart_homoglyph", "trust_lure"], "block", ""),
    ("ev39_image_contact_card.eml", "ev39", "evasion", 5, "malicious", "social_trust", "zh",
     ["image_contact_card"], "block", "fail-closed 兜住"),
    ("ev40_nested_alternative.eml", "ev40", "evasion", 5, "malicious", "structure_evasion", "zh",
     ["two_level_alternative_differential"], "block", ""),
    ("ev41_subject_only_lure.eml", "ev41", "evasion", 5, "malicious", "account_phishing", "zh",
     ["subject_only_lure"], "block", ""),

    # ---- round 6: dialect/identity/attachments ----
    ("ev42_rare_traditional_fold.eml", "ev42", "evasion", 6, "malicious", "language_coverage", "zh-hant",
     ["rare_traditional_forms"], "block", "帳戶/綁定/匯款/嚴重/緊急"),
    ("ev43_cantonese_lure.eml", "ev43", "evasion", 6, "malicious", "language_coverage", "zh-yue",
     ["cantonese_phrasing"], "block", "嘅/唔係/登入/停用"),
    ("ev44_crlf_folded_scheme.eml", "ev44", "evasion", 6, "malicious", "link_obfuscation", "zh",
     ["crlf_folded_scheme"], "block", ""),
    ("ev45_docm_attachment.eml", "ev45", "evasion", 6, "malicious", "malware_attachment", "zh",
     ["docm_macro"], "block", ""),
    ("ev46_iso_attachment.eml", "ev46", "evasion", 6, "malicious", "malware_attachment", "zh",
     ["iso_disk_image"], "block", ""),
    ("ev47_lnk_attachment.eml", "ev47", "evasion", 6, "malicious", "malware_attachment", "zh",
     ["lnk_shortcut"], "block", ""),
    ("ev48_latin_chunk_split.eml", "ev48", "evasion", 6, "malicious", "account_phishing", "en",
     ["latin_chunk_split"], "block", "compaction 门未被绕过"),
    ("ev49_vcard_url_lure.eml", "ev49", "evasion", 6, "malicious", "redirect_attachment", "zh",
     ["vcard_url_field"], "block", ""),
    ("ev50_ics_invite_lure.eml", "ev50", "evasion", 6, "malicious", "redirect_attachment", "zh",
     ["ics_url_summary_lure"], "block", ""),
    ("ev51_filename_lure.eml", "ev51", "evasion", 6, "malicious", "social_trust", "zh",
     ["filename_only_lure"], "block", ""),
    ("ev52_alt_title_keywords.eml", "ev52", "evasion", 6, "malicious", "visual_lure", "zh",
     ["alt_title_attribute_keywords"], "block", ""),
    ("ev53_fake_reply_thread.eml", "ev53", "evasion", 6, "malicious", "identity_spoof", "zh",
     ["fake_in_reply_to", "bare_domain"], "block", ""),
    ("ev54_greek_omicron_tld.eml", "ev54", "evasion", 6, "malicious", "link_obfuscation", "zh",
     ["greek_omicron_tld_bare_domain"], "block", ""),
    ("ev55_mailto_cred_form.eml", "ev55", "evasion", 6, "malicious", "credential_harvest", "zh",
     ["mailto_form_password"], "block", ""),
    ("ev56_chain_alt_svgqr.eml", "ev56", "evasion", 6, "malicious", "quishing", "zh",
     ["alt_keywords", "svg_qr", "chain"], "block", ""),
    ("ev57_chain_filename_refresh.eml", "ev57", "evasion", 6, "malicious", "redirect_attachment", "zh",
     ["filename_lure", "meta_refresh", "chain"], "block", ""),
    ("ev58_chain_canto_greek_form.eml", "ev58", "evasion", 6, "malicious", "account_phishing", "zh-yue",
     ["cantonese", "greek_tld", "form_button", "chain"], "block", ""),
    ("ev59_chain_ics_ceo.eml", "ev59", "evasion", 6, "malicious", "identity_spoof", "zh",
     ["ics_lure", "ceo_organizer", "chain"], "block", ""),
    ("ev60_chain_attach_stack.eml", "ev60", "evasion", 6, "malicious", "credential_harvest", "zh",
     ["attachment_class_hidden", "named_tab_entity", "chain"], "block", ""),
    ("ev61_chain_traditional_base.eml", "ev61", "evasion", 6, "malicious", "link_obfuscation", "zh-hant",
     ["rare_traditional", "base_href", "chain"], "block", ""),

    # ---- round 7: sanitizer-inversion / i18n / TOAD ----
    ("ev62_banner_prefix_lure.eml", "ev62", "evasion", 7, "malicious", "sanitizer_evasion", "zh",
     ["gateway_banner_prefix_inversion"], "block", "被 gateway_pre_classified 反杀"),
    ("ev63_autoreply_prefix_lure.eml", "ev63", "evasion", 7, "malicious", "sanitizer_evasion", "zh",
     ["auto_reply_prefix_inversion"], "block", ""),
    ("ev64_vietnamese_lure.eml", "ev64", "evasion", 7, "malicious", "language_coverage", "vi",
     ["vietnamese_lure"], "block", "content 零命中，靠 ip_action_target 兜底"),
    ("ev65_thai_lure.eml", "ev65", "evasion", 7, "malicious", "language_coverage", "th",
     ["thai_lure"], "block", "同上"),
    ("ev66_indonesian_lure.eml", "ev66", "evasion", 7, "malicious", "language_coverage", "id",
     ["indonesian_lure"], "block", "同上"),
    ("ev67_yao_phone.eml", "ev67", "evasion", 7, "malicious", "toad", "zh",
     ["yao_digit_phone"], "block", "幺→1 映射缺失，正文关键词先命中"),
    ("ev68_liang_phone.eml", "ev68", "evasion", 7, "malicious", "toad", "zh",
     ["liang_digit_phone"], "block", "两→2 映射缺失"),
    ("ev69_giftcard_bec.eml", "ev69", "evasion", 7, "malicious", "bec", "zh",
     ["giftcard_purchase_paraphrase"], "block", ""),
    ("ev70_tax_rebate_paraphrase.eml", "ev70", "evasion", 7, "malicious", "subsidy_fraud", "zh",
     ["tax_rebate_paraphrase", "bare_domain"], "block", ""),
    ("ev71_pii_harvest_reply.eml", "ev71", "evasion", 7, "malicious", "pii_harvest", "zh",
     ["reply_pii_harvest_id_face"], "block", ""),
    ("ev72_trusted_open_redirect.eml", "ev72", "evasion", 7, "malicious", "link_obfuscation", "zh",
     ["trusted_host_open_redirect_param"], "block", "redirect_url 仅 Low"),
    ("ev73_interlinear_break.eml", "ev73", "evasion", 7, "malicious", "account_phishing", "zh",
     ["interlinear_annotation_chars"], "block", ""),
    ("ev74_js_chunked_qr.eml", "ev74", "evasion", 7, "malicious", "quishing", "zh",
     ["js_chunked_datauri_qr"], "block", "html_scan data_uri+xss 兜住"),
    ("ev75_inverted_qr_attach.eml", "ev75", "evasion", 7, "malicious", "quishing", "zh",
     ["inverted_color_qr_png"], "block", "fail-closed 兜住"),
    ("ev76_paraphrase_no_keyword.eml", "ev76", "evasion", 7, "malicious", "social_trust", "zh",
     ["paraphrase_no_stock_keywords"], "block", ""),
    ("ev77_display_internal_domain.eml", "ev77", "evasion", 7, "malicious", "identity_spoof", "zh",
     ["display_name_internal_domain"], "block", ""),
    ("ev78_100part_lure_tail.eml", "ev78", "evasion", 7, "malicious", "structure_evasion", "zh",
     ["hundred_part_tail_lure"], "block", ""),
    ("ev79_rtf_attach_lure.eml", "ev79", "evasion", 7, "malicious", "credential_harvest", "en",
     ["rtf_attachment_lure"], "block", ""),
    ("ev80_chain_banner_yao.eml", "ev80", "evasion", 7, "malicious", "sanitizer_evasion", "zh",
     ["banner_inversion", "yao_phone", "chain"], "block", "横幅防护反杀"),
    ("ev81_chain_vi_redirect.eml", "ev81", "evasion", 7, "malicious", "account_phishing", "vi",
     ["vietnamese", "open_redirect", "fake_reply", "chain"], "block", ""),

    # ---- incidents ----
    ("inc01_account_security_root_token.eml", "inc01", "incident", "incident", "malicious",
     "account_phishing", "zh", ["real_incident_root_token"], "block", "真实事件回放"),
    ("inc02_obfuscated_adult_domain.eml", "inc02", "incident", "incident", "malicious",
     "link_obfuscation", "zh", ["real_incident_obfuscated_domain"], "block", "真实事件回放"),
    ("inc03_invoice_wechat_homophone.eml", "inc03", "incident", "incident", "malicious",
     "bec", "zh", ["real_incident_invoice_homophone"], "block", "真实事件回放"),
    ("inc04_fragmented_context_invoice.eml", "inc04", "incident", "incident", "malicious",
     "bec", "zh", ["fragmented_invoice_context", "wechat_contact"], "block", "事件回放补充样本"),
    ("inc05_japanese_apple_payment_update.eml", "inc05", "incident", "incident", "malicious",
     "account_phishing", "ja", ["apple_payment_update", "external_link"], "block", "事件回放补充样本"),

    # ---- ham (benign hard negatives; harness 不读子目录) ----
    ("ham/ham01_meeting_notice.eml", "ham01", "ham", "ham", "benign", "ham_business", "zh",
     ["internal_meeting"], "deliver", ""),
    ("ham/ham02_weekly_report.eml", "ham02", "ham", "ham", "benign", "ham_business", "zh",
     ["project_report"], "deliver", ""),
    ("ham/ham03_hr_policy.eml", "ham03", "ham", "ham", "benign", "ham_business", "zh",
     ["internal_portal_link"], "deliver", "内网链接负样本"),
    ("ham/ham04_vendor_invoice_notice.eml", "ham04", "ham", "ham", "benign", "ham_business", "zh",
     ["legit_invoice_notice"], "deliver", "发票词汇硬负样本"),
    ("ham/ham05_it_maintenance.eml", "ham05", "ham", "ham", "benign", "ham_business", "zh",
     ["legit_maintenance_window", "internal_link"], "deliver", "维护词汇硬负样本"),
    ("ham/ham06_family_trip.eml", "ham06", "ham", "ham", "benign", "ham_personal", "zh",
     ["personal_family"], "deliver", ""),
    ("ham/ham07_conference_cfp.eml", "ham07", "ham", "ham", "benign", "ham_business", "en",
     ["external_cfp_deadline_link"], "deliver", "英文外部链接+截止期硬负样本"),
    ("ham/ham08_parcel_pickup.eml", "ham08", "ham", "ham", "benign", "ham_business", "zh",
     ["pickup_code_notice"], "deliver", "取件码形似验证码硬负样本"),
    ("ham/ham09_gateway_newsletter.eml", "ham09", "ham", "ham", "benign", "ham_business", "zh",
     ["banner_prefixed_newsletter", "external_link"], "deliver", "带网关横幅+退订硬负样本"),
    ("ham/ham10_job_application.eml", "ham10", "ham", "ham", "benign", "ham_business", "zh",
     ["resume_attachment_context"], "deliver", ""),
    ("ham/ham11_bank_statement_ready.eml", "ham11", "ham", "ham", "benign", "ham_business", "zh",
     ["bank_statement_no_link"], "deliver", "金融词汇硬负样本，正文显式声明无链接"),
    ("ham/ham12_own_verification_code.eml", "ham12", "ham", "ham", "benign", "ham_business", "zh",
     ["own_verification_code"], "deliver", "最强硬负样本：验证码词汇，含上下文线索（统一认证平台）"),
]


def main() -> int:
    entries = []
    for (file, cid, group, rnd, label, family, lang, tech, expected, note) in TABLE:
        status = "not_in_harness" if group == "ham" else (
            "delivered" if file in DELIVERED_NOW else "blocked")
        entries.append({
            "file": file,
            "case_id": cid,
            "group": group,
            "round": rnd,
            "label": label,
            "family": family,
            "language": lang,
            "techniques": tech,
            "expected": expected,
            "engine_status": status,
            "open": expected == "block" and status == "delivered",
            "note": note,
        })

    # ---- validation ----
    labeled = {e["file"] for e in entries}
    on_disk = set()
    for root, _dirs, files in os.walk(HERE):
        if ".git" in root:
            continue
        for f in files:
            if f.endswith(".eml"):
                rel = os.path.relpath(os.path.join(root, f), HERE)
                if not rel.startswith(("assets", "synth")):
                    on_disk.add(rel)
    missing = on_disk - labeled
    extra = labeled - on_disk
    if missing or extra:
        print("VALIDATION FAILED")
        print("  on disk but unlabeled:", sorted(missing))
        print("  labeled but missing on disk:", sorted(extra))
        return 1

    doc = {
        "meta": {
            "version": 1,
            "generated": "2026-08-24",
            "corpus": "vigilyx red-team EML corpus",
            "engine_status_ref": "last complete redteam_harness run on remote builder, 2026-08-24 (round-7 state)",
            "expected_semantics": {
                "block": "恶意样本，引擎必须隔离（quarantine threshold=Medium）",
                "deliver": "良性 ham，引擎必须放行",
                "regression_contract": "覆盖缺口回归契约（不得给出内容安全结论）",
            },
            "families": FAMILIES,
        },
        "cases": entries,
    }
    out = os.path.join(HERE, "labels.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)

    manifest_out = os.path.join(HERE, "capability_manifest.json")
    with open(manifest_out, "w", encoding="utf-8") as f:
        json.dump(build_capability_manifest(entries), f, ensure_ascii=False, indent=2)
        f.write("\n")

    # ---- stats ----
    n = len(entries)
    mal = sum(1 for e in entries if e["label"] == "malicious")
    ham = n - mal
    open_now = [e["case_id"] for e in entries if e["open"]]
    langs = {}
    fams = {}
    for e in entries:
        langs[e["language"]] = langs.get(e["language"], 0) + 1
        fams[e["family"]] = fams.get(e["family"], 0) + 1
    print(f"labels.json written: {n} cases (malicious={mal}, benign={ham})")
    print(f"currently open (engine delivers, fix pending): {len(open_now)} -> {', '.join(open_now)}")
    print("languages:", dict(sorted(langs.items(), key=lambda kv: -kv[1])))
    print("families:", dict(sorted(fams.items(), key=lambda kv: -kv[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
