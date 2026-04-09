from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'shared' / 'schemas' / 'keyword_overrides_seed.json'
TARGET_PER_CATEGORY = 1280


def normalize(phrase: str) -> str:
    return ' '.join(phrase.strip().lower().split())


def take_unique(candidates: Iterable[str], target: int, excluded: set[str]) -> list[str]:
    result: list[str] = []
    seen = set(excluded)
    for candidate in candidates:
        normalized = normalize(candidate)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
        if len(result) >= target:
            return result
    raise RuntimeError(f'only generated {len(result)} items, need {target}')


def phishing_candidates() -> Iterable[str]:
    brands_en = [
        'microsoft 365', 'outlook web access', 'exchange online', 'sharepoint online',
        'onedrive business', 'docusign secure', 'adobe sign', 'google workspace',
        'dropbox business', 'okta verify', 'vpn portal', 'payroll portal',
        'benefits center', 'banking portal', 'vendor portal', 'shipping desk',
        'tax filing center', 'customs clearance desk', 'procurement portal', 'secure mail gateway',
    ]
    actions_en = [
        'password reset required', 'mailbox verification required', 'secure login validation',
        'unusual sign in review', 'account recovery confirmation', 'beneficiary validation request',
        'invoice release pending', 'document review pending', 'payment exception alert',
        'session unlock required', 'security hold removal', 'two factor sync required',
        'direct deposit update review', 'identity proof recheck',
    ]
    urgencies_en = [
        'immediate action required', 'expires today', 'final reminder', 'within 2 hours',
        'before account suspension', 'to avoid payment delay',
    ]
    for brand in brands_en:
        for action in actions_en:
            yield f'{brand} {action}'
            for urgency in urgencies_en:
                yield f'{brand} {action} {urgency}'
                yield f'{urgency} {brand} {action}'

    services_zh = [
        '微软365', '邮箱中心', '企业邮箱', '财务共享平台', '薪资系统', '报销平台',
        '税务服务', '海关平台', '采购门户', '供应商平台', '快递中心', '安全网关',
        '文档签署中心', '账号服务中心', '网银服务', '人事系统',
    ]
    actions_zh = [
        '密码重置通知', '邮箱验证失败', '登录状态异常复核', '账户恢复确认', '受益人信息复核',
        '付款异常处理', '发票下载待确认', '签署文件待查收', '双因子同步通知',
        '账号冻结解除申请', '安全策略更新确认', '身份核验复审',
    ]
    urgencies_zh = ['请立即处理', '今日到期', '最终提醒', '两小时内完成', '否则暂停访问', '避免付款延迟']
    for service in services_zh:
        for action in actions_zh:
            yield f'{service}{action}'
            for urgency in urgencies_zh:
                yield f'{service}{action}{urgency}'
                yield f'{urgency}{service}{action}'


def weak_phishing_candidates() -> Iterable[str]:
    objects_en = [
        'invoice copy', 'payment summary', 'vendor statement', 'shared file', 'project brief',
        'meeting minutes', 'policy acknowledgement', 'expense report', 'direct deposit form',
        'benefit enrollment', 'security questionnaire', 'access request', 'purchase order',
        'delivery notice', 'compliance packet', 'account profile', 'mailbox quota report',
        'device enrollment', 'service ticket', 'contract amendment',
    ]
    verbs_en = [
        'please review', 'please confirm', 'reply with approval', 'signature requested',
        'acknowledgement needed', 'updated copy attached', 'shared for validation',
        'waiting for confirmation', 'reconciliation needed', 'resubmission requested',
        'secure view available', 'follow up pending',
    ]
    contexts_en = [
        'before cutoff', 'for today processing', 'for finance reconciliation',
        'for payroll cycle', 'for month end close', 'through the secure portal',
        'in the attached document', 'to avoid delay',
    ]
    for obj in objects_en:
        for verb in verbs_en:
            yield f'{obj} {verb}'
            for context in contexts_en:
                yield f'{obj} {verb} {context}'

    objects_zh = [
        '付款摘要', '供应商对账单', '共享文件', '项目简报', '会议纪要', '制度确认单',
        '报销单据', '工资卡变更表', '福利登记表', '安全问卷', '访问申请', '采购订单',
        '交付通知', '合规资料包', '账户资料', '邮箱容量报告', '设备登记单', '服务工单',
    ]
    verbs_zh = [
        '请查收', '请确认', '请审批', '需要签收', '需要回执', '附件已更新',
        '等待核对', '请重新提交', '请及时回复', '请补充资料',
    ]
    contexts_zh = ['用于财务核对', '用于月末结账', '用于本周处理', '通过安全门户查看', '避免流程延误', '请在附件中核验']
    for obj in objects_zh:
        for verb in verbs_zh:
            yield f'{obj}{verb}'
            for context in contexts_zh:
                yield f'{obj}{verb}{context}'


def bec_candidates() -> Iterable[str]:
    roles_en = [
        'chief executive', 'chief financial officer', 'finance director', 'regional controller',
        'managing director', 'operations head', 'founder office', 'board representative',
        'treasury manager', 'country manager', 'general counsel', 'vice president finance',
    ]
    actions_en = [
        'approve a same day wire', 'keep this transfer confidential', 'change the beneficiary details',
        'send the remittance proof only to me', 'purchase gift cards before the meeting',
        'settle the attached invoice quietly', 'hold questions until the payment clears',
        'process the off cycle payroll transfer', 'move the funds before bank cutoff',
        'reply from your private mailbox only', 'clear this payment outside the normal chain',
        'update the vendor bank account immediately',
    ]
    modifiers_en = [
        'before lunch', 'without calling the requester', 'do not copy anyone else',
        'this stays between us', 'the board is waiting', 'the seller is on standby',
    ]
    for role in roles_en:
        for action in actions_en:
            yield f'{role} asked you to {action}'
            for modifier in modifiers_en:
                yield f'{role} asked you to {action} {modifier}'

    roles_zh = ['董事长', '总经理', '首席财务官', '财务总监', '运营负责人', '区域负责人', '老板办公室', '资金主管']
    actions_zh = [
        '马上安排加急转账', '不要在群里讨论这笔付款', '立即修改收款账户信息', '只把回单发给我本人',
        '先购买礼品卡再统一报销', '绕过常规审批先付款', '今天下班前完成汇款', '不要回拨电话确认',
        '按新账户支付尾款', '暂时不要通知财务共享中心',
    ]
    modifiers_zh = ['属于保密项目', '董事会正在等待', '供应商催得很急', '银行截止时间快到了', '只限你处理']
    for role in roles_zh:
        for action in actions_zh:
            yield f'{role}要求你{action}'
            for modifier in modifiers_zh:
                yield f'{role}要求你{action}{modifier}'


def internal_authority_candidates() -> Iterable[str]:
    departments_zh = [
        '集团办公室', '行政中心', '财务共享中心', '人力资源部', '信息安全部', '采购管理部',
        '审计合规部', '法务部', '总经办', '运营管理部', '品牌公关部', '客户成功部',
        '技术支持中心', '董事会秘书处', '纪检监察室',
    ]
    notice_types_zh = [
        '制度更新公告', '强制培训通知', '审批流程调整通知', '资产盘点通知', '差旅报销新规',
        '付款审批要求', '账号权限复核', '办公终端升级通知', '邮件签名规范', '文件归档要求',
        '供应商准入通知', '绩效填报通知',
    ]
    actions_zh = ['请全员知悉', '请立即执行', '请主管签收', '请部门确认', '请在今日完成', '请勿外传']
    for dept in departments_zh:
        for notice in notice_types_zh:
            yield f'{dept}{notice}'
            for action in actions_zh:
                yield f'{dept}{notice}{action}'

    departments_en = [
        'finance operations', 'human resources', 'information security office', 'procurement office',
        'compliance office', 'legal affairs', 'executive office', 'board secretary office',
    ]
    notice_types_en = [
        'mandatory acknowledgement notice', 'policy update bulletin', 'approval workflow change',
        'access review notice', 'asset inventory notice', 'signature standard notice',
        'supplier onboarding bulletin', 'device hardening notice',
    ]
    actions_en = ['for all staff', 'for department heads', 'effective immediately', 'reply for acknowledgement']
    for dept in departments_en:
        for notice in notice_types_en:
            yield f'{dept} {notice}'
            for action in actions_en:
                yield f'{dept} {notice} {action}'


def build_seed() -> dict[str, dict[str, list[str]]]:
    excluded = {
        'phishing_keywords': {
            '密码', '紧急', '汇款', 'password', 'urgent', 'wire transfer', '立即行动', '账户异常',
            '安全验证', '点击链接', 'suspended', 'unauthorized', 'immediately', '补贴', '年终补贴',
            '退税', '补偿金', '汇算', '不予受理', '自助申报', '办理领取', '账户冻结', '帐户冻结',
            '账户关闭', '帐户关闭', '账户将于', '帐户将于', '异常登录', '身份过期', '重新认证',
            '限时处理', '账号停用', '帐号停用', '安全升级', '解除限制', '非活动状态',
            'your account will be closed', 'account will be closed', 'account closure', '包裹滞留',
            '清关费', '快递异常', '海关扣押', '普票', '普通发票', '增值税发票', '正规发票',
            '代开发票', '加微信', '微信号', '微信转账', 'addqq', 'update your account', 'click here',
            'act now', 'limited time', 'verify your identity', 'account suspended', 'unusual activity',
            'security alert', 'login attempt', 'reset your password', 'payment failed', 'billing update',
            'deactivate', 'check out my profile', 'check my profile', 'my photos', 'getting to know you',
            'get to know each other', 'sign up to join', 'sign up to see', 'join to see',
            "i'm really interested", 'interested in you', 'my private photos', 'private pictures',
            'click my profile', 'visit my profile', 'my dating profile', 'lonely and looking', "let's meet",
            'want to meet', 'you have won', 'congratulations you', "you've been selected", 'claim your prize',
            'lottery winner', 'million dollars', 'guaranteed returns', 'risk free investment',
            'double your money', 'crypto opportunity', 'bitcoin investment', 'i recorded you',
            'recorded you masturbating', 'recorded footage of you', 'i have your password',
            'i know your password', 'infected by my malware', 'device was infected', 'camera was activated',
            'pay in bitcoin', 'pay exactly', 'send bitcoin', 'btc wallet', 'bitcoin wallet',
            'my bitcoin address', 'my wallet address', 'share the video', 'publish your files',
            'days to complete the payment', '勒索', '赎金', '比特币', 'bitcoin ransom',
            'your files are encrypted', 'pay the ransom', 'all your files', 'decrypt your files',
        },
        'weak_phishing_keywords': {'verify', 'confirm', 'expire', 'invoice', '发放', '申报', '核对', '逾期', '领取'},
        'bec_phrases': {
            'ceo', 'cfo', 'chief executive', 'chief financial', 'wire the funds', 'transfer the amount',
            'confidential request', 'do not discuss', 'keep this between us', 'urgent payment',
            '总经理', '财务总监', '紧急转账', '保密处理', '行政发布', '财务部通知', '人事部通知',
            '公司通告', '勿需回复', '无需回复', '不得外泄', '核对办理', '提交申报材料',
            '尽快处理', '立即办理', '马上转账', '今天必须完成',
        },
        'internal_authority_phrases': {
            '行政发布', '财务部', '人事部', '综合部', '办公室', 'financial department', 'hr department',
            'admin department', '本通知由', '公司通告', '集团通知',
        },
    }

    phishing_keywords = take_unique(phishing_candidates(), TARGET_PER_CATEGORY, excluded['phishing_keywords'])
    weak_phishing_keywords = take_unique(weak_phishing_candidates(), TARGET_PER_CATEGORY, excluded['weak_phishing_keywords'])
    bec_phrases = take_unique(bec_candidates(), TARGET_PER_CATEGORY, excluded['bec_phrases'])
    internal_authority_phrases = take_unique(internal_authority_candidates(), TARGET_PER_CATEGORY, excluded['internal_authority_phrases'])

    return {
        'phishing_keywords': {'added': phishing_keywords, 'removed': []},
        'weak_phishing_keywords': {'added': weak_phishing_keywords, 'removed': []},
        'bec_phrases': {'added': bec_phrases, 'removed': []},
        'internal_authority_phrases': {'added': internal_authority_phrases, 'removed': []},
    }


def main() -> None:
    seed = build_seed()
    OUT.write_text(json.dumps(seed, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    counts = {key: len(value['added']) for key, value in seed.items()}
    print(json.dumps({'output': str(OUT), 'counts': counts}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
