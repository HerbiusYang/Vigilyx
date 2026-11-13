#!/usr/bin/env python3
"""Batch 27: social/account lures + real account notices."""
import base64, json, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LABELS = []
def W(n, raw): open(os.path.join(ROOT, "synth", n), "wb").write(raw)
def HD(disp, frm, to, subj):
    b = base64.b64encode(disp.encode()).decode()
    return (f"From: =?utf-8?B?{b}?= <{frm}>\r\nTo: {to}\r\n"
            f"Date: Sun, 20 Sep 2026 09:{10+len(LABELS)%49:02d}:00 +0800\r\n"
            f"Message-ID: <{len(LABELS):04d}-b27@synth.example>\r\n"
            f"Subject: {subj}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
def E(n, raw, label, family, tech, note=""):
    W(n, raw if isinstance(raw, bytes) else raw.encode())
    LABELS.append({"file": f"synth/{n}", "case_id": n[:-4], "label": label,
        "family": family, "language": "zh", "techniques": tech,
        "expected": "block" if label == "malicious" else "deliver",
        "engine_status": "not_evaluated", "synthetic": True, "batch": 27, "note": note})

E("mal_0441_wx_assist.eml", HD("微信安全", "wx@assist-reg8.example", "me@personal.example", "辅助注册邀请（老用户）")
  + "协助链接：https://wx-fz8.example.vip/a\r\n（微信扫码授权）\r\n",
  "malicious", "account_phishing", ["wechat_assist_reg"], "辅助注册灰产")
E("mal_0442_qq_recycle.eml", HD("QQ安全", "qq@num-recycle8.example", "me@personal.example", "长期未登录将回收靓号")
  + "保号登记：https://qq-bh8.example.info/k\r\n（QQ号+密码）\r\n",
  "malicious", "credential_harvest", ["qq_recycle_password"], "回收靓号收密码")
E("mal_0443_game_recover.eml", HD("游戏客服", "kf@game-recover8.example", "me@personal.example", "账号申诉补充材料")
  + "补充：https://kf-bc8.example.info/s\r\n（游戏账号+密码+充值记录截图）\r\n",
  "malicious", "credential_harvest", ["game_appeal_password"], "申诉收密码")
E("mal_0444_like_job.eml",
  HD("点赞兼职", "dz@like-job8.example", "student@mail.example", "点赞返现（日结 80）")
  + "报名需交 99 保证金：https://dz-bm8.example.vip/j\r\n",
  "malicious", "pii_harvest", ["auto"], "b27fix")
E("mal_0445_kol_sign.eml", HD("MCN", "mcn@kol-sign8.example", "me@personal.example", "素人签约（保底 3000）")
  + "签约表：https://mcn-qy8.example.vip/s\r\n（身份证+人脸）\r\n",
  "malicious", "pii_harvest", ["kol_sign_face"], "MCN 签约收人脸")
E("mal_0446_fan_group.eml", HD("粉丝群", "fs@fan-group8.example", "me@personal.example", "偶像官方群（收费内测）")
  + "入群费 99：https://fs-rq8.example.vip/j\r\n",
  "malicious", "social_trust", ["paid_fan_group"], "收费粉丝群")
E("mal_0447_boost.eml", HD("代练", "dl@boost-svc8.example", "me@personal.example", "代练报价（赛季末）")
  + "下单需提供账号密码：https://dl-xd8.example.info/o\r\n",
  "malicious", "credential_harvest", ["boosting_password"], "代练收账号")
E("mal_0448_sms_forward.eml", HD("短信助手", "dx@sms-fwd8.example", "me@personal.example", "短信转发托管（月付 200）")
  + "绑定：https://dx-tg8.example.vip/b\r\n（手机号+SIM 卡序列号）\r\n",
  "malicious", "pii_harvest", ["sms_forwarding"], "SIM 序列收集（换卡前奏）")
E("mal_0449_id_auth.eml", HD("实名平台", "sm@id-auth8.example", "me@personal.example", "二次实名核验（新规）")
  + "核验：https://sm-hy8.example.info/v\r\n（身份证+人脸+手机服务密码）\r\n",
  "malicious", "pii_harvest", ["reauth_full"], "二次实名收全套")
E("mal_0450_account_merge2.eml", HD("账号中心", "zh@acct-merge8.example", "me@personal.example", "社区账号合并通知")
  + "合并需主账号密码：https://zh-hb8.example.info/m\r\n",
  "malicious", "credential_harvest", ["account_merge_password"], "合并收主账号密码")
E("mal_0451_stream_share.eml", HD("流媒体", "lm@stream-share8.example", "me@personal.example", "拼车会员（4 人位）")
  + "拼车需主账号授权码：https://lm-pc8.example.vip/s\r\n",
  "malicious", "credential_harvest", ["streaming_carshare_code"], "拼车收授权码")
E("mal_0452_cloud_game.eml", HD("云游戏", "yy@cloudgame8.example", "me@personal.example", "云游戏限免资格")
  + "领取：https://yy-lq8.example.info/g\r\n（平台账号密码）\r\n",
  "malicious", "credential_harvest", ["cloud_game_password"], "限免收账密")
E("mal_0453_nft_mint2.eml", HD("数字藏品", "sz@nft-mint8.example", "me@personal.example", "空投盲盒（隐藏款）")
  + "铸造：https://sz-zz8.example.vip/m\r\n（钱包连接）\r\n",
  "malicious", "account_phishing", ["nft_wallet_connect"], "钱包连接钓鱼")
E("mal_0454_vip_expire3.eml", HD("会员", "hy@vip-expire8.example", "me@personal.example", "会员今日到期（积分作废）")
  + "续期：https://hy-xq8.example.vip/r\r\n",
  "malicious", "account_phishing", ["vip_expiry2"], "")
E("mal_0455_group_admin.eml", HD("群管理", "qg@group-admin8.example", "me@personal.example", "您被任命为群管理员")
  + "接任需验证：https://qg-jr8.example.info/a\r\n",
  "malicious", "account_phishing", ["group_admin_lure"], "")
E("mal_0456_verify_badge.eml", HD("认证中心", "rz@badge-svc8.example", "me@personal.example", "蓝V认证到期")
  + "续认证：https://rz-x8.example.vip/v\r\n（账号密码+营业执照）\r\n",
  "malicious", "credential_harvest", ["badge_renew_docs"], "蓝V续认证")
E("mal_0457_data_move2.eml", HD("换机助手", "hj@phone-migrate8.example", "me@personal.example", "旧机数据迁移（云端中转）")
  + "中转授权：https://hj-sq8.example.info/a\r\n（云账号密码）\r\n",
  "malicious", "credential_harvest", ["phone_migrate_password"], "换机收云密码")
E("mal_0458_loc_share.eml",
  HD("家人共享", "jr@family-share8.example", "me@personal.example", "家人共享组邀请（位置共享）")
  + "接受并开启位置共享：https://jr-js8.example.info/a\r\n",
  "malicious", "pii_harvest", ["auto"], "b27fix")
E("mal_0459_avatar_nft.eml", HD("头像馆", "tx@avatar-svc8.example", "me@personal.example", "专属头像生成（AI）")
  + "生成需授权相册：https://tx-sc8.example.vip/p\r\n",
  "malicious", "pii_harvest", ["avatar_album_auth"], "诱导相册授权")
E("mal_0460_login_probe.eml", HD("账号安全", "aq@login-probe8.example", "me@personal.example", "检测到 3 次登录尝试失败")
  + "如非本人请锁定并改密：https://aq-suoding8.example.info/l\r\n",
  "malicious", "credential_harvest", ["failed_login_lock"], "假登录锁定")

E("ham_0401_wx_real.eml", HD("微信安全中心", "weixin@wechat.example", "me@personal.example", "账号安全提醒")
  + "检测到异地登录已下线。请勿向任何人提供验证码。\r\n",
  "benign", "ham_personal", ["wechat_real_alert"], "真安全提醒无链接")
E("ham_0402_qq_real.eml", HD("QQ安全", "security@qq.example", "me@personal.example", "密码修改成功")
  + "如非本人请通过官方渠道申诉。\r\n",
  "benign", "ham_personal", ["qq_real_pwchange"], "")
E("ham_0403_game_real2.eml", HD("游戏运营", "gm@game.example", "me@personal.example", "赛季奖励已发放")
  + "客户端领取。\r\n",
  "benign", "ham_personal", ["game_real_reward"], "")
E("ham_0404_family_real.eml", HD("家人共享", "jr@iCloud.example", "me@personal.example", "家人共享组变更")
  + "成员调整已在设备设置生效。\r\n",
  "benign", "ham_personal", ["family_real_change"], "与位置诱导同形")
E("ham_0405_stream_real.eml", HD("流媒体", "sv@stream.example", "me@personal.example", "新设备登录")
  + "如非本人请在官网（自行输入网址）修改密码。\r\n",
  "benign", "ham_personal", ["stream_real_login"], "")
E("ham_0406_cloud_real.eml", HD("云服务", "cl@cloud.example", "me@personal.example", "相册回忆生成")
  + "App 内查看。\r\n",
  "benign", "ham_personal", ["cloud_real_memory"], "")
E("ham_0407_backup_real2.eml",
  HD("云服务", "cl@cloud.example", "me@personal.example", "自动备份完成（昨晚）")
  + "相册 2.1G 已备份。\r\n",
  "benign", "ham_personal", ["auto"], "b27fix")
E("ham_0408_update_real.eml", HD("系统更新", "gx@os.example", "me@personal.example", "新版本可用")
  + "设置内更新，本邮件无链接。\r\n",
  "benign", "ham_personal", ["os_real_update"], "")
E("ham_0409_social_digest.eml", HD("社区", "sq@forum.example", "me@personal.example", "本周你的帖子获 32 赞")
  + "站点内查看。\r\n",
  "benign", "ham_personal", ["forum_real_digest2"], "")
E("ham_0410_follow.eml", HD("社区", "sq@forum.example", "me@personal.example", "3 位新粉丝")
  + "站点内查看。\r\n",
  "benign", "ham_personal", ["follow_real"], "")
E("ham_0411_mod.eml", HD("社区", "sq@forum.example", "me@personal.example", "您的回答被选为最佳")
  + "感谢贡献。\r\n",
  "benign", "ham_personal", ["best_answer_real"], "")
E("ham_0412_wiki_edit.eml", HD("百科", "bk@wiki.example", "me@personal.example", "您的编辑已通过审核")
  + "词条已更新。\r\n",
  "benign", "ham_personal", ["wiki_edit_real"], "")
E("ham_0413_dev_forums.eml", HD("Stack Overflow", "noreply@so.example", "dev@corp.internal", "Your answer was upvoted (15)")
  + "Thanks for contributing.\r\n",
  "benign", "ham_business", ["so_real_upvote"], "", )
E("ham_0414_npm_publish.eml", HD("npm", "notify@npmjs.example", "dev@corp.internal", "Package published: tower-lsp@0.4.1")
  + "Live on the registry.\r\n",
  "benign", "ham_business", ["npm_real_publish"], "")
E("ham_0415_docker_pull.eml", HD("Docker", "notify@docker.example", "dev@corp.internal", "Image pulled 1k+ times")
  + "Milestone notification.\r\n",
  "benign", "ham_business", ["docker_real_stats"], "")
E("ham_0416_cert_alert_real.eml", HD("监控", "jk@uptime.example", "webmaster@corp.internal", "SSL 15 天后到期")
  + "自动续期进行中，无需操作。\r\n",
  "benign", "ham_business", ["cert_monitor_real"], "")
E("ham_0417_domain_real2.eml", HD("注册商", "sv@registrar.example", "webmaster@corp.internal", "域名已自动续费")
  + "扣费凭证见账单。\r\n",
  "benign", "ham_business", ["domain_auto_real"], "")
E("ham_0418_gitlab_pipe.eml", HD("GitLab", "notify@gitlab.example", "dev@corp.internal", "Pipeline passed: release/1.9.6")
  + "All stages green.\r\n",
  "benign", "ham_business", ["gitlab_real_pipe"], "")
E("ham_0419_codefactor.eml", HD("CodeFactor", "noreply@codefactor.example", "dev@corp.internal", "New issue in gateway/src")
  + "See the dashboard (existing session).\r\n",
  "benign", "ham_business", ["codefactor_real"], "")
E("ham_0420_codecov.eml", HD("Codecov", "noreply@codecov.example", "dev@corp.internal", "Coverage +0.8% (gateway)")
  + "Report attached to commit.\r\n",
  "benign", "ham_business", ["codecov_real"], "")

with open(os.path.join(ROOT, "synth", "labels.jsonl"), "a", encoding="utf-8") as f:
    for e in LABELS: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(f"batch27 written: {len(LABELS)} samples")
