#!/usr/bin/env python3
"""
VirusTotal Scanner - supports URL and IP lookups (optimized)
Intercept VT internal API responses with a headless Playwright browser and extract detection results

Install dependencies:
    pip3 install playwright -i https://pypi.tuna.tsinghua.edu.cn/simple
    playwright install chromium

Usage:
    python3 vt_scan.py <URL>                    # Look up a URL
    python3 vt_scan.py --ip <IP>                # Look up an IP address
    python3 vt_scan.py <URL1> <URL2> ...        # Bulk lookup (auto-detect URL/IP)
    python3 vt_scan.py --hash <VT_HASH>         # Pass a VT hash directly
    python3 vt_scan.py -f targets.txt           # Read from a file (auto-detect)
    python3 vt_scan.py                          # Interactive mode

Examples:
    python3 vt_scan.py http://xred.mooo.com/
    python3 vt_scan.py --ip 3.3.1.109
    python3 vt_scan.py example.com 8.8.8.8 51.210.235.46
"""

import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from playwright.sync_api import sync_playwright

# --------------------------- Helper functions ---------------------------

IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


def is_ip(s: str) -> bool:
    s = s.strip()
    if IP_PATTERN.match(s):
        return all(0 <= int(p) <= 255 for p in s.split('.'))
    return False


def url_to_vt_hash(url: str) -> str:
    normalized = url if url.endswith('/') else url + '/'
    return hashlib.sha256(normalized.encode()).hexdigest()


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def ts_to_str(ts):
    if not ts:
        return "N/A"
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def safe_filename(s: str) -> str:
    return re.sub(r'[^\w\-.]', '_', s)[:40]


# --------------------------- Core scanning engine ---------------------------

def _scan_page(vt_url: str, api_keyword: str, label: str,
               browser=None, context=None, js_fetch_path: str = None):
    """
    Generic page scan: open vt_url and intercept API responses containing api_keyword
    Return (api_data_list, screenshot_path)
    """
    api_data = []
    got_main_data = False  # Tracks whether the main result payload has been captured

    def on_response(response):
        nonlocal got_main_data
        url = response.url
        ct = response.headers.get("content-type", "")
        if api_keyword in url or ("json" in ct and "virustotal.com" in url):
            try:
                body = response.json()
                api_data.append({"url": url, "status": response.status, "data": body})
                # Check whether this is the main payload containing analysis results
                inner = body.get("data", {})
                if isinstance(inner, dict):
                    attrs = inner.get("attributes", {})
                    if "last_analysis_results" in attrs:
                        got_main_data = True
            except Exception:
                pass

    owns_browser = browser is None
    pw = None
    if owns_browser:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/133.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
        )

    page = context.new_page()
    page.on("response", on_response)
    ss_path = ""

    try:
        print("  [*] 加载页面...")
        # Key optimization: use domcontentloaded instead of networkidle
        # networkidle waits for all requests to stop (GA/reCAPTCHA never do), so it times out
        page.goto(vt_url, wait_until="domcontentloaded", timeout=30000)

        # Smart wait: poll until API data arrives, for up to 15 seconds
        print("  [*] 等待 API 数据...")
        for i in range(30):  # 30 x 0.5s = up to 15 seconds
            if got_main_data:
                print(f"  [*] API 数据已获取 ({(i+1)*0.5:.1f}s)")
                break
            time.sleep(0.5)
        else:
            print("  [*] 等待超时，尝试 JS fetch 备用...")

        # JS fetch fallback
        if not got_main_data and js_fetch_path:
            try:
                js = page.evaluate(f"""
                async () => {{
                    try {{
                        const r = await fetch('{js_fetch_path}');
                        return {{ ok: true, status: r.status, data: await r.json() }};
                    }} catch(e) {{ return {{ ok: false, err: e.toString() }}; }}
                }}
                """)
                if js.get("ok") and js["status"] == 200:
                    api_data.append({"url": "[JS fetch]", "status": 200, "data": js["data"]})
                    print("  [*] JS fetch 成功")
            except Exception:
                pass

        # Screenshot
        fname = safe_filename(label)
        ss_path = f"vt_screenshot_{fname}.png"
        try:
            page.screenshot(path=ss_path, full_page=True)
            print(f"  [*] 截图: {ss_path}")
        except Exception:
            ss_path = ""

    except Exception as e:
        print(f"  [!] 错误: {e}")
    finally:
        page.close()
        if owns_browser:
            browser.close()
            if pw:
                pw.stop()

    return api_data, ss_path


def _parse_analysis(api_data: list):
    """Extract last_analysis_results and attributes from API data."""
    for resp in api_data:
        data = resp.get("data", {})
        attrs = None
        if isinstance(data, dict):
            inner = data.get("data", {})
            if isinstance(inner, dict):
                attrs = inner.get("attributes", {})
            if not attrs:
                attrs = data.get("attributes", {})
        if attrs and "last_analysis_results" in attrs:
            return attrs
    return None


# ------------------------------ IP scan ------------------------------

def scan_ip(ip: str, browser=None, context=None):
    vt_url = f"https://www.virustotal.com/gui/ip-address/{ip}"
    fname = safe_filename(ip)
    print(f"\n{'━'*60}")
    print(f"  目标 (IP): {ip}")
    print(f"  VT:        {vt_url}")
    print(f"{'━'*60}")

    api_data, ss = _scan_page(
        vt_url, "/ui/ip_addresses/", ip,
        browser=browser, context=context,
        js_fetch_path=f"/ui/ip_addresses/{ip}"
    )

    # Save JSON
    raw_path = f"vt_raw_{fname}.json"
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(api_data, f, ensure_ascii=False, indent=2)

    # Parse
    attrs = _parse_analysis(api_data)
    result = {
        "type": "ip", "label": ip, "vt_url": vt_url,
        "found": False, "stats": {}, "malicious_engines": [], "all_engines": [],
        "ip_info": {},
    }

    if attrs:
        result["found"] = True
        result["stats"] = attrs.get("last_analysis_stats", {})
        result["ip_info"] = {
            "ip": attrs.get("ip_address", ip),
            "as_owner": attrs.get("as_owner", "N/A"),
            "asn": attrs.get("asn", "N/A"),
            "country": attrs.get("country", "N/A"),
            "continent": attrs.get("continent", "N/A"),
            "network": attrs.get("network", "N/A"),
            "regional_internet_registry": attrs.get("regional_internet_registry", "N/A"),
            "reputation": attrs.get("reputation", "N/A"),
            "total_votes": attrs.get("total_votes", {}),
            "last_analysis_date": ts_to_str(attrs.get("last_analysis_date")),
            "whois": attrs.get("whois", "")[:500],
            "tags": attrs.get("tags", []),
        }

        for engine, info in sorted(attrs["last_analysis_results"].items()):
            cat = info.get("category", "")
            res = info.get("result", "")
            entry = {"engine": engine, "category": cat, "result": res}
            result["all_engines"].append(entry)
            if cat in ("malicious", "malware", "suspicious"):
                result["malicious_engines"].append(entry)

    # Report
    lines = _build_ip_report(result, ip)
    report = "\n".join(lines)
    txt_path = f"vt_result_{fname}.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    print(f"\n  [*] 报告: {txt_path} | JSON: {raw_path}")
    return result


def _build_ip_report(result, ip):
    lines = []
    lines.append(f"VirusTotal IP 检测报告")
    lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"{'='*70}")
    if result["found"]:
        info = result["ip_info"]
        stats = result["stats"]
        mal = result["malicious_engines"]
        total = len(result["all_engines"])
        lines.append(f"IP 地址:   {info.get('ip', ip)}")
        lines.append(f"国家/地区: {info.get('country', 'N/A')} ({info.get('continent', '')})")
        lines.append(f"AS 信息:   AS{info.get('asn', 'N/A')} - {info.get('as_owner', 'N/A')}")
        lines.append(f"网段:      {info.get('network', 'N/A')}")
        lines.append(f"RIR:       {info.get('regional_internet_registry', 'N/A')}")
        lines.append(f"信誉分:    {info.get('reputation', 'N/A')}")
        lines.append(f"投票:      {info.get('total_votes', {})}")
        lines.append(f"分析时间:  {info.get('last_analysis_date', 'N/A')}")
        tags = info.get("tags", [])
        if tags:
            lines.append(f"标签:      {', '.join(tags)}")
        lines.append(f"\n{'='*70}")
        lines.append(f"  检测结果: {len(mal)}/{total} 引擎标记为恶意")
        lines.append(f"  统计: 恶意={stats.get('malicious',0)} | "
                      f"可疑={stats.get('suspicious',0)} | "
                      f"安全={stats.get('harmless',0)} | "
                      f"未检测={stats.get('undetected',0)}")
        lines.append(f"{'='*70}")
        if mal:
            lines.append(f"\n🔴 恶意/可疑引擎 ({len(mal)}):")
            lines.append(f"  {'引擎':<35} {'类别':<15} {'结果'}")
            lines.append(f"  {'-'*65}")
            for d in mal:
                lines.append(f"  {d['engine']:<35} {d['category']:<15} {d['result']}")
        clean = [e for e in result["all_engines"] if e["category"] == "harmless"]
        if clean:
            lines.append(f"\n✅ 安全引擎 ({len(clean)}): {', '.join(e['engine'] for e in clean)}")
        unrated = [e for e in result["all_engines"] if e["category"] == "undetected"]
        if unrated:
            lines.append(f"\n❓ 未评级 ({len(unrated)}): {', '.join(e['engine'] for e in unrated)}")
        whois = info.get("whois", "")
        if whois:
            lines.append(f"\n📋 WHOIS 摘要:\n  {whois[:300]}")
    else:
        lines.append(f"IP: {ip}\n\n[!] 未能提取检测结果")
    return lines


# ------------------------------ URL scan ------------------------------

def scan_url(vt_hash: str, label: str = "", browser=None, context=None):
    vt_url = f"https://www.virustotal.com/gui/url/{vt_hash}"
    short = vt_hash[:8]
    print(f"\n{'━'*60}")
    print(f"  目标 (URL): {label or vt_hash}")
    print(f"  VT:         {vt_url}")
    print(f"{'━'*60}")

    api_data, ss = _scan_page(
        vt_url, "/ui/urls/", label,
        browser=browser, context=context,
        js_fetch_path=f"/ui/urls/{vt_hash}"
    )

    # Save JSON
    raw_path = f"vt_raw_{short}.json"
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(api_data, f, ensure_ascii=False, indent=2)

    # Parse
    attrs = _parse_analysis(api_data)
    result = {
        "type": "url", "label": label, "vt_hash": vt_hash, "vt_url": vt_url,
        "found": False, "stats": {}, "malicious_engines": [], "all_engines": [],
        "url_info": {},
    }

    if attrs:
        result["found"] = True
        result["stats"] = attrs.get("last_analysis_stats", {})
        result["url_info"] = {
            "url": attrs.get("url", ""),
            "last_analysis_date": ts_to_str(attrs.get("last_analysis_date")),
            "reputation": attrs.get("reputation", ""),
            "total_votes": attrs.get("total_votes", {}),
            "categories": attrs.get("categories", {}),
        }
        for engine, info in sorted(attrs["last_analysis_results"].items()):
            cat = info.get("category", "")
            res = info.get("result", "")
            entry = {"engine": engine, "category": cat, "result": res}
            result["all_engines"].append(entry)
            if cat in ("malicious", "malware", "suspicious"):
                result["malicious_engines"].append(entry)

    # Report
    lines = _build_url_report(result, label, vt_url)
    report = "\n".join(lines)
    txt_path = f"vt_result_{short}.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    print(f"\n  [*] 报告: {txt_path} | JSON: {raw_path}")
    return result


def _build_url_report(result, label, vt_url):
    lines = []
    lines.append(f"VirusTotal URL 检测报告")
    lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"{'='*70}")
    lines.append(f"目标:     {label}")
    lines.append(f"VT 页面:  {vt_url}")
    if result["found"]:
        info = result["url_info"]
        stats = result["stats"]
        mal = result["malicious_engines"]
        total = len(result["all_engines"])
        lines.append(f"扫描 URL: {info.get('url', 'N/A')}")
        lines.append(f"分析时间: {info.get('last_analysis_date', 'N/A')}")
        lines.append(f"信誉分:   {info.get('reputation', 'N/A')}")
        cats = info.get("categories", {})
        if cats:
            lines.append(f"分类:     {json.dumps(cats, ensure_ascii=False)}")
        lines.append(f"\n{'='*70}")
        lines.append(f"  检测结果: {len(mal)}/{total} 引擎标记为恶意")
        lines.append(f"  统计: 恶意={stats.get('malicious',0)} | "
                      f"可疑={stats.get('suspicious',0)} | "
                      f"安全={stats.get('harmless',0)} | "
                      f"未检测={stats.get('undetected',0)}")
        lines.append(f"{'='*70}")
        if mal:
            lines.append(f"\n🔴 恶意/可疑引擎 ({len(mal)}):")
            lines.append(f"  {'引擎':<35} {'类别':<15} {'结果'}")
            lines.append(f"  {'-'*65}")
            for d in mal:
                lines.append(f"  {d['engine']:<35} {d['category']:<15} {d['result']}")
        clean = [e for e in result["all_engines"] if e["category"] == "harmless"]
        if clean:
            lines.append(f"\n✅ 安全引擎 ({len(clean)}): {', '.join(e['engine'] for e in clean)}")
        unrated = [e for e in result["all_engines"] if e["category"] == "undetected"]
        if unrated:
            lines.append(f"\n❓ 未评级 ({len(unrated)}): {', '.join(e['engine'] for e in unrated)}")
    else:
        lines.append(f"\n[!] 未能提取检测结果")
    return lines


# --------------------------- Smart dispatch ---------------------------

def scan_target(target: str, browser=None, context=None):
    target = target.strip()
    if is_ip(target):
        return scan_ip(target, browser=browser, context=context)
    else:
        url = normalize_url(target)
        vt_hash = url_to_vt_hash(url)
        return scan_url(vt_hash, label=url, browser=browser, context=context)


def scan_targets(targets: list):
    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=True)
    context = browser.new_context(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/133.0.0.0 Safari/537.36",
        viewport={"width": 1920, "height": 1080},
    )

    results = []
    for i, t in enumerate(targets, 1):
        t = t.strip()
        if not t:
            continue
        print(f"\n[{i}/{len(targets)}] 正在扫描: {t}")
        r = scan_target(t, browser=browser, context=context)
        results.append(r)
        if i < len(targets):
            time.sleep(2)

    browser.close()
    pw.stop()

    if len(results) > 1:
        print(f"\n\n{'━'*60}")
        print(f"  批量扫描汇总 ({len(results)} 个目标)")
        print(f"{'━'*60}")
        for r in results:
            t = r.get("type", "?")
            label = r.get("label", "?")
            if r["found"]:
                mal = len(r["malicious_engines"])
                total = len(r["all_engines"])
                icon = "🔴" if mal > 0 else "✅"
                print(f"  [{t.upper():3}] {icon} {mal}/{total:<6} {label}")
            else:
                print(f"  [{t.upper():3}] ❓ 无结果  {label}")
    return results


# ------------------------------ Entry point ------------------------------

def main():
    args = sys.argv[1:]

    if not args:
        print("VirusTotal Scanner (URL + IP)")
        print("输入 URL 或 IP，q 退出\n")
        while True:
            try:
                user_input = input("VT> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n退出")
                break
            if not user_input or user_input.lower() == 'q':
                break
            scan_targets(user_input.split())
        return

    if args[0] == "--hash" and len(args) >= 2:
        scan_url(args[1])
        return

    if args[0] == "--ip" and len(args) >= 2:
        scan_targets(args[1:])
        return

    if args[0] == "-f" and len(args) >= 2:
        filepath = args[1]
        if not os.path.isfile(filepath):
            print(f"[!] 文件不存在: {filepath}")
            sys.exit(1)
        with open(filepath, "r") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        print(f"[*] 从 {filepath} 读取 {len(targets)} 个目标")
        scan_targets(targets)
        return

    scan_targets(args)


if __name__ == "__main__":
    main()