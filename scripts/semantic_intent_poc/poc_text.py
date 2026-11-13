"""Text normalisation and sentence units for the intent-model PoC.

Coarse mirror of the Rust semantic front end: NFKC, invisible and combining
mark removal, identity masking, then sentence units. PoC only.

Identity masking replaces who/where tokens with fixed placeholders so a model
learns the request and its rhetoric, not "this partner domain, hotline or
colleague name means benign" (which an attacker can borrow). Amounts, dates
and attachment file names stay: they carry meaning, not identity. Personal
names are only masked in salutation/title positions; free-text names would
need NER. The same rules must be ported to the Rust inference path.
"""

import re
import unicodedata

INVISIBLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x2800, 0x2800), (0x3164, 0x3164), (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xE0000, 0xE007F), (0xE0100, 0xE01EF),
)
COMBINING_RANGES = ((0x0300, 0x036F), (0x1AB0, 0x1AFF), (0x20D0, 0x20FF))


def char_class(ranges):
    parts = (re.escape(chr(a)) + ("-" + re.escape(chr(b)) if b != a else "") for a, b in ranges)
    return re.compile("[" + "".join(parts) + "]")


INVISIBLE = char_class(INVISIBLE_RANGES)
COMBINING = char_class(COMBINING_RANGES)
URL = re.compile(r"(?i)\b(?:https?://|www\.)\S+")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
SPACE = re.compile("[ \t\r\f\v" + chr(0x00A0) + chr(0x3000) + "]+")

TLDS = ("com|net|org|cn|top|xyz|info|io|co|cc|me|vip|shop|site|online|club|app|tech|biz|gov|edu|"
        "hk|tw|mo|us|uk|de|it|fr|es|nl|ru|jp|kr|sg|my|in|br|au|ca|eu|ch|se|no|dk|pl|ly|ai|link|"
        "live|icu|work|ltd|wang|ink|pro|mobi|tv|asia|cloud|email|space|store|fun|life|world|today|"
        "news|bank|finance|support|services|help|xin|cyou|buzz|rest|loan|win|bid|click")
SURNAMES = ("王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于蒋蔡余杜叶程"
            "苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛"
            "郝龚邵万钱严覃武戴莫孔向汤")
# 总 is a title only when it does not start a common word (总结, 总部, 总额 ...).
TITLE = ("(?:总监|总裁|总经理|总(?![结部公司行额计体共之量价数账表会值和])|经理|主任|主管|老师|先生|女士|小姐|"
         "处长|科长|局长|部长|行长|董事长|律师|医生|老板|教授|博士)")
IDENTITY_RULES = (
    (re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), " (ip) "),
    (re.compile(r"(?<![A-Za-z0-9])\d{17}[\dXx](?![A-Za-z0-9])"), " (number) "),
    # Mixed letter/digit codes next, so phone rules never cut digits out of an IBAN or case number.
    # Boundaries are ASCII-only: \w would also match the CJK text these codes sit next to.
    (re.compile(r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)+"
                r"(?![A-Za-z0-9_-])"), " (code) "),
    (re.compile(r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9]{8,}(?![A-Za-z0-9_-]))(?=(?:[A-Za-z]*\d){4})(?=[A-Za-z0-9]*[A-Za-z])"
                r"[A-Za-z0-9]+"), " (code) "),
    (re.compile(r"(?<![A-Za-z0-9])(?:\+?86[\s-]?)?1[3-9]\d[\s-]?\d{4}[\s-]?\d{4}(?!\d)"), " (phone) "),
    (re.compile(r"(?<![A-Za-z0-9])[48]00[\s-]?\d{3}[\s-]?\d{4}(?!\d)"), " (phone) "),
    (re.compile(r"(拨打|致电|热线|电话|客服|呼叫)([:：]?\s*)(?:95\d{3,5}|1[0-2]\d{3})(?!\d)"), r"\1\2(phone)"),
    (re.compile(r"(?<![A-Za-z0-9])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?!\d)"), " (phone) "),
    (re.compile(r"(?<![A-Za-z0-9])(?:1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"), " (phone) "),
    (re.compile(r"(?<![A-Za-z0-9])\(?0\d{2,3}\)?[\s-]?\d{7,8}(?!\d)"), " (phone) "),
    (re.compile(r"(?<!\d)\d{4}(?:[\s-]\d{4}){2,4}(?:[\s-]\d{1,3})?(?!\d)"), " (number) "),
    (re.compile(r"(?<![\d.,])\d{8,}(?![\d.,])"), " (number) "),
    (re.compile(r"(?i)(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + TLDS + r")(?![\w-])"), " (domain) "),
    (re.compile("[" + SURNAMES + "](?=" + TITLE + ")"), "(name)"),
    (re.compile("[" + SURNAMES + "][一-鿿]{1,2}(?=先生|女士|小姐)"), "(name)"),
    (re.compile("(?<![一-鿿])[小老][" + SURNAMES + "](?=[,，。!！?？:：\\s]|你|您|$)"), "(name)"),
    (re.compile(r"\b(Mr|Mrs|Ms|Miss|Dr|Prof|Frau|Herr|Sig|Signor|Signora|Dott)\.?\s+[A-Z][\w'-]+(?:\s+[A-Z][\w'-]+)?"),
     r"\1 (name)"),
    (re.compile(r"\b(Dear|Hi|Hello|Hey|Gentile|Caro|Cara|Liebe|Lieber)\s+[A-Z][\w'-]+(?:\s+[A-Z][\w'-]+)?(?=\s*[,!:\n])"),
     r"\1 (name)"),
)


def mask_identities(text):
    for pattern, replacement in IDENTITY_RULES:
        text = pattern.sub(replacement, text)
    return text
# Sentence ends: CJK/Latin terminal punctuation, newlines, or ". " before a
# capital/digit/quote. Lookbehinds are single characters (fixed width).
BOUNDARY = re.compile(r"(?<=[。！？!?；;])|\n+|(?<=[.:])\s+(?=[\"'“(\[A-Z0-9])")
SOFT = re.compile(r"(?<=[,，、：])")
WORD = re.compile(r"\w")

MAX_CHARS = 200
MAX_SENTENCES = 32
HEAD, TAIL = 24, 8


def normalize(text, identities=True):
    """identities=False reproduces the first PoC runs (links and e-mails only)."""
    text = unicodedata.normalize("NFKC", text or "")
    text = INVISIBLE.sub("", text)
    text = COMBINING.sub("", text)
    text = URL.sub(" (link) ", text)
    text = EMAIL.sub(" (email) ", text)
    return mask_identities(text) if identities else text


def _chunks(piece):
    if len(piece) <= MAX_CHARS:
        return [piece]
    out, current = [], ""
    for part in SOFT.split(piece):
        if current and len(current) + len(part) > MAX_CHARS:
            out.append(current)
            current = ""
        current += part
    if current:
        out.append(current)
    final = []
    for part in out:
        final.extend(part[i:i + MAX_CHARS] for i in range(0, len(part), MAX_CHARS))
    return final


def sentences(subject, body):
    """Return (sentences, truncated). The subject, when present, comes first."""
    units, seen = [], set()
    pieces = [normalize(subject)] if subject else []
    pieces += BOUNDARY.split(normalize(body))
    for piece in pieces:
        if piece is None:
            continue
        piece = SPACE.sub(" ", piece).strip()
        for chunk in _chunks(piece):
            chunk = chunk.strip()
            if len(WORD.findall(chunk)) < 4 or chunk in seen:
                continue
            seen.add(chunk)
            units.append(chunk)
    if len(units) > MAX_SENTENCES:
        return units[:HEAD] + units[-TAIL:], True
    return units, False
