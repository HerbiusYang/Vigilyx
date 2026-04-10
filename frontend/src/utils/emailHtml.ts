const ALLOWED_TAGS = new Set([
  'article', 'aside', 'blockquote', 'br', 'code', 'div', 'em', 'figcaption',
  'figure', 'footer', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hr', 'li',
  'main', 'ol', 'p', 'pre', 'section', 'span', 'strong', 'table', 'tbody', 'td',
  'tfoot', 'th', 'thead', 'tr', 'u', 'ul',
])

const TRANSPARENT_TAGS = new Set([
  'a', 'abbr', 'b', 'body', 'center', 'font', 'html', 'label', 'small', 'sup',
  'sub',
])

const BLOCKED_TAGS = new Set([
  'audio', 'base', 'button', 'canvas', 'embed', 'form', 'iframe', 'img', 'input',
  'link', 'meta', 'object', 'picture', 'script', 'select', 'source', 'style',
  'svg', 'textarea', 'video',
])

export function buildEmailPreviewDoc(html: string): string {
  const parser = new DOMParser()
  const doc = parser.parseFromString(html, 'text/html')
  const safeContent = sanitizeNodes(Array.from(doc.body.childNodes))

  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
    <style>
      :root {
        color-scheme: light only;
      }
      * {
        box-sizing: border-box;
      }
      body {
        margin: 0;
        padding: 16px;
        color: #1f2937;
        background: #ffffff;
        font: 14px/1.6 "SF Pro Text", "PingFang SC", "Microsoft YaHei", sans-serif;
        word-break: break-word;
      }
      a {
        color: inherit;
        text-decoration: none;
        pointer-events: none;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        margin: 12px 0;
      }
      th, td {
        border: 1px solid #d1d5db;
        padding: 8px 10px;
        text-align: left;
        vertical-align: top;
      }
      pre, code {
        font-family: "SFMono-Regular", "JetBrains Mono", Consolas, monospace;
      }
      pre {
        white-space: pre-wrap;
        background: #f3f4f6;
        border-radius: 10px;
        padding: 12px;
      }
      blockquote {
        margin: 12px 0;
        padding-left: 12px;
        border-left: 3px solid #d1d5db;
        color: #4b5563;
      }
      .email-preview-empty {
        color: #6b7280;
      }
    </style>
  </head>
  <body>${safeContent || '<p class="email-preview-empty">该 HTML 邮件在安全净化后没有保留可展示的内容。</p>'}</body>
</html>`
}

function sanitizeNodes(nodes: ChildNode[]): string {
  return nodes.map(node => sanitizeNode(node)).join('')
}

function sanitizeNode(node: ChildNode): string {
  if (node.nodeType === Node.TEXT_NODE) {
    return escapeHtml(node.textContent || '')
  }

  if (node.nodeType !== Node.ELEMENT_NODE) {
    return ''
  }

  const element = node as Element
  const tag = element.tagName.toLowerCase()

  if (BLOCKED_TAGS.has(tag)) {
    return ''
  }

  const inner = sanitizeNodes(Array.from(element.childNodes))

  if (TRANSPARENT_TAGS.has(tag) || !ALLOWED_TAGS.has(tag)) {
    return inner
  }

  const attrs = buildSafeAttributes(element, tag)
  return `<${tag}${attrs}>${inner}</${tag}>`
}

function buildSafeAttributes(element: Element, tag: string): string {
  if (tag !== 'td' && tag !== 'th') {
    return ''
  }

  const attrs: string[] = []
  const colspan = clampTableSpan(element.getAttribute('colspan'))
  const rowspan = clampTableSpan(element.getAttribute('rowspan'))

  if (colspan) attrs.push(`colspan="${colspan}"`)
  if (rowspan) attrs.push(`rowspan="${rowspan}"`)

  return attrs.length ? ` ${attrs.join(' ')}` : ''
}

function clampTableSpan(value: string | null): string {
  const parsed = Number.parseInt(value || '', 10)
  if (!Number.isFinite(parsed) || parsed < 1) {
    return ''
  }
  return String(Math.min(parsed, 12))
}

function escapeHtml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}
