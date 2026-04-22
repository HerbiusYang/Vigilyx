import { describe, it, expect } from 'vitest'
import { buildEmailPreviewDoc } from '../emailHtml'

/**
 * Helper: parse the output HTML and extract body content.
 * Uses DOMParser (available in jsdom).
 */
function bodyContent(html: string): string {
  const doc = new DOMParser().parseFromString(buildEmailPreviewDoc(html), 'text/html')
  return doc.body.innerHTML
}

describe('buildEmailPreviewDoc', () => {
  // ---------- Blocked tags removed ----------
  it('removes script tags completely', () => {
    const result = bodyContent('<div>Hello</div><script>alert("xss")</script>')
    expect(result).not.toContain('script')
    expect(result).not.toContain('alert')
    expect(result).toContain('Hello')
  })

  it('removes iframe tags completely', () => {
    const result = bodyContent('<p>Text</p><iframe src="evil.html"></iframe>')
    expect(result).not.toContain('iframe')
    expect(result).not.toContain('evil.html')
    expect(result).toContain('Text')
  })

  it('removes img tags (tracking pixel prevention)', () => {
    const result = bodyContent('<p>Text</p><img src="tracker.gif" />')
    expect(result).not.toContain('img')
    expect(result).not.toContain('tracker')
    expect(result).toContain('Text')
  })

  it('removes style tags completely', () => {
    const result = bodyContent('<style>body{color:red}</style><p>Hello</p>')
    expect(result).not.toContain('style')
    expect(result).not.toContain('color:red')
    expect(result).toContain('Hello')
  })

  it('removes form and input tags', () => {
    const result = bodyContent('<form action="evil"><input type="text" /><button>Click</button></form>')
    expect(result).not.toContain('form')
    expect(result).not.toContain('input')
    expect(result).not.toContain('button')
  })

  it('removes embed and object tags', () => {
    const result = bodyContent('<embed src="flash.swf"><object data="bad.swf"></object>')
    expect(result).not.toContain('embed')
    expect(result).not.toContain('object')
  })

  it('removes svg tags', () => {
    const result = bodyContent('<svg onload="alert(1)"><circle r="50"/></svg>')
    expect(result).not.toContain('svg')
    expect(result).not.toContain('circle')
  })

  // ---------- Transparent tags (content preserved, tag unwrapped) ----------
  it('unwraps a tags preserving inner content', () => {
    const result = bodyContent('<a href="http://example.com">Click here</a>')
    // The link content should be preserved; the a tag is transparent
    expect(result).toContain('Click here')
    // The output should not contain href or link functionality within body content
    // (a tags in transparent set → content preserved but tag removed from output)
    // Actually transparent tags keep the inner text but drop the tag itself
    expect(result).not.toContain('href')
  })

  it('unwraps font, body, html, center tags', () => {
    const result = bodyContent('<center><font color="red">Styled</font></center>')
    expect(result).toContain('Styled')
    expect(result).not.toContain('<font')
    expect(result).not.toContain('<center')
  })

  // ---------- Safe tags preserved ----------
  it('preserves div tags', () => {
    const result = bodyContent('<div>Hello</div>')
    expect(result).toContain('<div>')
    expect(result).toContain('Hello')
  })

  it('preserves p, span, strong, em tags', () => {
    const result = bodyContent('<p><span>Text</span> <strong>Bold</strong> <em>Italic</em></p>')
    expect(result).toContain('<p>')
    expect(result).toContain('<span>')
    expect(result).toContain('<strong>')
    expect(result).toContain('<em>')
  })

  it('preserves table structure', () => {
    const result = bodyContent('<table><tr><td>Cell</td></tr></table>')
    expect(result).toContain('<table>')
    expect(result).toContain('<tr>')
    expect(result).toContain('<td>')
    expect(result).toContain('Cell')
  })

  it('preserves ul/ol/li tags', () => {
    const result = bodyContent('<ul><li>Item 1</li><li>Item 2</li></ul>')
    expect(result).toContain('<ul>')
    expect(result).toContain('<li>')
  })

  it('preserves blockquote and pre tags', () => {
    const result = bodyContent('<blockquote>Quote</blockquote><pre>Code</pre>')
    expect(result).toContain('<blockquote>')
    expect(result).toContain('<pre>')
  })

  // ---------- td/th colspan/rowspan clamping ----------
  it('preserves valid colspan/rowspan on td', () => {
    const result = bodyContent('<table><tr><td colspan="3" rowspan="2">Cell</td></tr></table>')
    expect(result).toContain('colspan="3"')
    expect(result).toContain('rowspan="2"')
  })

  it('clamps colspan/rowspan to max 12', () => {
    const result = bodyContent('<table><tr><td colspan="50">Cell</td></tr></table>')
    expect(result).toContain('colspan="12"')
  })

  it('drops invalid colspan/rowspan values', () => {
    const result = bodyContent('<table><tr><td colspan="0">Cell</td></tr></table>')
    expect(result).not.toContain('colspan')
  })

  it('drops negative colspan', () => {
    const result = bodyContent('<table><tr><td colspan="-3">Cell</td></tr></table>')
    expect(result).not.toContain('colspan')
  })

  // ---------- XSS payloads neutralized ----------
  it('removes onerror attribute via tag blocking (img)', () => {
    const result = bodyContent('<img onerror="alert(1)" src="x">')
    expect(result).not.toContain('onerror')
    expect(result).not.toContain('alert')
  })

  it('removes javascript: protocol via tag blocking (a transparent)', () => {
    const result = bodyContent('<a href="javascript:alert(1)">Click</a>')
    expect(result).not.toContain('javascript')
    expect(result).toContain('Click')
  })

  it('strips all attributes from non-td/th allowed tags', () => {
    const result = bodyContent('<div class="evil" onclick="alert(1)" style="background:url(evil)">Safe</div>')
    expect(result).not.toContain('class')
    expect(result).not.toContain('onclick')
    expect(result).not.toContain('style')
    expect(result).toContain('Safe')
  })

  // ---------- HTML entities properly escaped ----------
  it('escapes HTML entities in text nodes', () => {
    const result = bodyContent('<div>&lt;script&gt;</div>')
    // The text node content "<script>" should be escaped back
    expect(result).toContain('&lt;script&gt;')
    expect(result).not.toContain('<script>')
  })

  // ---------- Nested attack vectors ----------
  it('handles nested script in div', () => {
    const result = bodyContent('<div><script>alert("xss")</script>Safe content</div>')
    expect(result).not.toContain('script')
    expect(result).toContain('Safe content')
  })

  it('handles deeply nested attack vectors', () => {
    const result = bodyContent('<div><p><span><script>evil()</script></span></p></div>')
    expect(result).not.toContain('script')
    expect(result).not.toContain('evil')
  })

  // ---------- Empty / null input ----------
  it('handles empty string input', () => {
    const result = buildEmailPreviewDoc('')
    expect(result).toContain('<!doctype html>')
    expect(result).toContain('[内容已清理] 该邮件的 HTML 内容经安全过滤后为空')
  })

  it('shows fallback for content that sanitizes to empty', () => {
    const result = buildEmailPreviewDoc('<script>alert(1)</script><style>.x{}</style>')
    expect(result).toContain('[内容已清理] 该邮件的 HTML 内容经安全过滤后为空')
  })

  // ---------- Normal email renders correctly ----------
  it('renders a normal email table layout correctly', () => {
    const html = `
      <table>
        <tr>
          <td colspan="2">Header</td>
        </tr>
        <tr>
          <td>Name</td>
          <td>Value</td>
        </tr>
      </table>
      <p>Dear user,</p>
      <p>This is a <strong>test</strong> email.</p>
    `
    const result = bodyContent(html)
    expect(result).toContain('<table>')
    expect(result).toContain('colspan="2"')
    expect(result).toContain('Header')
    expect(result).toContain('Dear user')
    expect(result).toContain('<strong>test</strong>')
  })

  // ---------- Full document output structure ----------
  it('outputs a complete HTML document with CSP', () => {
    const result = buildEmailPreviewDoc('<p>Hello</p>')
    expect(result).toContain('<!doctype html>')
    expect(result).toContain('Content-Security-Policy')
    expect(result).toContain("default-src 'none'")
    expect(result).toContain('Hello')
  })
})
