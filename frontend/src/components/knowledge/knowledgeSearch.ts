import { type TopicId, type TopicEntry, getLocalizedTopicContent } from './knowledgeData'

export interface SearchSnippet {
  text: string
  highlights: [number, number][]
  sectionHeading: string
}

export interface SearchResult {
  topicId: TopicId
  title: string
  subtitle: string
  tag: string
  tagClass: string
  iconType: TopicEntry['iconType']
  snippets: SearchSnippet[]
  score: number
}

function normalizeQuery(query: string): string[] {
  return query
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(t => t.length > 0)
}

function countMatches(text: string, tokens: string[]): number {
  const lower = text.toLowerCase()
  let count = 0
  for (const token of tokens) {
    if (lower.includes(token)) count++
  }
  return count
}

function extractSnippet(
  text: string,
  query: string,
  sectionHeading: string,
  contextChars = 40
): SearchSnippet | null {
  const lowerText = text.toLowerCase()
  const lowerQuery = query.toLowerCase()
  const idx = lowerText.indexOf(lowerQuery)
  if (idx === -1) return null

  const start = Math.max(0, idx - contextChars)
  const end = Math.min(text.length, idx + lowerQuery.length + contextChars)

  const prefix = start > 0 ? '...' : ''
  const suffix = end < text.length ? '...' : ''
  const snippet = prefix + text.slice(start, end) + suffix

  const highlightStart = idx - start + prefix.length
  const highlightEnd = highlightStart + lowerQuery.length

  return {
    text: snippet,
    highlights: [[highlightStart, highlightEnd]],
    sectionHeading,
  }
}

export function searchTopics(query: string, topics: TopicEntry[], language = 'zh-CN'): SearchResult[] {
  const trimmed = query.trim()
  if (!trimmed) return []

  const tokens = normalizeQuery(query)
  if (tokens.length === 0) return []

  const results: SearchResult[] = []

  for (const topic of topics) {
    const localized = getLocalizedTopicContent(topic, language)
    let score = 0

    // Title match (highest priority)
    score += countMatches(localized.title, tokens) * 100
    score += countMatches(topic.searchableText, tokens) * 10

    // Keyword match
    const keywordsJoined = topic.keywords.join(' ')
    score += countMatches(keywordsJoined, tokens) * 50

    // Subtitle match
    score += countMatches(localized.subtitle, tokens) * 30

    // Lead match
    score += countMatches(localized.lead, tokens) * 20

    // Section heading match
    for (const section of localized.sections) {
      score += countMatches(section.heading, tokens) * 15
    }

    // Body text match
    for (const section of localized.sections) {
      score += countMatches(section.plainText, tokens) * 5
    }

    if (score === 0) continue

    // Extract snippets - try full query first, then individual tokens
    const snippets: SearchSnippet[] = []
    const maxSnippets = 2

    // Try matching the full query string first
    for (const section of localized.sections) {
      if (snippets.length >= maxSnippets) break
      const snippet = extractSnippet(section.plainText, trimmed, section.heading)
      if (snippet) snippets.push(snippet)
    }

    // If no full-query match found, try individual tokens
    if (snippets.length === 0) {
      for (const token of tokens) {
        if (snippets.length >= maxSnippets) break
        // Try lead first
        const leadSnippet = extractSnippet(localized.lead, token, '')
        if (leadSnippet) {
          snippets.push(leadSnippet)
          continue
        }
        // Then sections
        for (const section of localized.sections) {
          if (snippets.length >= maxSnippets) break
          const snippet = extractSnippet(section.plainText, token, section.heading)
          if (snippet) {
            snippets.push(snippet)
            break
          }
        }
      }
    }

    results.push({
      topicId: topic.id,
      title: localized.title,
      subtitle: localized.subtitle,
      tag: localized.tag,
      tagClass: topic.tagClass,
      iconType: topic.iconType,
      snippets,
      score,
    })
  }

  // Sort by score descending
  results.sort((a, b) => b.score - a.score)
  return results
}
