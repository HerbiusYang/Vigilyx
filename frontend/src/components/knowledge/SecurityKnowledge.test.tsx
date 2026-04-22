import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeAll, describe, expect, it, vi } from 'vitest'

import '../../i18n'
import { topicEntries } from './knowledgeData'
import { TopicVisualShowcase } from './knowledgeVisuals'
import SecurityKnowledge from './SecurityKnowledge'

beforeAll(() => {
  vi.stubGlobal(
    'IntersectionObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )

  window.scrollTo = vi.fn()
})

describe('SecurityKnowledge', () => {
  it('renders the mta article route without crashing', async () => {
    render(
      <MemoryRouter initialEntries={['/knowledge/mta']}>
        <Routes>
          <Route path="/knowledge/:topicId" element={<SecurityKnowledge />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByRole('heading', { level: 1, name: '什么是 MTA' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 2, name: '邮件投递路径图解' })).toBeInTheDocument()
  })

  it.each(['zh', 'en'] as const)('renders all visual showcases in %s without crashing', (language) => {
    const { rerender, container } = render(
      <TopicVisualShowcase topicId="mta" language={language} />,
    )

    for (const entry of topicEntries) {
      rerender(<TopicVisualShowcase topicId={entry.id} language={language} />)

      expect(container.querySelector('.sk-showcase')).toBeInTheDocument()
      expect(container.querySelector('.sk-showcase-art svg')).toBeInTheDocument()
      expect(container.querySelectorAll('.sk-showcase-card')).toHaveLength(2)
      expect(container.querySelectorAll('.sk-flow-node').length).toBeGreaterThanOrEqual(4)
    }
  })
})
