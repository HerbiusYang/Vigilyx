import type { ModuleMetadata, PipelineConfig, ModuleConfig, ContentRules, EngineStatus } from '../../types'
import PipelineGraph from './PipelineGraph'

interface PipelineTabProps {
  modules: ModuleMetadata[]
  engineStatus: EngineStatus | null
  pipelineConfig: PipelineConfig | null
  contentRules: ContentRules | null
  onToggleModule: (moduleId: string) => void
  onChangeMode: (moduleId: string, mode: ModuleConfig['mode']) => void
}

export default function PipelineTab({
  modules,
  engineStatus,
  pipelineConfig,
  contentRules,
  onToggleModule,
  onChangeMode,
}: PipelineTabProps) {
  return (
    <PipelineGraph
      modules={modules}
      engineStatus={engineStatus}
      pipelineConfig={pipelineConfig}
      contentRules={contentRules}
      onToggleModule={onToggleModule}
      onChangeMode={onChangeMode}
    />
  )
}
