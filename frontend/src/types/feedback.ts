import type { SecurityVerdict } from './index'

export type FeedbackType = 'legitimate' | 'phishing' | 'spoofing' | 'social_engineering' | 'other_threat'
export type FeedbackThreatLevel = SecurityVerdict['threat_level']
export type FeedbackLearningStatus = 'recorded' | 'insufficient_evidence'

export interface SessionFeedback {
  id: string
  feedback_type: FeedbackType
  corrected_threat_level: FeedbackThreatLevel | null
  original_threat_level: FeedbackThreatLevel | null
  status: string
  created_at: string
}

export interface SessionFeedbackHistory {
  feedbacks: SessionFeedback[]
  learning_status: FeedbackLearningStatus | null
  learning_reason?: string | null
}

export interface FeedbackSubmissionResult {
  learning_status: FeedbackLearningStatus
  learning_reason?: string | null
}

export interface FeedbackSubmission {
  feedback_type: FeedbackType
  corrected_threat_level: FeedbackThreatLevel | null
  expected_verdict_id: string
  comment: string | null
}

export interface DsModelParameters {
  parameter_version: string
  training_status?: string
  training_sample_count?: number
  calibration?: { slope: number; intercept: number } | null
  base_rate?: number
  sources: Record<string, { slope: number; intercept: number; reliability: number }>
}

export interface DsLearningState {
  schema_version: number
  revision: string | number
  sample_window_limit: number
  feedback_count: number
  eligible_count: number
  excluded_count: number
  candidate: DsModelParameters | null
  active: DsModelParameters | null
  validation_status: string
  pending_gates: string[]
  updated_at: string | null
}
