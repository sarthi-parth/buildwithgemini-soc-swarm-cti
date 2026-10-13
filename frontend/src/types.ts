export interface DashboardSummary {
  total_incidents_discovered: number;
  incidents_investigated: number;
  total_iocs_extracted: number;
  total_ioas_extracted: number;
  high_severity_incidents: number;
  unverified_findings: number;
  active_sources: number;
  total_agent_runs: number;
  total_notifications: number;
  knowledge_base_chunks: number;
  gmail_status: string;
}

export interface IncidentSummary {
  id: string;
  title: string;
  summary: string;
  affected_organization: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "DISCOVERED" | "INVESTIGATING" | "VERIFYING" | "READY_TO_PUBLISH" | "PUBLISHED" | "NEEDS_REVIEW" | "FAILED";
  is_demo: boolean;
  confidence_score: number;
  created_at: string;
  iocs_count: number;
  ioas_count?: number;
  techniques_count: number;
  source_url?: string;
}

export interface IOAItem {
  id: string;
  incident_id?: string;
  type: string;
  pattern_name: string;
  technique_id: string;
  observed_behavior: string;
  detection_logic: string;
  evidence_quote?: string;
  confidence?: number;
  created_at?: string;
}

export interface IncidentDetail {
  id: string;
  title: string;
  summary: string;
  affected_organization: string;
  affected_systems: string;
  initial_access_vector: string;
  root_cause_analysis: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence_score: number;
  status: string;
  is_demo: boolean;
  created_at: string;
  source: {
    title: string;
    url: string;
    extracted_text: string;
  };
  iocs: Array<{
    id: string;
    type: string;
    value: string;
    defanged: string;
    context_role: string;
    threat_status: string;
    confidence: number;
  }>;
  ioas?: IOAItem[];
  techniques: Array<{
    id: string;
    name: string;
    tactic: string;
    supporting_behavior: string;
    is_confirmed: boolean;
  }>;
  recommendations: Array<{
    category: string;
    title: string;
    action_items: string;
    priority: string;
  }>;
  timeline: Array<{
    order: number;
    stage: string;
    description: string;
  }>;
  verification_reviews: Array<{
    status: string;
    score: number;
    reasons: string;
    reviewed_at: string;
  }>;
  agent_runs: Array<{
    id: string;
    agent_name: string;
    status: string;
    duration_seconds: number;
    decision_summary: string;
    started_at: string;
  }>;
}

export interface DayWiseGroup {
  date: string;
  display_label: string;
  total_reports: number;
  high_critical_count: number;
  total_iocs: number;
  total_ioas: number;
  reports: IncidentSummary[];
}

export interface SearchResults {
  query: string;
  total_matches: number;
  reports: IncidentSummary[];
  iocs: IOCItem[];
  ioas: IOAItem[];
  historical_rag: Array<{
    title: string;
    text: string;
    score: number;
    source_url: string;
  }>;
}

export interface IOCItem {
  id: string;
  type: string;
  value: string;
  defanged: string;
  threat_status: string;
  enrichment_status?: string;
  first_seen?: string;
}

export interface SourceItem {
  id: string;
  name: string;
  source_type: string;
  url: string;
  enabled: boolean;
  last_polled_at: string | null;
  last_error: string | null;
}

export interface NotificationItem {
  id: string;
  incident_id: string;
  notification_type: string;
  recipient: string;
  subject: string;
  delivery_status: string;
  html_preview: string;
  plain_preview: string;
  created_at: string;
  error_message: string | null;
}

export interface AgentRunItem {
  id: string;
  agent_name: string;
  status: string;
  incident_id: string;
  decision_summary: string;
  duration_seconds: number;
  started_at: string;
}
