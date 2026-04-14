import type {
  AIMetadata,
  AuditResponse,
  CheckResult,
  DashboardOverview,
  GroupedResult,
  IOCRecord,
  PagedResponse,
  RiskLevel,
  ScanMode,
  ScanRecord,
  SummaryCard,
  ThreatMapPoint,
  ThreatReport,
  Verdict,
} from '@/types';

export interface ReportPayload {
  scan_summary: {
    target_url: string;
    scan_mode: string;
    risk_score: number;
    risk_level: string;
    verdict: string;
    created_at: string;
    duration_ms: number;
    total_checks: number;
  };
  indicators_of_compromise: IOCRecord[];
  domain_intelligence: CheckResult[];
  risk_assessment: {
    pass_count: number;
    warn_count: number;
    fail_count: number;
    info_count: number;
    skip_count: number;
    risk_score: number;
    risk_level: RiskLevel;
  };
  recommendations: string[];
  grouped_checks: GroupedResult[];
  threat_report?: ThreatReport | null;
}

export interface StoredScan extends ScanRecord {
  checks: CheckResult[];
  iocs: IOCRecord[];
  summary_cards: SummaryCard[];
  grouped_results: GroupedResult[];
  ai_threat_report?: ThreatReport | null;
  ai_metadata?: AIMetadata | null;
  ai_error?: string | null;
  report: ReportPayload;
}

export interface StoreState {
  version: number;
  nextScanId: number;
  nextIOCId: number;
  scans: StoredScan[];
}

export interface AuditBuildResult extends AuditResponse {
  checks: CheckResult[];
  iocs: IOCRecord[];
  report: ReportPayload;
  grouped_results: GroupedResult[];
  summary_cards: SummaryCard[];
}

export interface ListScanQuery {
  page?: number;
  pageSize?: number;
  q?: string;
  risk?: string;
  status?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface ListIocQuery {
  page?: number;
  pageSize?: number;
  q?: string;
  type?: string;
  severity?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface ThreatDomainRow {
  domain: string;
  hits: number;
  last_seen: string;
}

export interface ThreatIpRow {
  ip: string;
  sightings: number;
  critical_hits: number;
  high_hits: number;
  medium_hits: number;
  last_seen: string;
}

export interface ThreatMapResponse {
  range: string;
  points: ThreatMapPoint[];
}

export interface DashboardOverviewResult extends DashboardOverview {}

export type { AuditResponse, CheckResult, IOCRecord, PagedResponse, ScanMode, ScanRecord, SummaryCard, ThreatMapPoint, ThreatReport, Verdict, AIMetadata, GroupedResult };
