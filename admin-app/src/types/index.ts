// Type definitions cho WP Security Monitor

export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';
export type IssueStatus = 'new' | 'investigating' | 'resolved' | 'ignored' | 'false_positive';
export type IssueType =
  | 'failed_login_attempts'
  | 'brute_force_attack'
  | 'suspicious_admin_login'
  | 'off_hours_login'
  | 'redirect'
  | 'user_registration'
  | 'file_change'
  | 'malware'
  | 'unknown';

export interface BacktraceFrame {
  file: string;
  line: number;
  function: string;
  class: string | null;
}

export interface Issue {
  id: number;
  issue_hash: string;
  line_code_hash: string | null;
  issuer_name: string;
  issue_type: IssueType;
  severity: SeverityLevel;
  status: IssueStatus;
  title: string;
  description: string;
  details: string;
  raw_data: Record<string, any>;
  backtrace: BacktraceFrame[] | string | null; // Can be array or JSON string
  file_path: string | null;
  ip_address: string | null;
  user_agent: string | null;
  first_detected: string;
  last_detected: string;
  detection_count: number;
  is_ignored: boolean;
  viewed: boolean;
  viewed_by: number | null;
  viewed_at: string | null;
  ignored_by: number | null;
  ignored_at: string | null;
  ignore_reason: string | null;
  resolved_by: number | null;
  resolved_at: string | null;
  resolution_notes: string | null;
  metadata: Record<string, any> | null;
  created_at: string;
  updated_at: string;
}

export interface IssuesResponse {
  issues: Issue[];
  total: number;
  pages: number;
  current_page: number;
  per_page: number;
}

export interface SecurityStats {
  total_issues: number;
  new_issues: number;
  ignored_issues: number;
  resolved_issues: number;
  by_severity: Record<SeverityLevel, number>;
  by_issuer: Record<string, number>;
  total_ignore_rules: number;
  active_ignore_rules: number;
  issues_last_24h: number;
  issues_last_7d: number;
}

export interface BotStats {
  is_running: boolean;
  channels_count: number;
  issuers_count: number;
  last_check: number;
  total_issues_found: number;
  new_issues: number;
  next_scheduled_check: number | null;
}

export interface Channel {
  name: string;
  enabled: boolean;
  available: boolean;
}

export interface Issuer {
  name: string;
  enabled: boolean;
  priority: number;
  is_realtime: boolean;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
}

