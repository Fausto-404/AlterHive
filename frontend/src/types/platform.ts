export interface PageResponse<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
}

export interface DashboardSummary {
  total_sessions: number;
  active_sessions: number;
  total_commands: number;
  total_evidence_hits: number;
  total_score: number;
  unique_attackers: number;
  ppf_triggered_count: number;
  playbook_metrics: { handler: string; count: number }[];
  top_attackers: { ip: string; sessions: number }[];
  recent_sessions: {
    session_id: string;
    username: string;
    remote_addr: string;
    connected_at: string;
    commands: number;
    evidence_hits?: number;
    score?: number;
    ppf_triggered?: boolean;
  }[];
}

export interface NodeItem {
  ip: string;
  hostname: string;
  role: string;
  os: string;
  services: { port: number; protocol: string; state: string }[];
  segment_cidr?: string;
  reachable_via?: string;
  required_state?: string[];
  shadow?: boolean;
  theme?: string;
  compromise_mode?: string;
  status: string;
  last_seen: string;
}

export interface NetworkSegment {
  cidr: string;
  name: string;
  zone: string;
  gateway_ip: string;
  shadow: boolean;
  visible_after?: string[];
}

export interface NetworkEdge {
  from: string;
  to: string;
  type: string;
  via: string;
  required_state?: string[];
  status: string;
}

export interface NodeListResponse {
  nodes: NodeItem[];
  segments: NetworkSegment[];
  edges: NetworkEdge[];
  total: number;
  session?: {
    session_id: string;
    username: string;
    remote_addr: string;
    current_target?: string;
    access_states?: string[];
  };
}

export interface SessionRow {
  session_id: string;
  username: string;
  remote_addr: string;
  hostname: string;
  connected_at: string;
  command_count: number;
  evidence_hits: number;
  score: number;
  ppf_triggered: boolean;
  status: string;
}

export interface CommandRow {
  command: string;
  output: string;
  timestamp: string;
  intent: string;
  evidence_hits: string[];
  score: number;
  session_id?: string;
  username?: string;
  remote_addr?: string;
  hostname?: string;
  llm_generated?: boolean;
}

export interface ShadowHost {
  ip: string;
  hostname: string;
  role: string;
  triggered_by: string;
}

export interface SSHContext {
  Hostname: string;
  User: string;
  CWD: string;
  SubnetLocalIP: string;
}

export interface SessionDetail {
  session_id: string;
  username: string;
  remote_addr: string;
  hostname: string;
  user: string;
  cwd: string;
  connected_at: string;
  command_count: number;
  evidence_hits: number;
  evidence_tokens: string[];
  score: number;
  ppf_triggered: boolean;
  shell_mode?: string;
  current_target?: string;
  current_host_ip?: string;
  ssh_stack?: SSHContext[];
  loop_metrics: {
    evidence_hit_count: number;
    credential_reuse_attempt: number;
    protocol_switch_count: number;
    real_network_touch_count: number;
  };
  shadow_hosts: ShadowHost[];
  commands: CommandRow[];
  events: string[];
  status: string;
}

export interface RuntimeConfig {
  honeypot: {
    ssh_port: number;
    api_port: number;
    topology_cidr: string;
    session_timeout: number;
  };
  restart_required?: boolean;
  restart_queued?: boolean;
  llm: {
    enabled: boolean;
    provider: string;
    base_url: string;
    model: string;
    api_key: string;
  };
}

export interface RuntimeUpdateStatus {
  phase: "idle" | "queued" | "running" | "complete" | "failed";
  message: string;
  updated_at: string;
  error?: string;
  config?: RuntimeConfig["honeypot"];
}

export interface LLMProvider {
  id: string;
  name: string;
  type: string;
  base_url: string;
  api_key: string;
  model: string;
  max_tokens: number;
  temperature: number;
  enabled: boolean;
}

export interface LLMActiveInfo {
  active_provider: string;
  enabled: boolean;
  is_active: boolean;
  providers: LLMProvider[];
}

export interface ModelInfo {
  id: string;
  owned_by?: string;
}

export interface SystemInfo {
  app_name: string;
  app_version: string;
  api_prefix: string;
  mode: string;
}
