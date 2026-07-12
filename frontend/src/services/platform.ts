import { api, ApiResponse, fetchHealth, fetchSystemInfo } from "./api";
import type {
  CommandRow,
  DashboardSummary,
  LLMActiveInfo,
  LLMProvider,
  ModelInfo,
  NodeListResponse,
  PageResponse,
  RuntimeConfig,
  RuntimeUpdateStatus,
  SessionDetail,
  SessionRow,
  SystemInfo
} from "../types/platform";

export { fetchHealth, fetchSystemInfo };
export type { SystemInfo };

function cleanParams(input: Record<string, string | number | undefined>) {
  return Object.fromEntries(
    Object.entries(input).filter(([, value]) => value !== undefined && value !== "" && value !== null)
  );
}

export function toErrorMessage(error: unknown, fallback = "请求失败，请稍后重试") {
  if (typeof error === "object" && error && "response" in error) {
    const response = (error as { response?: { data?: { detail?: string; message?: string } } }).response;
    return response?.data?.detail || response?.data?.message || fallback;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return fallback;
}

export async function fetchDashboardSummary() {
  const response = await api.get<ApiResponse<DashboardSummary>>("/api/v1/dashboard/summary");
  return response.data.data;
}

export async function fetchNodes() {
  const response = await api.get<ApiResponse<NodeListResponse>>("/api/v1/nodes");
  return response.data.data;
}

export async function fetchSessionTopology(sessionId: string) {
  const response = await api.get<ApiResponse<NodeListResponse>>(`/api/v1/sessions/${sessionId}/topology`);
  return response.data.data;
}

export async function fetchSessions(params: { page: number; pageSize: number; query?: string }) {
  const response = await api.get<ApiResponse<PageResponse<SessionRow>>>("/api/v1/sessions", {
    params: cleanParams({
      page: params.page,
      page_size: params.pageSize,
      query: params.query?.trim()
    })
  });
  return response.data.data;
}

export async function fetchSessionDetail(sessionId: string) {
  const response = await api.get<ApiResponse<SessionDetail>>(`/api/v1/sessions/${sessionId}`, {
    params: { include_commands: false }
  });
  return response.data.data;
}

export async function fetchSessionCommands(sessionId: string, params: { page: number; pageSize: number; query?: string }) {
  const response = await api.get<ApiResponse<PageResponse<CommandRow>>>(`/api/v1/sessions/${sessionId}/commands`, {
    params: cleanParams({ page: params.page, page_size: params.pageSize, query: params.query?.trim() })
  });
  return response.data.data;
}

export async function deleteSession(sessionId: string) {
  await api.delete(`/api/v1/sessions/${sessionId}`);
}

export async function fetchCommands(params: {
  page: number;
  pageSize: number;
  query?: string;
  sessionId?: string;
  handler?: string;
}) {
  const response = await api.get<ApiResponse<PageResponse<CommandRow>>>("/api/v1/commands", {
    params: cleanParams({
      page: params.page,
      page_size: params.pageSize,
      query: params.query?.trim(),
      session_id: params.sessionId?.trim(),
      handler: params.handler?.trim()
    })
  });
  return response.data.data;
}

export async function fetchRuntimeConfig() {
  const response = await api.get<ApiResponse<RuntimeConfig>>("/api/v1/config/runtime");
  return response.data.data;
}

export async function updateRuntimeConfig(payload: Record<string, unknown>) {
  const response = await api.patch<ApiResponse<RuntimeConfig>>("/api/v1/config/runtime", payload);
  return response.data.data;
}

export async function fetchRuntimeUpdateStatus() {
  const response = await api.get<ApiResponse<RuntimeUpdateStatus>>("/api/v1/config/runtime/update-status", {
    params: { t: Date.now() }
  });
  return response.data.data;
}

// --- LLM Provider Management ---

export async function fetchLLMActive() {
  const response = await api.get<ApiResponse<LLMActiveInfo>>("/api/v1/llm/active");
  return response.data.data;
}

export async function fetchLLMProviders() {
  const response = await api.get<ApiResponse<LLMProvider[]>>("/api/v1/llm/providers");
  return response.data.data;
}

export async function switchLLMProvider(id: string) {
  const response = await api.post<ApiResponse<null>>(`/api/v1/llm/switch/${id}`);
  return response.data;
}

export async function setLLMEnabled(enabled: boolean) {
  const response = await api.put<ApiResponse<null>>("/api/v1/llm/enabled", { enabled });
  return response.data;
}

export async function updateLLMProvider(id: string, config: Partial<LLMProvider>) {
  const response = await api.put<ApiResponse<null>>(`/api/v1/llm/providers/${id}`, config);
  return response.data;
}

export async function testLLMProvider(id: string, baseUrl?: string, apiKey?: string) {
  const params = new URLSearchParams();
  if (baseUrl) params.set("base_url", baseUrl);
  if (apiKey) params.set("api_key", apiKey);
  const qs = params.toString();
  const url = `/api/v1/llm/test/${id}${qs ? "?" + qs : ""}`;
  const response = await api.post<ApiResponse<{ provider: string; status: string }>>(url);
  return response.data;
}

export async function fetchProviderModels(id: string, baseUrl?: string, apiKey?: string): Promise<ModelInfo[]> {
  const params = new URLSearchParams();
  if (baseUrl) params.set("base_url", baseUrl);
  if (apiKey) params.set("api_key", apiKey);
  const qs = params.toString();
  const url = `/api/v1/llm/providers/${id}/models${qs ? "?" + qs : ""}`;
  const response = await api.get<ApiResponse<ModelInfo[]>>(url);
  if (response.data.ok) {
    return response.data.data;
  }
  throw new Error(response.data.message);
}
