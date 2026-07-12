import { api, ApiResponse } from "./api";
import { CurrentUser, saveSession } from "./session";

export interface LoginResult {
  access_token: string;
  token_type: string;
  user: CurrentUser;
}

export async function login(username: string, password: string): Promise<CurrentUser> {
  const response = await api.post<ApiResponse<LoginResult>>("/api/v1/auth/login", { username, password });
  const result = response.data.data;
  saveSession(result.access_token, result.user);
  return result.user;
}

export async function fetchMe(): Promise<CurrentUser> {
  const response = await api.get<ApiResponse<CurrentUser>>("/api/v1/auth/me");
  return response.data.data;
}

export async function logout() {
  await api.post("/api/v1/auth/logout").catch(() => undefined);
}
