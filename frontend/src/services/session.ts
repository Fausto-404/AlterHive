export interface CurrentUser {
  id: string;
  username: string;
  display_name: string;
  role: string;
  active: boolean;
  permissions: string[];
  created_at?: string;
  updated_at?: string;
  last_login_at?: string;
}

const TOKEN_KEY = "ai_honeypot_access_token";
const USER_KEY = "ai_honeypot_current_user";

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) || "";
}

export function getStoredUser(): CurrentUser | null {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as CurrentUser;
  } catch {
    return null;
  }
}

export function saveSession(token: string, user: CurrentUser) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function saveUser(user: CurrentUser) {
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function hasPermission(user: CurrentUser | null, permission?: string) {
  if (!permission) return true;
  return Boolean(user?.permissions?.includes(permission));
}
