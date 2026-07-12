import { createContext, useContext, useEffect, useMemo, useState } from "react";

import { fetchMe, login as loginRequest, logout as logoutRequest } from "../services/auth";
import { clearSession, CurrentUser, getStoredUser, getToken, saveUser } from "../services/session";

interface AuthContextValue {
  user: CurrentUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(() => getStoredUser());
  const [loading, setLoading] = useState(Boolean(getToken()));

  async function refresh() {
    const token = getToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      const current = await fetchMe();
      saveUser(current);
      setUser(current);
    } catch {
      clearSession();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }

  async function login(username: string, password: string) {
    const current = await loginRequest(username, password);
    setUser(current);
  }

  async function logout() {
    await logoutRequest();
    clearSession();
    setUser(null);
  }

  useEffect(() => {
    refresh();
  }, []);

  const value = useMemo(() => ({ user, loading, login, logout, refresh }), [user, loading]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return value;
}
