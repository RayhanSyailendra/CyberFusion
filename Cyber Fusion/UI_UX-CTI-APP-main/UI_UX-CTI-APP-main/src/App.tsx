import React, { useEffect, useState } from "react";
import {
  Routes,
  Route,
  Navigate,
  useNavigate,
  useLocation,
} from "react-router-dom";

import { getSupabaseClient } from "./utils/supabase/client";

import { LoginPage } from "./components/LoginPage";
import { SignupPage } from "./components/SignupPage";
import { DashboardPage } from "./components/DashboardPage";
import { HistoryPage } from "./components/HistoryPage";
import { SettingsPage } from "./components/SettingsPage";
import { AdminDashboard } from "./components/AdminDashboard";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { AppSidebar } from "./components/layout/AppSidebar";
import { GoogleSignupCallback } from "./components/GoogleSignupCallback";

import { Button } from "./components/ui/button";
import { Toaster } from "./components/ui/sonner";
import { Menu, X } from "lucide-react";

export default function App() {
  const supabase = getSupabaseClient();

  const navigate = useNavigate();
  const location = useLocation();

  const [loading, setLoading] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [accessToken, setAccessToken] = useState("");

  const [user, setUser] = useState<any>(null);
  const [userRole, setUserRole] = useState<string | null>(null);

  // Tambahan: simpan data profile dari tabel profiles
  const [profile, setProfile] = useState<any>(null);

  const apiBaseUrl = "http://103.129.149.89:5000";
  /* ===========================================
     FETCH USER PROFILE
  =========================================== */
  const fetchUserProfile = async (authUser: any) => {
    try {
      if (!authUser?.id) {
        setUserRole("user");
        setProfile(null);
        return;
      }

      const { data, error } = await supabase
        .from("profiles")
        .select("id, email, name, role")
        .eq("id", authUser.id)
        .maybeSingle();

      console.log("AUTH USER:", authUser);
      console.log("PROFILE DATA:", data);

      if (error) {
        console.error("Failed to fetch user profile:", error);
        setUserRole("user");
        setProfile(null);
        return;
      }

      setProfile(data);
      setUserRole(data?.role ?? "user");
    } catch (error) {
      console.error("Unexpected profile fetch error:", error);
      setUserRole("user");
      setProfile(null);
    }
  };

  /* ===========================================
     CHECK SESSION
  =========================================== */
  useEffect(() => {
    const init = async () => {
      const {
        data: { session },
      } = await supabase.auth.getSession();

      if (session) {
        setIsAuthenticated(true);
        setAccessToken(session.access_token);
        setUser(session.user);

        await fetchUserProfile(session.user);
      } else {
        setIsAuthenticated(false);
        setAccessToken("");
        setUser(null);
        setUserRole(null);
        setProfile(null);
      }

      setTimeout(() => {
        setLoading(false);
      }, 500);
    };

    init();

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session) {
        setIsAuthenticated(true);
        setAccessToken(session.access_token);
        setUser(session.user);

        fetchUserProfile(session.user);
      } else {
        setIsAuthenticated(false);
        setAccessToken("");
        setUser(null);
        setUserRole(null);
        setProfile(null);
        navigate("/login");
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  /* ===========================================
     MOBILE SIDEBAR
  =========================================== */
  useEffect(() => {
    if (window.innerWidth < 768) {
      setSidebarOpen(false);
    }
  }, []);

  /* ===========================================
     LOGIN SUCCESS
  =========================================== */
  const handleLoginSuccess = async (token: string, userData: any) => {
    setIsAuthenticated(true);
    setAccessToken(token);
    setUser(userData);

    await fetchUserProfile(userData);

    navigate("/dashboard");
  };

  /* ===========================================
     SIGNUP SUCCESS
  =========================================== */
  const handleSignupSuccess = () => {
    navigate("/login");
  };

  /* ===========================================
     USER UPDATE FROM SETTINGS
  =========================================== */
  const handleUserUpdate = async (updatedUser: any) => {
    setUser(updatedUser);

    const updatedName =
      updatedUser?.user_metadata?.full_name ||
      updatedUser?.user_metadata?.name ||
      updatedUser?.user_metadata?.preferred_username ||
      "";

    setProfile((prev: any) => ({
      ...prev,
      id: prev?.id || updatedUser?.id,
      email: prev?.email || updatedUser?.email,
      role: prev?.role || userRole || "user",
      name: updatedName || prev?.name,
    }));

    // Ambil ulang dari database agar nama benar-benar sesuai tabel profiles
    await fetchUserProfile(updatedUser);
  };

  /* ===========================================
     LOGOUT
  =========================================== */
  const handleLogout = async () => {
    localStorage.removeItem("threat-analysis-last-result");

    await supabase.auth.signOut();

    setUserRole(null);
    setProfile(null);
    setUser(null);
    setAccessToken("");
    setIsAuthenticated(false);

    navigate("/login");
  };

  /* ===========================================
     LOADING
  =========================================== */
  if (loading) {
    return (
      <div className="fixed inset-0 flex items-center justify-center bg-background z-[9999]">
        <div className="flex flex-col items-center gap-4">
          <div className="cyber-loading-spinner" />

          <div className="text-center">
            <h1
              className="text-xl"
              style={{
                fontWeight: "var(--font-weight-bold)",
                color: "var(--foreground)",
              }}
            >
              Cyber Fusion
            </h1>

            <p className="text-sm text-muted-foreground mt-1">
              Loading<span className="loading-dots"></span>
            </p>
          </div>
        </div>
      </div>
    );
  }

  const showSidebar =
    isAuthenticated &&
    location.pathname !== "/login" &&
    location.pathname !== "/signup";

  return (
    <>
      <div className="min-h-dvh bg-background flex flex-col">
        {/* SIDEBAR */}
        {showSidebar && (
          <AppSidebar
            sidebarOpen={sidebarOpen}
            setSidebarOpen={setSidebarOpen}
            user={user}
            userRole={userRole}
            profileName={profile?.name}
            onLogout={handleLogout}
          />
        )}

        {/* CONTENT */}
        <div
          className={
            (showSidebar && sidebarOpen
              ? "md:ml-64 transition-all duration-300"
              : "md:ml-0 transition-all duration-300") + " flex flex-col flex-1"
          }
        >
          {/* Header */}
          {showSidebar && (
            <header className="sticky top-0 z-30 bg-background border-b">
              <div className="flex items-center justify-between p-3 sm:p-4">
                {/* Tombol Sidebar */}
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setSidebarOpen(!sidebarOpen)}
                  className="
                  hover:bg-transparent
                  active:bg-transparent
                  focus:bg-transparent
                  focus-visible:ring-0
                "
                >
                  {sidebarOpen ? (
                    <X className="h-5 w-5" />
                  ) : (
                    <Menu className="h-5 w-5" />
                  )}
                </Button>

                {/* Tanggal */}
                <div className="flex items-center gap-2 sm:gap-4">
                  <div
                    className="text-xs sm:text-sm text-muted-foreground hidden sm:block"
                    style={{ fontWeight: "var(--font-weight-medium)" }}
                  >
                    {new Date().toLocaleDateString("en-US", {
                      weekday: "long",
                      year: "numeric",
                      month: "long",
                      day: "numeric",
                    })}
                  </div>

                  <div
                    className="text-xs text-muted-foreground sm:hidden"
                    style={{ fontWeight: "var(--font-weight-medium)" }}
                  >
                    {new Date().toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                      year: "numeric",
                    })}
                  </div>
                </div>
              </div>
            </header>
          )}

          {/* PAGE */}
          <main className={showSidebar ? "p-4 md:p-6" : ""}>
            <Routes>
              {/* PUBLIC ROUTES */}
              <Route
                path="/login"
                element={
                  isAuthenticated ? (
                    <Navigate to="/dashboard" replace />
                  ) : (
                    <LoginPage
                      onLoginSuccess={handleLoginSuccess}
                      onSwitchToSignup={() => navigate("/signup")}
                    />
                  )
                }
              />

              <Route
                path="/signup"
                element={
                  isAuthenticated ? (
                    <Navigate to="/dashboard" replace />
                  ) : (
                    <SignupPage
                      onSignupSuccess={handleSignupSuccess}
                      onSwitchToLogin={() => navigate("/login")}
                    />
                  )
                }
              />

              <Route
                path="/google-signup-callback"
                element={<GoogleSignupCallback />}
              />

              {/* PRIVATE ROUTES */}
              <Route
                path="/dashboard"
                element={
                  <ProtectedRoute isAuthenticated={isAuthenticated}>
                    <DashboardPage
                      accessToken={accessToken}
                      apiBaseUrl={apiBaseUrl}
                    />
                  </ProtectedRoute>
                }
              />

              <Route
                path="/history"
                element={
                  <ProtectedRoute isAuthenticated={isAuthenticated}>
                    <HistoryPage
                      accessToken={accessToken}
                      apiBaseUrl={apiBaseUrl}
                    />
                  </ProtectedRoute>
                }
              />

              <Route
                path="/admin"
                element={
                  <ProtectedRoute isAuthenticated={isAuthenticated}>
                    {userRole === "admin" ? (
                      <AdminDashboard
                        accessToken={accessToken}
                        apiBaseUrl={apiBaseUrl}
                      />
                    ) : (
                      <Navigate to="/dashboard" replace />
                    )}
                  </ProtectedRoute>
                }
              />

              <Route
                path="/settings"
                element={
                  <ProtectedRoute isAuthenticated={isAuthenticated}>
                    <SettingsPage
                      accessToken={accessToken}
                      apiBaseUrl={apiBaseUrl}
                      user={user}
                      onLogout={handleLogout}
                      onUserUpdate={handleUserUpdate}
                    />
                  </ProtectedRoute>
                }
              />

              {/* DEFAULT */}
              <Route
                path="/"
                element={
                  <Navigate
                    to={isAuthenticated ? "/dashboard" : "/login"}
                    replace
                  />
                }
              />

              {/* NOT FOUND */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>

      <Toaster />
    </>
  );
}
