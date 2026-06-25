import React, { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { getSupabaseClient } from "../utils/supabase/client";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card";
import { Shield, Mail } from "lucide-react";
import { toast } from "sonner";

interface LoginPageProps {
  onLoginSuccess: (accessToken: string, user: any) => void;
  onSwitchToSignup: () => void;
}

export function LoginPage({
  onLoginSuccess,
  onSwitchToSignup,
}: LoginPageProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const supabase = getSupabaseClient();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const params = new URLSearchParams(location.search);

    if (params.get("signup") === "success") {
      toast.success("Google account created successfully! Please sign in.");
      navigate("/login", { replace: true });
    }
  }, [location.search, navigate]);
  
  const handleEmailLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (error) {
        console.error("Login error:", error);
        toast.error(`Login failed: ${error.message}`);
        return;
      }

      if (data?.session?.access_token) {
        toast.success("Login successful!");
        onLoginSuccess(data.session.access_token, data.user);
      }
    } catch (error) {
      console.error("Login processing error:", error);
      toast.error("Login failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    try {
      setLoading(true);

      const { error } = await supabase.auth.signInWithOAuth({
        provider: "google",
        options: {
          redirectTo: `${window.location.origin}/dashboard`,
        },
      });

      if (error) {
        console.error("Google login error:", error);
        toast.error(`Google login failed: ${error.message}`);
      }
    } catch (error) {
      console.error("Google login processing error:", error);
      toast.error("Google login failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen w-full flex items-center justify-center p-4"
      style={{
        background: "linear-gradient(135deg, var(--sidebar) 0%, #1E293B 100%)",
      }}
    >
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-4">
          <div className="flex justify-center">
            <div
              className="w-16 h-16 rounded-lg flex items-center justify-center"
              style={{
                background:
                  "linear-gradient(135deg, var(--accent) 0%, var(--primary) 100%)",
              }}
            >
              <Shield className="w-10 h-10 text-white" />
            </div>
          </div>
          <CardTitle
            className="text-center"
            style={{
              fontSize: "1.875rem",
              fontWeight: "var(--font-weight-bold)",
              letterSpacing: "-0.015em",
            }}
          >
            Cyber Fusion
          </CardTitle>
          <CardDescription
            className="text-center"
            style={{ fontSize: "0.9375rem" }}
          >
            Sign in to access threat analysis platform
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Development Mode Info */}
          {/* <div className="p-3 rounded-lg border border-blue-200 bg-blue-50 dark:bg-blue-950 dark:border-blue-800">
            <p className="text-xs text-blue-900 dark:text-blue-100" style={{ fontWeight: 'var(--font-weight-medium)' }}>
              <strong>Testing:</strong> Create an account using Sign Up, or use:<br/>
              Email: <code className="px-1 py-0.5 rounded bg-blue-100 dark:bg-blue-900">test@example.com</code><br/>
              Password: <code className="px-1 py-0.5 rounded bg-blue-100 dark:bg-blue-900">test123456</code>
            </p>
          </div> */}

          <form onSubmit={handleEmailLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <Button
              type="submit"
              className="w-full"
              disabled={loading}
              style={{ fontWeight: "var(--font-weight-semibold)" }}
            >
              {loading ? "Signing in..." : "Sign In"}
            </Button>
          </form>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span
                className="bg-background px-2 text-muted-foreground"
                style={{
                  fontWeight: "var(--font-weight-medium)",
                  letterSpacing: "0.05em",
                }}
              >
                Or continue with
              </span>
            </div>
          </div>

          <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={handleGoogleLogin}
            style={{ fontWeight: "var(--font-weight-medium)" }}
          >
            <Mail className="mr-2 h-4 w-4" />
            Sign in with Google
          </Button>

          <div className="text-center text-sm">
            Don't have an account?{" "}
            <button
              type="button"
              onClick={onSwitchToSignup}
              className="hover:underline"
              style={{
                color: "var(--primary)",
                fontWeight: "var(--font-weight-semibold)",
              }}
            >
              Sign up
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
