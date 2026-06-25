import React, { useState } from "react";
import { getSupabaseClient } from "../utils/supabase/client";
import { projectId, publicAnonKey } from "../utils/supabase/info";
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

interface SignupPageProps {
  onSignupSuccess: () => void;
  onSwitchToLogin: () => void;
}

export function SignupPage({
  onSignupSuccess,
  onSwitchToLogin,
}: SignupPageProps) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const supabase = getSupabaseClient();

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();

    if (password !== confirmPassword) {
      toast.error("Passwords do not match");
      return;
    }

    if (password.length < 6) {
      toast.error("Password must be at least 6 characters");
      return;
    }

    setLoading(true);

    try {
      // Use Supabase client-side auth signup
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            name: name,
          },
        },
      });

      if (error) {
        console.error("Signup error:", error);
        toast.error(`Signup failed: ${error.message}`);
        return;
      }

      toast.success(
        "Account created successfully! Registration successful! Please check your email to verify your account before signing in.",
      );
      onSignupSuccess();
    } catch (error) {
      console.error("Signup processing error:", error);
      toast.error("Signup failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignup = async () => {
    try {
      setLoading(true);

      const { error } = await supabase.auth.signInWithOAuth({
        provider: "google",
        options: {
          redirectTo: `${window.location.origin}/google-signup-callback`,
        },
      });

      if (error) {
        console.error("Google signup error:", error);
        toast.error(`Google signup failed: ${error.message}`);
      }
    } catch (error) {
      console.error("Google signup processing error:", error);
      toast.error("Google signup failed. Please try again.");
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
            Create Account
          </CardTitle>
          <CardDescription
            className="text-center"
            style={{ fontSize: "0.9375rem" }}
          >
            Join our threat intelligence platform
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Development Mode Info */}
          {/* <div className="p-3 rounded-lg border border-green-200 bg-green-50 dark:bg-green-950 dark:border-green-800">
            <p className="text-xs text-green-900 dark:text-green-100" style={{ fontWeight: 'var(--font-weight-medium)' }}>
              <strong>Quick Start:</strong> Create your account with any email and password (min 6 characters). Email verification is disabled for testing.
            </p>
          </div> */}

          <form onSubmit={handleSignup} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Full Name</Label>
              <Input
                id="name"
                type="text"
                placeholder="John Doe"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>
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
            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <Input
                id="confirmPassword"
                type="password"
                placeholder="••••••••"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </div>
            <Button
              type="submit"
              className="w-full"
              disabled={loading}
              style={{ fontWeight: "var(--font-weight-semibold)" }}
            >
              {loading ? "Creating account..." : "Sign Up"}
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
            onClick={handleGoogleSignup}
            style={{ fontWeight: "var(--font-weight-medium)" }}
          >
            <Mail className="mr-2 h-4 w-4" />
            Sign up with Google
          </Button>

          <div className="text-center text-sm">
            Already have an account?{" "}
            <button
              type="button"
              onClick={onSwitchToLogin}
              className="hover:underline"
              style={{
                color: "var(--primary)",
                fontWeight: "var(--font-weight-semibold)",
              }}
            >
              Sign in
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
