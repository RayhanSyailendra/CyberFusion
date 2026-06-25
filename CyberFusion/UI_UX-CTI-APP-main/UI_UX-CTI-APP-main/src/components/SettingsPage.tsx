import React, { useState, useEffect } from "react";
import { getSupabaseClient } from "../utils/supabase/client";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Separator } from "./ui/separator";
import { User, LogOut, Save } from "lucide-react";
import { toast } from "sonner";

interface SettingsPageProps {
  accessToken: string;
  apiBaseUrl: string;
  user: any;
  onLogout: () => void;
  onUserUpdate: (updatedUser: any) => void;
}

export function SettingsPage({
  accessToken,
  apiBaseUrl,
  user,
  onLogout,
  onUserUpdate,
}: SettingsPageProps) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);

  const supabase = getSupabaseClient();

  useEffect(() => {
    if (user) {
      setName(
        user.user_metadata?.name ||
          user.user_metadata?.full_name ||
          user.user_metadata?.preferred_username ||
          user.email?.split("@")[0] ||
          "",
      );

      setEmail(user.email || "");
    }
  }, [user]);

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();

    const cleanName = name.trim();

    if (!cleanName) {
      toast.error("Full name cannot be empty");
      return;
    }

    setLoading(true);

    try {
      /**
       * 1. Update nama ke backend/database profiles
       */
      const response = await fetch(`${apiBaseUrl}/profile`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          name: cleanName,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        console.error("Profile update error:", data);
        toast.error(`Update failed: ${data.error || "Unknown error"}`);
        return;
      }

      /**
       * 2. Update juga metadata Supabase Auth
       * Ini penting agar user_metadata ikut berubah.
       */
      const { data: updatedAuthData, error: updateAuthError } =
        await supabase.auth.updateUser({
          data: {
            ...user?.user_metadata,
            name: cleanName,
            full_name: cleanName,
            preferred_username: cleanName,
          },
        });

      if (updateAuthError) {
        console.warn("Supabase auth metadata update warning:", updateAuthError);
      }

      /**
       * 3. Ambil ulang user terbaru dari Supabase
       * Supaya state user benar-benar fresh.
       */
      const { data: refreshedUserData, error: refreshError } =
        await supabase.auth.getUser();

      if (refreshError) {
        console.warn("Refresh user warning:", refreshError);
      }

      /**
       * 4. Bentuk user terbaru secara manual sebagai fallback.
       * Ini memastikan sidebar langsung berubah tanpa harus logout/login ulang.
       */
      const updatedUser = refreshedUserData?.user ||
        updatedAuthData?.user || {
          ...user,
          user_metadata: {
            ...user?.user_metadata,
            name: cleanName,
            full_name: cleanName,
            preferred_username: cleanName,
          },
        };

      onUserUpdate({
        ...updatedUser,
        user_metadata: {
          ...updatedUser.user_metadata,
          name: cleanName,
          full_name: cleanName,
          preferred_username: cleanName,
        },
      });

      setName(cleanName);

      toast.success("Profile updated successfully!");
    } catch (error) {
      console.error("Profile update processing error:", error);
      toast.error("Profile update failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await supabase.auth.signOut();
      toast.success("Logged out successfully");
      onLogout();
    } catch (error) {
      console.error("Logout error:", error);
      toast.error("Logout failed");
    }
  };

  return (
    <div className="space-y-6 w-full">
      <div>
        <h1
          style={{
            fontSize: "2.25rem",
            fontWeight: "var(--font-weight-bold)",
            letterSpacing: "-0.02em",
            marginBottom: "0.5rem",
          }}
        >
          Settings
        </h1>
        <p className="text-muted-foreground" style={{ fontSize: "0.9375rem" }}>
          Manage your account settings and preferences
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            Profile Information
          </CardTitle>
          <CardDescription>Update your personal information</CardDescription>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleUpdateProfile} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Full Name</Label>
              <Input
                id="name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Enter your name"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                disabled
                className="bg-muted"
              />
              <p className="text-xs text-muted-foreground">
                Email address cannot be changed
              </p>
            </div>

            <Button type="submit" disabled={loading}>
              <Save className="mr-2 h-4 w-4" />
              {loading ? "Saving..." : "Save Changes"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Separator />

      <Card>
        <CardContent className="mt-4">
          <Button variant="destructive" onClick={handleLogout}>
            <LogOut className="mr-2 h-4 w-4" />
            Sign Out
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
