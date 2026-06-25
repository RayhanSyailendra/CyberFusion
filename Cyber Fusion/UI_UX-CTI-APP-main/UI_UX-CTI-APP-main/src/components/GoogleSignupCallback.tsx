import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getSupabaseClient } from "../utils/supabase/client";
import { toast } from "sonner";

export function GoogleSignupCallback() {
  const navigate = useNavigate();
  const supabase = getSupabaseClient();
  const [processing, setProcessing] = useState(true);

  useEffect(() => {
    const finishGoogleSignup = async () => {
      try {
        // Beri waktu Supabase membaca session dari URL callback OAuth
        const {
          data: { session },
        } = await supabase.auth.getSession();

        if (session) {
          // Logout agar setelah signup tidak langsung masuk dashboard
          await supabase.auth.signOut();
        }

        toast.success("Google account created successfully! Please sign in.");
        navigate("/login?signup=success", { replace: true });
      } catch (error) {
        console.error("Google signup callback error:", error);
        toast.error("Google signup failed. Please try again.");
        navigate("/signup", { replace: true });
      } finally {
        setProcessing(false);
      }
    };

    finishGoogleSignup();
  }, [navigate, supabase]);

  return (
    <div className="min-h-screen flex items-center justify-center text-lg">
      {processing ? "Finishing Google signup..." : "Redirecting..."}
    </div>
  );
}