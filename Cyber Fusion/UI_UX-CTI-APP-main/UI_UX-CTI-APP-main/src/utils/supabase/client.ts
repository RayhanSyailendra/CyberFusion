import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { projectId, publicAnonKey } from "./info";

let supabaseInstance: SupabaseClient | null = null;

export function getSupabaseClient(): SupabaseClient {
  if (!supabaseInstance) {
    supabaseInstance = createClient(
      `https://${projectId}.supabase.co`,
      publicAnonKey,
      {
        auth: {
          persistSession: true,
          autoRefreshToken: true,
          detectSessionInUrl: true,
          storageKey: `sb-${projectId}-auth-token`,
        },
      },
    );
  }

  return supabaseInstance;
}

export function resetSupabaseClient() {
  supabaseInstance = null;
}
