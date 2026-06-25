/// <reference lib="deno.ns" />

import { Hono } from "npm:hono";
import { cors } from "npm:hono/cors";
import { logger } from "npm:hono/logger";
import { createClient } from "npm:@supabase/supabase-js@2";

import * as kv from "./kv_store.tsx";
import {
  analyzeWithVirusTotal,
  analyzeWithAbuseIPDB,
  generateAIAnalysis,
} from "./threat-analysis.tsx";

const app = new Hono();

/* =====================================================
   SUPABASE CLIENT (SERVER SIDE)
===================================================== */
const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/* =====================================================
   GLOBAL MIDDLEWARE
===================================================== */

// logger
app.use("*", logger(console.log));

// cors
app.use(
  "/*",
  cors({
    origin: "*",
    allowHeaders: ["Content-Type", "Authorization"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    exposeHeaders: ["Content-Length"],
    maxAge: 600,
  }),
);

/* =====================================================
   AUTH MIDDLEWARE
===================================================== */

const publicRoutes = ["/health"];

app.use("*", async (c, next) => {
  if (publicRoutes.includes(c.req.path)) {
    return await next();
  }

  const authHeader = c.req.header("Authorization");

  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const token = authHeader.replace("Bearer ", "");

  const {
    data: { user },
    error,
  } = await supabase.auth.getUser(token);

  if (error || !user) {
    return c.json({ error: "Invalid token" }, 401);
  }

  c.set("user", user);

  await next();
});

/* =====================================================
   PUBLIC ROUTE
===================================================== */

app.get("/health", (c) => {
  return c.json({
    status: "ok",
    message: "CTI API Running",
  });
});

/* =====================================================
   ANALYZE THREAT
===================================================== */

app.post("/analyze", async (c) => {
  try {
    const user = c.get("user");
    const { type, value } = await c.req.json();

    let vtData = null;
    let abuseData = null;
    let aiAnalysis = "";

    try {
      vtData = await analyzeWithVirusTotal(type, value);
    } catch (error: any) {
      vtData = { error: error.message };
    }

    if (type === "ip") {
      try {
        abuseData = await analyzeWithAbuseIPDB(value);
      } catch (error: any) {
        abuseData = { error: error.message };
      }
    }

    try {
      aiAnalysis = await generateAIAnalysis(vtData, abuseData, type, value);
    } catch {
      aiAnalysis = "AI analysis unavailable";
    }

    const analysisId = `analysis_${user.id}_${Date.now()}`;

    await kv.set(analysisId, {
      userId: user.id,
      type,
      value,
      vtData,
      abuseData,
      aiAnalysis,
      timestamp: new Date().toISOString(),
    });

    return c.json({
      success: true,
      analysisId,
      vtData,
      abuseData,
      aiAnalysis,
    });
  } catch (error) {
    return c.json({ error: "Analysis failed" }, 500);
  }
});

/* =====================================================
   SAVE HISTORY
===================================================== */

app.post("/history", async (c) => {
  try {
    const user = c.get("user");

    const { analysisId, fileName, format } = await c.req.json();

    const historyId = `history_${user.id}_${Date.now()}`;

    await kv.set(historyId, {
      userId: user.id,
      analysisId,
      fileName,
      format,
      downloadedAt: new Date().toISOString(),
    });

    return c.json({
      success: true,
      historyId,
    });
  } catch {
    return c.json({ error: "Failed to save history" }, 500);
  }
});

/* =====================================================
   GET HISTORY
===================================================== */

app.get("/history", async (c) => {
  try {
    const user = c.get("user");

    const historyItems = await kv.getByPrefix(`history_${user.id}_`);

    const sorted = historyItems.sort((a: any, b: any) => {
      return (
        new Date(b.downloadedAt).getTime() - new Date(a.downloadedAt).getTime()
      );
    });

    return c.json({
      success: true,
      history: sorted,
    });
  } catch {
    return c.json({ error: "Failed to fetch history" }, 500);
  }
});

/* =====================================================
   GET ANALYSIS BY ID
===================================================== */

app.get("/analysis/:id", async (c) => {
  try {
    const user = c.get("user");
    const id = c.req.param("id");

    const analysis = await kv.get(id);

    if (!analysis || analysis.userId !== user.id) {
      return c.json({ error: "Not found" }, 404);
    }

    return c.json({
      success: true,
      analysis,
    });
  } catch {
    return c.json({ error: "Failed to fetch analysis" }, 500);
  }
});

/* =====================================================
   UPDATE PROFILE
===================================================== */

app.put("/profile", async (c) => {
  try {
    const user = c.get("user");
    const { name } = await c.req.json();

    const { data, error } = await supabase.auth.admin.updateUserById(user.id, {
      user_metadata: { name },
    });

    if (error) {
      return c.json({ error: error.message }, 400);
    }

    return c.json({
      success: true,
      data,
    });
  } catch {
    return c.json({ error: "Failed to update profile" }, 500);
  }
});

/* =====================================================
   ABUSE CHECK
===================================================== */

app.post("/abuse-check", async (c) => {
  try {
    const { value } = await c.req.json();

    const data = await analyzeWithAbuseIPDB(value);

    return c.json({
      success: true,
      data,
    });
  } catch (error: any) {
    return c.json({
      error: error.message || "Abuse check failed",
    });
  }
});

/* =====================================================
   USER INFO
===================================================== */

app.get("/me", async (c) => {
  const user = c.get("user");

  return c.json({
    success: true,
    user,
  });
});

/* =====================================================
   NOT FOUND
===================================================== */

app.notFound((c) => {
  return c.json({ error: "Route not found" }, 404);
});

/* =====================================================
   START SERVER
===================================================== */

Deno.serve(app.fetch);
