import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const INTERNAL_TOKEN = Deno.env.get("SCAMSHIELD_INTERNAL_TOKEN");

serve(async (req: Request) => {
  const incomingToken = req.headers.get("X-ScamShield-Token");

  if (!INTERNAL_TOKEN || !incomingToken || incomingToken !== INTERNAL_TOKEN) {
    return new Response(
      JSON.stringify({ error: "unauthorized" }),
      { status: 401, headers: { "Content-Type": "application/json" } }
    );
  }

  const placeholderResult = {
    schema_version: 1,
    risk_level: "YELLOW",
    headline: "We could not finish checking",
    manipulation_technique: "",
    explanation: "Analysis is not connected yet.",
    suspicious_signals: [],
    safe_action: "Verify another way before clicking or paying.",
    analysis_status: "unavailable",
    analysis_mode: "rules_only",
    url_check: "not_checked",
    language: "en",
  };

  return new Response(
    JSON.stringify(placeholderResult),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
});
