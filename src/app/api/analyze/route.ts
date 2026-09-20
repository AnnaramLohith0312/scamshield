import { NextRequest, NextResponse } from "next/server";

const EDGE_URL = process.env.SCAMSHIELD_EDGE_URL;
const INTERNAL_TOKEN = process.env.SCAMSHIELD_INTERNAL_TOKEN;
const MAX_BODY_BYTES = 16 * 1024;
const TIMEOUT_MS = 15000;

export async function POST(req: NextRequest) {
  if (!EDGE_URL || !INTERNAL_TOKEN) {
    return NextResponse.json(
      { error: "server_misconfigured" },
      { status: 500, headers: { "Cache-Control": "no-store" } }
    );
  }

  let body: unknown;
  try {
    const raw = await req.text();
    if (raw.length > MAX_BODY_BYTES) {
      return NextResponse.json(
        { error: "payload_too_large" },
        { status: 413, headers: { "Cache-Control": "no-store" } }
      );
    }
    body = JSON.parse(raw);
  } catch {
    return NextResponse.json(
      { error: "invalid_json" },
      { status: 400, headers: { "Cache-Control": "no-store" } }
    );
  }

  const { text, language } = body as { text?: unknown; language?: unknown };
  if (typeof text !== "string" || text.trim().length === 0 || text.length > 3000) {
    return NextResponse.json(
      { error: "invalid_text" },
      { status: 400, headers: { "Cache-Control": "no-store" } }
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const edgeResponse = await fetch(EDGE_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ScamShield-Token": INTERNAL_TOKEN,
      },
      body: JSON.stringify({
        text,
        language: typeof language === "string" ? language : "en",
      }),
      signal: controller.signal,
    });

    const data = await edgeResponse.json();
    return NextResponse.json(data, {
      status: edgeResponse.status,
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json(
      {
        schema_version: 1,
        risk_level: "YELLOW",
        headline: "We could not finish checking",
        manipulation_technique: "",
        explanation: "The checking service did not respond in time.",
        suspicious_signals: [],
        safe_action: "Verify another way before clicking or paying.",
        analysis_status: "unavailable",
        analysis_mode: "rules_only",
        url_check: "not_checked",
        language: "en",
      },
      { status: 200, headers: { "Cache-Control": "no-store" } }
    );
  } finally {
    clearTimeout(timeout);
  }
}
