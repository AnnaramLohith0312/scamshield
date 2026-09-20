export interface RuleSignal {
  id: string;
  evidence: string;
  minRisk: "RED" | "YELLOW";
}

export interface RuleResult {
  signals: RuleSignal[];
  hasRedFloor: boolean;
  hasYellowFloor: boolean;
}

export function extractUrls(text: string): string[] {
  const normalized = text
    .replace(/hxxps?:\/\//gi, "https://")
    .replace(/\[\.\]/g, ".");

  const urlPattern = /\b((?:https?:\/\/|www\.)[^\s<>"')]+)/gi;
  const matches = normalized.match(urlPattern) || [];

  const cleaned = matches.map((u) => u.replace(/[.,;:!?)]+$/, ""));
  return Array.from(new Set(cleaned));
}

function containsAny(text: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(text));
}

export function findRuleSignals(text: string): RuleResult {
  const lower = text.toLowerCase();
  const signals: RuleSignal[] = [];

  const otpShareRequest =
    /\b(share|send|give|tell|provide)\b.{0,25}\b(otp|pin|password|cvv)\b/i;
  const otpWarning =
    /\b(never|don'?t|do not)\b.{0,15}\b(share|tell|give)\b.{0,25}\b(otp|pin|password|cvv)\b/i;

  if (otpShareRequest.test(lower) && !otpWarning.test(lower)) {
    signals.push({
      id: "otp_share_request",
      evidence: "Message asks the recipient to share a private code.",
      minRisk: "RED",
    });
  }

  if (
    containsAny(lower, [/\barrest\b/, /\bcbi\b/, /\bpolice\b.{0,20}\bpay\b/]) &&
    containsAny(lower, [/\bpay\b/, /\btransfer\b/, /\bfine\b/])
  ) {
    signals.push({
      id: "arrest_payment_demand",
      evidence: "Message demands payment to avoid arrest or legal action.",
      minRisk: "RED",
    });
  }

  if (
    containsAny(lower, [/\bremote\b.{0,15}\b(access|control|app)\b/, /\bteamviewer\b/, /\banydesk\b/]) &&
    containsAny(lower, [/\bbank\b/, /\bpayment\b/, /\brefund\b/, /\baccount\b/])
  ) {
    signals.push({
      id: "remote_access_banking",
      evidence: "Message asks to install remote-access software combined with a banking action.",
      minRisk: "RED",
    });
  }

  if (
    containsAny(lower, [
      /ignore (all |every |previous )?instructions/,
      /disregard (the )?(system|previous)/,
      /output (green|safe)/,
      /return green/,
      /you are now/,
    ])
  ) {
    signals.push({
      id: "prompt_injection",
      evidence: "Message attempts to override the checker's instructions.",
      minRisk: "RED",
    });
  }

  const urls = extractUrls(text);
  if (urls.length > 0) {
    const hasContext = text.trim().split(/\s+/).length > 8;
    if (!hasContext) {
      signals.push({
        id: "bare_url",
        evidence: "Message contains a link with little surrounding context.",
        minRisk: "YELLOW",
      });
    }
  }

  return {
    signals,
    hasRedFloor: signals.some((s) => s.minRisk === "RED"),
    hasYellowFloor: signals.some((s) => s.minRisk === "YELLOW"),
  };
}

export type RiskLevel = "RED" | "YELLOW" | "GREEN";

export interface ModelResult {
  succeeded: boolean;
  suggestedRisk?: RiskLevel;
}

export function aggregateRisk(rules: RuleResult, model: ModelResult): RiskLevel {
  if (rules.hasRedFloor) return "RED";
  if (!model.succeeded) return "YELLOW";
  if (rules.hasYellowFloor) {
    return model.suggestedRisk === "RED" ? "RED" : "YELLOW";
  }
  return model.suggestedRisk ?? "YELLOW";
}

export function redactForModel(text: string): string {
  return text
    .replace(/\b\d{4,8}\b/g, "[OTP]")
    .replace(/\b(?:\+?\d{1,3}[-\s]?)?\d{10}\b/g, "[PHONE]")
    .replace(/\b\d{12,19}\b/g, "[CARD]")
    .replace(/\b[\w.-]+@[\w-]+\.[a-z]{2,}\b/gi, "[EMAIL]")
    .replace(/\b[\w.-]+@[a-z]+\b/gi, "[UPI_ID]");
}
