import { z } from "zod";

export const contractSchema = z.object({
  schema_version: z.literal(1),
  risk_level: z.enum(["RED", "YELLOW", "GREEN"]),
  headline: z.string(),
  manipulation_technique: z.string().max(80),
  explanation: z.string().max(240),
  suspicious_signals: z.array(z.string().max(100)).max(3),
  safe_action: z.string().max(240),
  analysis_status: z.enum(["completed", "limited", "unavailable"]),
  analysis_mode: z.enum(["rules_and_ai", "rules_only"]),
  url_check: z.enum([
    "no_url",
    "not_checked",
    "no_known_match",
    "known_malicious",
    "unavailable",
  ]),
  language: z.enum(["en"]),
});

export type Contract = z.infer<typeof contractSchema>;

export type ContractValidationResult =
  | { success: true; data: Contract }
  | { success: false; error: z.ZodError };

export function validateContract(input: unknown): ContractValidationResult {
  return contractSchema.safeParse(input);
}