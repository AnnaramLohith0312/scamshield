"use client";

import { useEffect, useRef, useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Loader2,
  RotateCcw,
  ShieldAlert,
  Volume2,
  VolumeX,
} from "lucide-react";

type RiskLevel = "RED" | "YELLOW" | "GREEN";

interface AnalysisResult {
  schema_version: number;
  risk_level: RiskLevel;
  headline: string;
  manipulation_technique: string;
  explanation: string;
  suspicious_signals: string[];
  safe_action: string;
  analysis_status: "completed" | "limited" | "unavailable";
  analysis_mode: "rules_and_ai" | "rules_only";
  url_check:
    | "no_url"
    | "not_checked"
    | "no_known_match"
    | "known_malicious"
    | "unavailable";
  language: string;
}

type ScreenState = "idle" | "checking" | "result" | "error";

const EXAMPLES = [
  {
    label: "OTP scam",
    text: "Bank KYC freeze. Send your OTP to our agent now.",
  },
  {
    label: "Prize scam",
    text: "You won a prize. Pay the processing fee immediately.",
  },
  {
    label: "Fake arrest scam",
    text: "CBI: transfer money now to avoid arrest.",
  },
  {
    label: "Parcel scam",
    text: "Your parcel will be returned unless you pay at https://parcel-help.example/pay",
  },
  {
    label: "Safe reminder",
    text: "Dentist appointment tomorrow at 10 AM.",
  },
];

const riskStyles: Record<
  RiskLevel,
  {
    card: string;
    banner: string;
    icon: string;
    label: string;
    Icon: typeof AlertTriangle;
  }
> = {
  RED: {
    card: "border-red-300 bg-red-50 text-red-950",
    banner: "bg-red-600 text-white",
    icon: "text-red-700",
    label: "High risk",
    Icon: AlertTriangle,
  },
  YELLOW: {
    card: "border-amber-300 bg-amber-50 text-amber-950",
    banner: "bg-amber-500 text-white",
    icon: "text-amber-700",
    label: "Needs caution",
    Icon: AlertCircle,
  },
  GREEN: {
    card: "border-emerald-300 bg-emerald-50 text-emerald-950",
    banner: "bg-emerald-600 text-white",
    icon: "text-emerald-700",
    label: "No obvious warning signs",
    Icon: CheckCircle2,
  },
};

function isAnalysisResult(value: unknown): value is AnalysisResult {
  if (!value || typeof value !== "object") return false;

  const item = value as Record<string, unknown>;

  return (
    item.schema_version === 1 &&
    (item.risk_level === "RED" ||
      item.risk_level === "YELLOW" ||
      item.risk_level === "GREEN") &&
    typeof item.headline === "string" &&
    typeof item.explanation === "string" &&
    Array.isArray(item.suspicious_signals) &&
    typeof item.safe_action === "string"
  );
}

export default function Home() {
  const [message, setMessage] = useState("");
  const [screenState, setScreenState] = useState<ScreenState>("idle");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [showExamples, setShowExamples] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);

  const abortControllerRef = useRef<AbortController | null>(null);
  const resultHeadingRef = useRef<HTMLHeadingElement | null>(null);

  useEffect(() => {
    if (screenState === "result") {
      resultHeadingRef.current?.focus();
    }
  }, [screenState]);

  useEffect(() => {
    return () => {
      abortControllerRef.current?.abort();

      if ("speechSynthesis" in window) {
        window.speechSynthesis.cancel();
      }
    };
  }, []);

  function stopReading() {
    if ("speechSynthesis" in window) {
      window.speechSynthesis.cancel();
    }

    setIsSpeaking(false);
  }

  function resetChecker() {
    abortControllerRef.current?.abort();
    stopReading();

    setMessage("");
    setResult(null);
    setErrorMessage("");
    setScreenState("idle");
  }

  function chooseExample(text: string) {
    stopReading();
    setMessage(text);
    setResult(null);
    setErrorMessage("");
    setScreenState("idle");
    setShowExamples(false);
  }

  async function checkMessage() {
    const cleanMessage = message.trim();

    if (!cleanMessage) {
      setErrorMessage("Please paste or type a message before checking it.");
      setScreenState("error");
      return;
    }

    if (cleanMessage.length > 3000) {
      setErrorMessage(
        "This message is too long. Please paste no more than 3,000 characters.",
      );
      setScreenState("error");
      return;
    }

    abortControllerRef.current?.abort();
    stopReading();

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setResult(null);
    setErrorMessage("");
    setScreenState("checking");

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          text: cleanMessage,
          language: "en",
        }),
        signal: controller.signal,
      });

      let data: unknown;

      try {
        data = await response.json();
      } catch {
        throw new Error("The checker returned an unreadable response.");
      }

      if (!response.ok) {
        const apiError =
          data &&
          typeof data === "object" &&
          "error" in data &&
          typeof (data as { error?: unknown }).error === "string"
            ? (data as { error: string }).error
            : "The message could not be checked.";

        throw new Error(apiError);
      }

      if (!isAnalysisResult(data)) {
        throw new Error("The checker returned an unexpected result.");
      }

      setResult(data);
      setScreenState("result");
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        return;
      }

      setErrorMessage(
        error instanceof Error
          ? error.message
          : "We could not finish checking this message.",
      );
      setScreenState("error");
    } finally {
      if (abortControllerRef.current === controller) {
        abortControllerRef.current = null;
      }
    }
  }

  function readAloud() {
    if (!result) return;

    if (!("speechSynthesis" in window)) {
      setErrorMessage(
        "Read aloud is not available in this browser. You can still read the warning on screen.",
      );
      setScreenState("error");
      return;
    }

    if (isSpeaking) {
      stopReading();
      return;
    }

    const messageToRead = [
      result.headline,
      result.explanation,
      result.suspicious_signals.length > 0
        ? `Warning signs: ${result.suspicious_signals.join(". ")}`
        : "",
      `What to do now: ${result.safe_action}`,
    ]
      .filter(Boolean)
      .join(". ");

    const speech = new SpeechSynthesisUtterance(messageToRead);
    speech.lang = result.language || "en-IN";
    speech.rate = 0.9;
    speech.pitch = 1;

    speech.onend = () => setIsSpeaking(false);
    speech.onerror = () => setIsSpeaking(false);

    setIsSpeaking(true);
    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(speech);
  }

  const currentStyle = result ? riskStyles[result.risk_level] : null;
  const CurrentRiskIcon = currentStyle?.Icon ?? ShieldAlert;

  return (
    <main className="min-h-screen bg-slate-50 px-4 py-8 text-slate-950 sm:px-6 sm:py-12">
      <div className="mx-auto w-full max-w-3xl">
        <header className="mb-8">
          <div className="mb-4 flex items-center gap-3">
            <div className="rounded-2xl bg-blue-700 p-3 text-white shadow-sm">
              <ShieldAlert aria-hidden="true" className="h-8 w-8" />
            </div>

            <div>
              <h1 className="text-4xl font-extrabold tracking-tight text-slate-950">
                ScamShield
              </h1>
              <p className="mt-1 text-base font-medium text-slate-700 sm:text-lg">
                Check a message before you click, pay, or share information.
              </p>
            </div>
          </div>

          <div className="rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 text-base leading-relaxed text-blue-950">
            Paste an SMS, WhatsApp message, or suspicious link below. ScamShield
            explains the warning signs in plain language.
          </div>
        </header>

        <section
          aria-labelledby="message-checker-heading"
          className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm sm:p-7"
        >
          <h2
            id="message-checker-heading"
            className="mb-5 text-2xl font-bold text-slate-950"
          >
            Check a message
          </h2>

          <label
            htmlFor="scam-message"
            className="mb-2 block text-xl font-bold text-slate-950"
          >
            Paste the message you want to check
          </label>

          <textarea
            id="scam-message"
            value={message}
            onChange={(event) => {
              setMessage(event.target.value);

              if (screenState === "result" || screenState === "error") {
                setResult(null);
                setErrorMessage("");
                setScreenState("idle");
              }
            }}
            disabled={screenState === "checking"}
            maxLength={3000}
            placeholder="Example: You won a prize. Pay the processing fee immediately."
            className="min-h-48 w-full resize-y rounded-xl border-2 border-slate-400 bg-white p-4 text-lg font-medium leading-relaxed text-slate-950 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-100 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-600"
            aria-describedby="message-help message-count"
          />

          <div className="mt-2 flex flex-col justify-between gap-1 text-sm text-slate-600 sm:flex-row">
            <p id="message-help">
              Do not include personal banking details, passwords, or real OTPs.
            </p>
            <p id="message-count" aria-live="polite">
              {message.length}/3000 characters
            </p>
          </div>

          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <button
              type="button"
              onClick={checkMessage}
              disabled={screenState === "checking" || !message.trim()}
              className="inline-flex min-h-14 items-center justify-center gap-2 rounded-xl bg-blue-700 px-6 py-4 text-lg font-bold text-white shadow-sm transition hover:bg-blue-800 focus:outline-none focus:ring-4 focus:ring-blue-200 disabled:cursor-not-allowed disabled:bg-slate-400"
            >
              {screenState === "checking" ? (
                <>
                  <Loader2 className="h-6 w-6 animate-spin" aria-hidden="true" />
                  Checking message…
                </>
              ) : (
                <>
                  <ShieldAlert className="h-6 w-6" aria-hidden="true" />
                  Check message
                </>
              )}
            </button>

            <button
              type="button"
              onClick={resetChecker}
              disabled={screenState === "checking"}
              className="inline-flex min-h-14 items-center justify-center gap-2 rounded-xl border-2 border-slate-300 bg-white px-6 py-4 text-lg font-bold text-slate-900 transition hover:bg-slate-100 focus:outline-none focus:ring-4 focus:ring-slate-200 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <RotateCcw className="h-5 w-5" aria-hidden="true" />
              Check another message
            </button>
          </div>

          <div className="mt-5 border-t border-slate-200 pt-5">
            <button
              type="button"
              onClick={() => setShowExamples((previous) => !previous)}
              aria-expanded={showExamples}
              className="inline-flex items-center gap-2 text-base font-bold text-blue-800 underline-offset-4 hover:underline focus:outline-none focus:ring-4 focus:ring-blue-100"
            >
              Try an example
              <ChevronDown
                className={`h-5 w-5 transition-transform ${
                  showExamples ? "rotate-180" : ""
                }`}
                aria-hidden="true"
              />
            </button>

            {showExamples && (
              <div className="mt-3 flex flex-wrap gap-2">
                {EXAMPLES.map((example) => (
                  <button
                    key={example.label}
                    type="button"
                    onClick={() => chooseExample(example.text)}
                    disabled={screenState === "checking"}
                    className="rounded-lg border border-blue-300 bg-blue-50 px-3 py-2 text-sm font-bold text-blue-950 transition hover:bg-blue-100 focus:outline-none focus:ring-4 focus:ring-blue-100 disabled:opacity-60"
                  >
                    {example.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          <p className="mt-5 border-t border-slate-200 pt-4 text-sm leading-relaxed text-slate-600">
            <strong className="text-slate-800">Privacy note:</strong> Use sample
            messages or remove personal details first. Text is sent to a checking
            service. ScamShield does not save a message history.
          </p>
        </section>

        <div aria-live="polite" aria-atomic="true">
          {screenState === "checking" && (
            <section className="mt-6 rounded-2xl border-2 border-blue-200 bg-blue-50 p-6 text-blue-950">
              <div className="flex items-center gap-3">
                <Loader2 className="h-8 w-8 animate-spin text-blue-700" />
                <div>
                  <h2 className="text-xl font-bold">Checking the message…</h2>
                  <p className="mt-1 text-base">
                    Please wait. Do not click any links or make a payment while
                    checking.
                  </p>
                </div>
              </div>
            </section>
          )}

          {screenState === "error" && (
            <section className="mt-6 rounded-2xl border-2 border-red-300 bg-red-50 p-6 text-red-950">
              <div className="flex items-start gap-3">
                <AlertTriangle className="mt-1 h-8 w-8 flex-none text-red-700" />
                <div>
                  <h2 className="text-2xl font-extrabold">
                    We could not finish checking
                  </h2>
                  <p className="mt-3 text-lg leading-relaxed">
                    {errorMessage}
                  </p>
                  <p className="mt-3 text-lg font-bold">
                    Verify another way before clicking, replying, or paying.
                  </p>
                </div>
              </div>
            </section>
          )}

          {screenState === "result" && result && currentStyle && (
            <section
              className={`mt-6 overflow-hidden rounded-2xl border-2 shadow-sm ${currentStyle.card}`}
              aria-labelledby="analysis-result-heading"
            >
              <div
                className={`flex items-center gap-3 px-5 py-4 sm:px-7 ${currentStyle.banner}`}
              >
                <CurrentRiskIcon className="h-9 w-9 flex-none" aria-hidden="true" />
                <div>
                  <p className="text-sm font-bold uppercase tracking-wide">
                    {currentStyle.label}
                  </p>
                  <h2
                    id="analysis-result-heading"
                    ref={resultHeadingRef}
                    tabIndex={-1}
                    className="text-2xl font-extrabold outline-none sm:text-3xl"
                  >
                    {result.headline}
                  </h2>
                </div>
              </div>

              <div className="p-5 sm:p-7">
                {result.analysis_status !== "completed" && (
                  <div className="mb-5 rounded-xl border border-amber-300 bg-amber-100 px-4 py-3 text-base font-medium text-amber-950">
                    Limited check: this result uses safety rules because the AI
                    explanation service could not complete. Treat links and payment
                    requests with extra caution.
                  </div>
                )}

                <div className="mb-6">
                  <h3 className="text-lg font-extrabold">Why this needs attention</h3>
                  <p className="mt-2 text-lg font-medium leading-relaxed">
                    {result.explanation}
                  </p>
                </div>

                {result.manipulation_technique && (
                  <div className="mb-6 rounded-xl border border-current/20 bg-white/50 p-4">
                    <h3 className="text-lg font-extrabold">Pressure tactic used</h3>
                    <p className="mt-1 text-lg font-medium">
                      {result.manipulation_technique}
                    </p>
                  </div>
                )}

                {result.suspicious_signals.length > 0 && (
                  <div className="mb-6">
                    <h3 className="text-lg font-extrabold">Warning signs</h3>
                    <ul className="mt-3 space-y-3">
                      {result.suspicious_signals.map((signal, index) => (
                        <li
                          key={`${signal}-${index}`}
                          className="flex items-start gap-3 text-lg font-medium leading-relaxed"
                        >
                          <AlertTriangle
                            className={`mt-1 h-5 w-5 flex-none ${currentStyle.icon}`}
                            aria-hidden="true"
                          />
                          <span>{signal}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="rounded-xl border-2 border-current/25 bg-white/70 p-5">
                  <h3 className="text-xl font-extrabold">What to do now</h3>
                  <p className="mt-2 text-lg font-bold leading-relaxed">
                    {result.safe_action}
                  </p>
                </div>

                <div className="mt-6 flex flex-col gap-3 sm:flex-row">
                  <button
                    type="button"
                    onClick={readAloud}
                    className="inline-flex min-h-14 items-center justify-center gap-2 rounded-xl bg-slate-900 px-5 py-3 text-lg font-bold text-white transition hover:bg-slate-800 focus:outline-none focus:ring-4 focus:ring-slate-300"
                  >
                    {isSpeaking ? (
                      <>
                        <VolumeX className="h-6 w-6" aria-hidden="true" />
                        Stop reading
                      </>
                    ) : (
                      <>
                        <Volume2 className="h-6 w-6" aria-hidden="true" />
                        Read aloud
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={resetChecker}
                    className="inline-flex min-h-14 items-center justify-center gap-2 rounded-xl border-2 border-current/30 bg-white/70 px-5 py-3 text-lg font-bold transition hover:bg-white focus:outline-none focus:ring-4 focus:ring-current/20"
                  >
                    <RotateCcw className="h-5 w-5" aria-hidden="true" />
                    Check another message
                  </button>
                </div>

                {result.risk_level !== "GREEN" && (
                  <p className="mt-6 text-sm leading-relaxed">
                    Do not click links, send money, share OTPs, PINs, passwords,
                    card details, or install remote-access apps because of an
                    unexpected message.
                  </p>
                )}

                {result.risk_level === "GREEN" && (
                  <p className="mt-6 text-sm leading-relaxed">
                    No obvious warning signs were found. This does not verify the
                    sender or guarantee that a message is safe.
                  </p>
                )}
              </div>
            </section>
          )}
        </div>

        <footer className="mt-8 pb-6 text-center text-sm text-slate-600">
          ScamShield is an educational hackathon prototype. It does not open,
          visit, or execute submitted links.
        </footer>
      </div>
    </main>
  );
}