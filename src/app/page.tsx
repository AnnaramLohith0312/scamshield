"use client";

import { useState } from "react";
import { AlertTriangle, CheckCircle, AlertCircle, Loader2, Volume2, VolumeX } from "lucide-react";

interface AnalysisResult {
  schema_version: number;
  risk_level: "RED" | "YELLOW" | "GREEN";
  headline: string;
  manipulation_technique: string;
  explanation: string;
  suspicious_signals: string[];
  safe_action: string;
  analysis_status: string;
  analysis_mode: string;
  url_check: string;
  language: string;
}

const EXAMPLE_MESSAGES = [
  {
    label: "Parcel scam",
    text: "Your parcel will be returned unless you pay at https://parcel-help.example/fee",
  },
  {
    label: "Routine reminder",
    text: "Dentist appointment tomorrow at 10 AM",
  },
];

export default function Home() {
  const [input, setInput] = useState("");
  const [status, setStatus] = useState<"idle" | "checking" | "result" | "error">("idle");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSpeaking, setIsSpeaking] = useState(false);

  async function checkMessage() {
    if (!input.trim()) return;

    setStatus("checking");
    setError(null);
    setResult(null);

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: input, language: "en" }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Checking failed");
      }

      setResult(data);
      setStatus("result");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
      setStatus("error");
    }
  }

  function reset() {
    setInput("");
    setStatus("idle");
    setResult(null);
    setError(null);
    setIsSpeaking(false);
    if ("speechSynthesis" in window) {
      speechSynthesis.cancel();
    }
  }

  function readAloud() {
    if (!result || !("speechSynthesis" in window)) return;

    if (isSpeaking) {
      speechSynthesis.cancel();
      setIsSpeaking(false);
      return;
    }

    const utterance = new SpeechSynthesisUtterance(
      `${result.headline}. ${result.explanation}. ${result.safe_action}`
    );
    utterance.lang = result.language || "en";
    utterance.onend = () => setIsSpeaking(false);
    utterance.onerror = () => setIsSpeaking(false);

    setIsSpeaking(true);
    speechSynthesis.speak(utterance);
  }

  const riskConfig = {
    RED: {
      icon: AlertTriangle,
      color: "bg-red-100 text-red-900 border-red-300",
      badgeColor: "bg-red-600 text-white",
    },
    YELLOW: {
      icon: AlertCircle,
      color: "bg-yellow-100 text-yellow-900 border-yellow-300",
      badgeColor: "bg-yellow-600 text-white",
    },
    GREEN: {
      icon: CheckCircle,
      color: "bg-green-100 text-green-900 border-green-300",
      badgeColor: "bg-green-600 text-white",
    },
  };

  return (
    <main className="min-h-screen bg-gray-50 py-8 px-4">
      <div className="max-w-2xl mx-auto">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">ScamShield</h1>
        <p className="text-gray-600 mb-6">
          Paste a suspicious message to get a clear warning and safe next step.
        </p>

        {status === "idle" || status === "checking" || status === "result" || status === "error" ? (
          <div>
            <label htmlFor="message-input" className="block text-lg font-medium text-gray-800 mb-2">
              Paste the message you want to check
            </label>
            <textarea
              id="message-input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="w-full h-40 p-4 text-lg border-2 border-gray-300 rounded-lg focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
              placeholder="Paste the full message text here..."
              disabled={status === "checking"}
            />

            <div className="mt-4 flex flex-col sm:flex-row gap-3">
              <button
                onClick={checkMessage}
                disabled={!input.trim() || status === "checking"}
                className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white text-lg font-semibold py-4 px-6 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-blue-300"
              >
                {status === "checking" ? (
                  <span className="flex items-center justify-center gap-2">
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Checking...
                  </span>
                ) : (
                  "Check message"
                )}
              </button>
              {(status === "result" || status === "error") && (
                <button
                  onClick={reset}
                  className="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-800 text-lg font-semibold py-4 px-6 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-gray-300"
                >
                  Check another message
                </button>
              )}
            </div>

            <div className="mt-4">
              <details className="text-sm">
                <summary className="cursor-pointer text-blue-600 hover:text-blue-700">
                  Try an example
                </summary>
                <div className="mt-2 flex flex-wrap gap-2">
                  {EXAMPLE_MESSAGES.map((ex) => (
                    <button
                      key={ex.label}
                      onClick={() => setInput(ex.text)}
                      className="px-3 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-md text-sm transition-colors"
                    >
                      {ex.label}
                    </button>
                  ))}
                </div>
              </details>
            </div>

            <p className="mt-4 text-xs text-gray-500">
              Use sample messages or remove personal details first. Text is sent to an AI service for
              checking. We do not save a message history.
            </p>
          </div>
        ) : null}

        {status === "result" && result && (
          <div className={`mt-8 p-6 rounded-lg border-2 ${riskConfig[result.risk_level].color}`}>
            <div className="flex items-center gap-3 mb-4">
              {(() => {
                const Icon = riskConfig[result.risk_level].icon;
                return <Icon className="w-8 h-8" />;
              })()}
              <h2 className="text-2xl font-bold">{result.headline}</h2>
            </div>

            <p className="text-lg mb-4">{result.explanation}</p>

            {result.manipulation_technique && (
              <div className="mb-4">
                <span className="font-semibold">Pressure tactic:</span>{" "}
                {result.manipulation_technique}
              </div>
            )}

            {result.suspicious_signals.length > 0 && (
              <div className="mb-4">
                <span className="font-semibold">Warning signs:</span>
                <ul className="list-disc list-inside mt-2 space-y-1">
                  {result.suspicious_signals.map((signal, i) => (
                    <li key={i}>{signal}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="mb-4">
              <span className="font-semibold">What to do now:</span>
              <p className="text-lg mt-1">{result.safe_action}</p>
            </div>

            <div className="flex gap-3">
              <button
                onClick={readAloud}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-blue-300"
              >
                {isSpeaking ? (
                  <>
                    <VolumeX className="w-5 h-5" />
                    Stop reading
                  </>
                ) : (
                  <>
                    <Volume2 className="w-5 h-5" />
                    Read aloud
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {status === "error" && error && (
          <div className="mt-8 p-6 rounded-lg border-2 bg-red-100 text-red-900 border-red-300">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="w-8 h-8" />
              <h2 className="text-2xl font-bold">We could not finish checking</h2>
            </div>
            <p className="text-lg mb-4">{error}</p>
            <p className="text-lg">Verify another way before clicking or paying.</p>
          </div>
        )}
      </div>
    </main>
  );
}
