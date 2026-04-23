import { useState, useEffect } from "react";
import "./PA1Panel.css";

export default function PA1Panel() {
  const [seed, setSeed] = useState("1a2b3c4d5e6f7788");
  const [length, setLength] = useState(64);
  const [bits, setBits] = useState("");
  const [stats, setStats] = useState(null);

  // PA#1b backward direction state
  const [owfFromPrgResult, setOwfFromPrgResult] = useState(null);
  const [owfFromPrgLoading, setOwfFromPrgLoading] = useState(false);
  const [distinguisherY, setDistinguisherY] = useState("");
  const [distinguisherResult, setDistinguisherResult] = useState(null);
  const [activeTab, setActiveTab] = useState("forward"); // 'forward' | 'backward'

  const hexToDecimal = (hex) => {
    try {
      return BigInt("0x" + hex).toString();
    } catch {
      return "123";
    }
  };

  const fetchPRG = async () => {
    try {
      const res = await fetch("http://localhost:5000/prg", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ seed: hexToDecimal(seed), length }),
      });
      const data = await res.json();
      setBits(data.bits || "");
      setStats(null);
    } catch {
      setBits("(API unreachable)");
    }
  };

  const runTests = async () => {
    const res = await fetch("http://localhost:5000/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ bits }),
    });
    const data = await res.json();
    setStats(data);
  };

  // PA#1b — OWF from PRG hardness demo
  const runOwfFromPrg = async () => {
    setOwfFromPrgLoading(true);
    setOwfFromPrgResult(null);
    try {
      const res = await fetch("http://localhost:5000/owf-from-prg", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: "hardness", n_seeds: 5, brute_force_budget: 10000, output_bits: 64 }),
      });
      const data = await res.json();
      setOwfFromPrgResult(data);
    } catch (e) {
      setOwfFromPrgResult({ error: String(e) });
    }
    setOwfFromPrgLoading(false);
  };

  // PA#1b — distinguisher demo
  const runDistinguisher = async () => {
    try {
      const body = distinguisherY
        ? { mode: "distinguisher", y: distinguisherY, output_bits: 64 }
        : { mode: "distinguisher", output_bits: 64 };      // server generates y
      const res = await fetch("http://localhost:5000/owf-from-prg", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setDistinguisherResult(data);
    } catch (e) {
      setDistinguisherResult({ error: String(e) });
    }
  };

  useEffect(() => { fetchPRG(); }, [seed, length]);

  const bitRatio = bits ? (bits.split("1").length - 1) / bits.length : 0;

  return (
    <div className="panel">
      <h3>PA#1 — OWF + PRG</h3>

      {/* Tab switcher */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <button
          onClick={() => setActiveTab("forward")}
          style={{ fontWeight: activeTab === "forward" ? "bold" : "normal" }}
        >
          Forward: OWF → PRG
        </button>
        <button
          onClick={() => setActiveTab("backward")}
          style={{ fontWeight: activeTab === "backward" ? "bold" : "normal" }}
        >
          Backward: PRG → OWF (PA#1b)
        </button>
      </div>

      {/* ──────────────── FORWARD TAB ──────────────── */}
      {activeTab === "forward" && (
        <>
          <label>
            Seed (hex)
            <input value={seed} onChange={(e) => setSeed(e.target.value)} placeholder="Hex seed" />
          </label>

          <label>
            Output length: {length} bits
            <input
              type="range" min="8" max="256" value={length}
              onChange={(e) => setLength(Number(e.target.value))}
            />
          </label>

          <div className="output-box" style={{ fontFamily: "monospace", wordBreak: "break-all" }}>
            {bits || "—"}
          </div>

          <button onClick={runTests}>Run Randomness Tests (NIST SP 800-22)</button>

          {stats && (
            <div className="stats">
              <p>
                <b>Frequency:</b> p = {stats.frequency.p_value.toFixed(4)}{" "}
                {stats.frequency.pass ? "✅ PASS" : "❌ FAIL"}
              </p>
              <p>
                <b>Runs:</b> p = {stats.runs.p_value.toFixed(4)}{" "}
                {stats.runs.pass ? "✅ PASS" : "❌ FAIL"}
              </p>
              <p>
                <b>Serial:</b> p₁ = {stats.serial.p_value1.toFixed(4)}, p₂ = {stats.serial.p_value2.toFixed(4)}{" "}
                {stats.serial.pass ? "✅ PASS" : "❌ FAIL"}
              </p>

              <div className="ratio-bar">
                <div className="ratio-fill" style={{ width: `${bitRatio * 100}%` }} />
              </div>
              <p>1s Ratio: {(bitRatio * 100).toFixed(2)}% (expected ≈ 50%)</p>
            </div>
          )}
        </>
      )}

      {/* ──────────────── BACKWARD TAB ──────────────── */}
      {activeTab === "backward" && (
        <>
          <div className="output-box" style={{ marginBottom: 12, fontSize: "0.85rem", color: "#aaa" }}>
            <b>Claim:</b> f(s) = G(s) is a OWF. Any adversary inverting f would break PRG security
            (distinguish G(s) from random). The demo below confirms random brute-force fails.
          </div>

          <button onClick={runOwfFromPrg} disabled={owfFromPrgLoading}>
            {owfFromPrgLoading ? "Running..." : "Run Hardness Demo (5 seeds × 10,000 guesses)"}
          </button>

          {owfFromPrgResult && !owfFromPrgResult.error && (
            <div className="stats">
              <p>
                <b>Hardness confirmed:</b>{" "}
                {owfFromPrgResult.hardness_confirmed ? "✅ YES" : "⚠️ No (rare collision!)"}
              </p>
              <p>
                Seeds tried: {owfFromPrgResult.n_seeds} | Budget: {owfFromPrgResult.brute_force_budget} |
                Space: 2³² ({owfFromPrgResult.seed_space?.toLocaleString()})
              </p>
              {owfFromPrgResult.results?.map((r, i) => (
                <div key={i} className="output-box" style={{ marginTop: 4, fontSize: "0.8rem" }}>
                  s = {r.s} | y = {r.y?.slice(0, 20)}… | inversion:{" "}
                  {r.brute_force_found ? `⚠️ found at ${r.found_at}` : "❌ not found"}
                </div>
              ))}
              <p style={{ fontSize: "0.8rem", color: "#888", marginTop: 8 }}>
                {owfFromPrgResult.argument}
              </p>
            </div>
          )}

          <hr style={{ margin: "20px 0", borderColor: "#333" }} />

          <h4>Distinguisher D (reduction)</h4>
          <div style={{ fontSize: "0.85rem", color: "#aaa", marginBottom: 8 }}>
            D(y): try to find s′ with G(s′) = y. If found → label "PRG"; else → "Random".
          </div>
          <label>
            y (bit-string, leave blank to auto-generate from PRG)
            <input
              value={distinguisherY}
              onChange={(e) => setDistinguisherY(e.target.value)}
              placeholder="Leave blank to auto-generate"
            />
          </label>
          <button onClick={runDistinguisher}>Run Distinguisher D</button>

          {distinguisherResult && !distinguisherResult.error && (
            <div className="stats">
              <p>
                <b>D labels:</b>{" "}
                <span style={{ color: distinguisherResult.distinguisher_label === "PRG" ? "#6cf" : "#fa0" }}>
                  {distinguisherResult.distinguisher_label}
                </span>
              </p>
              <p style={{ fontSize: "0.8rem" }}>{distinguisherResult.explanation}</p>
            </div>
          )}

          {(owfFromPrgResult?.error || distinguisherResult?.error) && (
            <p style={{ color: "red" }}>
              Error: {owfFromPrgResult?.error || distinguisherResult?.error}
            </p>
          )}
        </>
      )}
    </div>
  );
}