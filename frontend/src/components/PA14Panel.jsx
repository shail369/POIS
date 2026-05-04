import { useState } from "react";
import "./PA13Panel.css";
import "./PA12Panel.css";

function Field({ label, value, mono = true }) {
  return (
    <div className="kv-row">
      <span className="kv-label">{label}</span>
      <span className={`kv-value${mono ? " mono" : ""}`}>{value ?? "—"}</span>
    </div>
  );
}

function Badge({ ok, label }) {
  return <span className={`badge ${ok ? "badge-ok" : "badge-fail"}`}>{label}</span>;
}

const trunc = (s, n = 48) => {
  if (!s) return "—";
  const str = String(s);
  return str.length > n ? str.slice(0, n) + "…" : str;
};

export default function PA14Panel() {
  const [message, setMessage] = useState(42);
  const [usePadding, setUsePadding] = useState(false);
  const [result, setResult] = useState(null);
  const [cubeRootRevealed, setCubeRootRevealed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const runAttack = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    setCubeRootRevealed(false);

    try {
      const endpoint = usePadding ? "/pa14/hastad_padded" : "/pa14/hastad";
      const res = await fetch(`http://127.0.0.1:5000${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: Number(message) }),
      });
      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 style={{ marginBottom: 4, color: "#e2e8f0" }}>PA#14 — Håstad's Broadcast Attack</h2>
      <p className="sub">
        Demonstrates the danger of using textbook RSA with a small public exponent (e=3)
        to send the same message to multiple recipients. The Chinese Remainder Theorem (CRT)
        can be used to recover the message without any private keys.
      </p>

      <div style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 14 }}>
        <div style={{ flex: "1 1 180px" }}>
          <label>Message (m)</label>
          <input
            type="number"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
        </div>
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "flex-end", gap: 6, marginBottom: 8, flex: "1 1 180px" }}>
          <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, cursor: "pointer", color: "#e2e8f0" }}>
            <input
              type="checkbox"
              checked={usePadding}
              onChange={(e) => setUsePadding(e.target.checked)}
            />
            Use PKCS#1 v1.5 Padding
          </label>
        </div>
        <button onClick={runAttack} disabled={loading}>
          {loading ? "Running Attack..." : "Run Broadcast Attack"}
        </button>
      </div>

      {error && <div className="err">{error}</div>}

      {result && (
        <>
          <div className={`det-banner ${result.success ? "danger" : "safe"}`}>
            {result.success
              ? `🔴 CRT Complete! We have intercepted the ciphertexts.`
              : `🟢 Attack Failed! Moduli were relatively prime, but exact cube root extraction failed (likely due to padding).`}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginTop: 14 }}>
            {result.moduli.map((n, i) => (
              <div key={i} className="ct-box">
                <div className="ct-label">Recipient {i + 1} (N)</div>
                <div className="ct-value">{trunc(n, 60)}</div>
                <div className="ct-label" style={{marginTop: 8}}>Ciphertext (c)</div>
                <div className="ct-value">{trunc(result.ciphertexts[i], 60)}</div>
              </div>
            ))}
          </div>

          <div className="result-card" style={{ marginTop: 14 }}>
            <div className="result-headline">
              <strong>Attacker View (CRT + Cube Root)</strong>
              <Badge ok={!result.success} label={result.success ? "Vulnerable" : "Secure"} />
            </div>
            
            <p className="sub" style={{ fontSize: 12, marginTop: 4, marginBottom: 12 }}>
              The attacker intercepts the 3 ciphertexts and knows the 3 public moduli. They apply CRT to find x = m³ mod (N₁N₂N₃).
            </p>

            {result.recovered_integer !== undefined && (
              <Field label="Recovered Integer (m³)" value={trunc(result.recovered_integer ?? result.recovered_message, 120)} />
            )}
            
            {!cubeRootRevealed ? (
              <div style={{ marginTop: 14 }}>
                <button onClick={() => setCubeRootRevealed(true)} style={{ width: '100%', background: '#f59e0b', color: 'white' }}>
                  Cube Root
                </button>
              </div>
            ) : (
              <div className={`shared-secret-box ${result.success ? 'match' : ''}`} style={{ marginTop: 12 }}>
                <div className="label">Extracted Message (∛x)</div>
                <div className="value">
                  {result.success ? result.recovered_message : result.message}
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
