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

export default function PA15Panel() {
  const [message, setMessage] = useState("hello, world");
  const [signature, setSignature] = useState(null);
  const [vk, setVk] = useState(null);
  const [useRaw, setUseRaw] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  
  const [forgeM1, setForgeM1] = useState(2);
  const [forgeM2, setForgeM2] = useState(3);
  const [forgeResult, setForgeResult] = useState(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const sign = async () => {
    setLoading(true); setError(null); setVerifyResult(null); setSignature(null);
    try {
      const res = await fetch("http://127.0.0.1:5000/pa15/sign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, raw: useRaw }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      setSignature(data.signature);
      setVk(data.vk);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const verify = async (msg = message, sig = signature, tampered = false) => {
    setLoading(true); setError(null); setVerifyResult(null);
    try {
      const res = await fetch("http://127.0.0.1:5000/pa15/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: msg, signature: sig, raw: useRaw, tampered }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      setVerifyResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const forge = async () => {
    setLoading(true); setError(null); setForgeResult(null);
    try {
      const res = await fetch("http://127.0.0.1:5000/pa15/forge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ m1: Number(forgeM1), m2: Number(forgeM2) }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      setForgeResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 style={{ marginBottom: 4, color: "#e2e8f0" }}>PA#15 — Digital Signatures</h2>
      <p className="sub">
        Demonstrates Hash-then-Sign using RSA. Digital signatures provide non-repudiation.
        Without hashing (Raw RSA), the signature scheme is vulnerable to existential forgery.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14, marginTop: 14 }}>
        <div className="result-card">
          <div className="result-headline">
            <strong>Sign & Verify</strong>
            <Badge ok={!useRaw} label={useRaw ? "Raw RSA" : "Hash-then-Sign"} />
          </div>
          
          <div style={{ marginBottom: 14 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, cursor: "pointer", color: "#f87171" }}>
              <input type="checkbox" checked={useRaw} onChange={e => setUseRaw(e.target.checked)} />
              Use Raw RSA (Warning: Vulnerable)
            </label>
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 14 }}>
            <div style={{ flex: "1 1 180px" }}>
              <label>Message</label>
              <input 
                type={useRaw ? "number" : "text"} 
                value={message} 
                onChange={e => setMessage(e.target.value)} 
                placeholder="Message to sign"
              />
            </div>
            <div style={{ display: "flex", flexDirection: "column", justifyContent: "flex-end", gap: 6 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <button onClick={sign} disabled={loading} style={{ minWidth: 80 }}>Sign</button>
                <button onClick={() => verify(message, signature, false)} disabled={loading || !signature} style={{ minWidth: 80 }}>Verify</button>
                <button onClick={() => verify(message, signature, true)} disabled={loading || !signature} style={{ minWidth: 120, border: "1px solid #f87171", color: "#f87171" }}>Tamper & Verify</button>
              </div>
            </div>
          </div>

          {error && <div className="err" style={{ marginTop: 12 }}>{error}</div>}

          {signature && (
            <div style={{ marginTop: 14 }}>
              <Field label="Signature (σ) [Hex]" value={trunc(signature, 120)} />
            </div>
          )}

          {verifyResult !== null && (
            <div style={{ marginTop: 14 }}>
              <div className="ct-box" style={{ marginBottom: 12 }}>
                {verifyResult.message !== message && (
                  <>
                    <div className="ct-label">Tampered Message</div>
                    <div className="ct-value" style={{ marginBottom: 8 }}>{verifyResult.message}</div>
                  </>
                )}
                <div className="ct-label">{useRaw ? "Original Message (m)" : "Hash H(m)"}</div>
                <div className="ct-value" style={{ marginBottom: 8 }}>{trunc(verifyResult.h_m, 60)}</div>
                
                <div className="ct-label">Recovered σ^e mod N</div>
                <div className="ct-value">{trunc(verifyResult.sigma_e, 60)}</div>
              </div>
              
              <div className={`shared-secret-box ${verifyResult.valid ? 'match' : ''}`}>
                <div className="label">Verification Result</div>
                <div className="value">
                  {verifyResult.valid ? "✓ Valid Signature" : "✗ Invalid Signature"}
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="result-card" style={{ opacity: useRaw ? 1 : 0.5 }}>
          <div className="result-headline">
            <strong>Multiplicative Forgery</strong>
            <Badge ok={false} label="Attack" />
          </div>
          
          <p className="sub" style={{ fontSize: 12, marginTop: 4, marginBottom: 12 }}>
            Available only in Raw RSA mode. Given signatures on m₁ and m₂, an attacker can forge a signature on m₁×m₂.
          </p>
          
          <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
            <div style={{ flex: 1 }}>
              <label>m₁</label>
              <input type="number" value={forgeM1} onChange={e => setForgeM1(e.target.value)} disabled={!useRaw} />
            </div>
            <div style={{ flex: 1 }}>
              <label>m₂</label>
              <input type="number" value={forgeM2} onChange={e => setForgeM2(e.target.value)} disabled={!useRaw} />
            </div>
          </div>

          <button onClick={forge} disabled={loading || !useRaw} style={{ width: '100%' }}>
            Demonstrate Forgery
          </button>

          {forgeResult && (
            <div style={{ marginTop: 14 }}>
              <Field label="Forged Message (m₁×m₂)" value={forgeResult.m_forged} mono={false} />
              <Field label="Forged Signature (s₁×s₂)" value={trunc(String(forgeResult.s_forged), 80)} />
              
              <div className={`shared-secret-box ${forgeResult.valid ? 'match' : ''}`} style={{ marginTop: 12 }}>
                <div className="label">Forgery Verification</div>
                <div className="value">
                  {forgeResult.valid ? "✓ Forgery Successful!" : "✗ Forgery Failed"}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
