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

export default function PA17Panel() {
  const [message, setMessage] = useState(42);
  const [encryptedData, setEncryptedData] = useState(null);
  const [decryptResult, setDecryptResult] = useState(null);
  const [tamperResult, setTamperResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const encrypt = async () => {
    setLoading(true); setEncryptedData(null); setDecryptResult(null); setTamperResult(null);
    try {
      const res = await fetch("http://127.0.0.1:5000/pa17/encrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: Number(message) }),
      });
      const data = await res.json();
      if (data.success) {
        setEncryptedData(data.ciphertext);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const decrypt = async (tampered = false) => {
    setLoading(true); setDecryptResult(null);
    try {
      const res = await fetch("http://127.0.0.1:5000/pa17/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...encryptedData, tampered }),
      });
      const data = await res.json();
      setDecryptResult({ tampered, ...data });
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const plainElgamalTamper = async () => {
    setLoading(true); setTamperResult(null);
    try {
      const res = await fetch("http://127.0.0.1:5000/pa17/plain_elgamal_tamper", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ CE: encryptedData.CE }),
      });
      const data = await res.json();
      setTamperResult(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 style={{ marginBottom: 4, color: "#e2e8f0" }}>PA#17 — CCA-Secure PKC (Signcryption)</h2>
      <p className="sub">
        Combines Digital Signatures (PA#15) with ElGamal PKC (PA#16) in the Sign-then-Encrypt paradigm
        to achieve Chosen-Ciphertext Attack (CCA) security. Plain ElGamal is malleable, but Signcryption
        aborts on tampered ciphertexts.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14, marginTop: 14 }}>
        {/* Left Column: Flow */}
        <div className="result-card">
          <div className="result-headline">
            <strong>Signcryption Flow</strong>
            <Badge ok={true} label="Secure" />
          </div>
          
          <div style={{ marginBottom: 14 }}>
            <label>Message (m)</label>
            <input 
              type="number" 
              value={message} 
              onChange={e => setMessage(e.target.value)}
            />
          </div>

          <button onClick={encrypt} disabled={loading} style={{ width: '100%', marginBottom: 14 }}>
            Encrypt-then-Sign
          </button>

          {encryptedData && (
            <div className="ct-box" style={{ marginBottom: 14 }}>
              <div className="ct-label">ElGamal (c₁)</div>
              <div className="ct-value" style={{ marginBottom: 8 }}>{trunc(encryptedData.CE.c1, 80)}</div>
              
              <div className="ct-label">ElGamal (c₂)</div>
              <div className="ct-value" style={{ marginBottom: 8 }}>{trunc(encryptedData.CE.c2, 80)}</div>
              
              <div className="ct-label">Signature (σ)</div>
              <div className="ct-value" style={{ color: "#34d399" }}>{trunc(encryptedData.sigma, 80)}</div>
            </div>
          )}

          {encryptedData && (
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => decrypt(false)} disabled={loading} style={{ flex: 1 }}>
                Verify & Decrypt
              </button>
              <button onClick={() => decrypt(true)} disabled={loading} style={{ flex: 1, border: "1px solid #f87171", color: "#f87171" }}>
                Tamper with C_E
              </button>
            </div>
          )}

          {decryptResult && (
            <div className={`shared-secret-box ${decryptResult.success ? 'match' : ''}`} style={{ marginTop: 14 }}>
              <div className="label">{decryptResult.success ? "Decrypted Message" : "Decryption Aborted"}</div>
              <div className="value">
                {decryptResult.success ? decryptResult.message : decryptResult.error}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Contrast */}
        <div className="result-card" style={{ opacity: encryptedData ? 1 : 0.5 }}>
          <div className="result-headline">
            <strong>Contrast: Plain ElGamal</strong>
            <Badge ok={false} label="Malleable" />
          </div>
          
          <p className="sub" style={{ fontSize: 12, marginTop: 4, marginBottom: 12 }}>
            Plain ElGamal is CPA-secure but malleable (CCA-vulnerable). An attacker can modify the ciphertext to predictably change the plaintext.
          </p>

          <button onClick={plainElgamalTamper} disabled={loading || !encryptedData} style={{ width: '100%' }}>
            Submit Tampered C_E to Oracle
          </button>

          {tamperResult && (
            <div className="result-card" style={{ marginTop: 14, border: "1px solid #fbbf24", background: "rgba(245, 158, 11, 0.05)" }}>
              <div className="result-headline">
                <strong style={{ color: "#fbbf24" }}>⚠ Exploit Successful</strong>
              </div>
              <p className="sub" style={{ fontSize: 12, marginTop: 4, marginBottom: 8 }}>
                We modified c₂ → 2×c₂. Since there is no signature to verify, decryption proceeds blindly.
              </p>
              <Field label="Oracle returned" value={tamperResult.decrypted_message} mono={false} />
              <div className="note-box" style={{ marginTop: 8 }}>
                Notice this is 2 × {message}.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
