import { useState } from "react";
import "./PA13Panel.css";
import "./PA16Panel.css";

const API = "http://localhost:5000";

const post = (path, body) =>
  fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then((r) => r.json());

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
const trunc = (s, n = 32) => {
  if (!s) return "—";
  const str = String(s);
  return str.length > n ? str.slice(0, n) + "…" : str;
};

/* ════════════════════════════════════════════════════════════════════
   TAB 1 — Key Generation
   ════════════════════════════════════════════════════════════════════ */
function KeyGen() {
  const [bits, setBits] = useState(32);
  const [keys, setKeys] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const generate = async () => {
    setBusy(true); setErr(""); setKeys(null);
    try {
      const d = await post("/pa16/keygen", { bits });
      if (d.error) throw new Error(d.error);
      setKeys(d);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <p className="sub">
        ElGamal key generation: pick a safe prime p = 2q+1 (via PA#13), find a
        generator g of the prime-order-q subgroup, sample private key x ← Zq,
        compute public key h = g^x mod p.
      </p>
      <div className="example-row">
        {[16, 24, 32, 48].map(b => (
          <button key={b} className={`example-btn${bits === b ? " active" : ""}`}
            onClick={() => setBits(b)}>{b}-bit</button>
        ))}
      </div>
      <button className="run-btn" onClick={generate} disabled={busy}>
        {busy ? "Generating…" : "Generate Keys"}
      </button>
      {err && <div className="err">{err}</div>}
      {keys && (
        <div className="result-card">
          <div className="result-headline">
            ElGamal Key Pair — {keys.bits} bits
            <span style={{ marginLeft: 8, fontSize: 12, color: "#94a3b8" }}>
              {keys.time_ms} ms
            </span>
          </div>
          <div className="eg-key-grid">
            <div className="eg-section">
              <div className="eg-section-title">Public Parameters</div>
              <Field label="p (safe prime)" value={trunc(keys.p, 36)} />
              <Field label="q (subgroup order)" value={trunc(keys.q, 36)} />
              <Field label="g (generator)" value={trunc(keys.g, 36)} />
            </div>
            <div className="eg-section">
              <div className="eg-section-title">Key Pair</div>
              <Field label="h = g^x mod p (PUBLIC)" value={trunc(keys.h, 36)} />
              <Field label="x (PRIVATE)" value={trunc(keys.x, 36)} />
            </div>
          </div>
          <div className="note-box">
            Public key: (p, q, g, h). Private key: x. Security relies on the
            Decisional Diffie-Hellman (DDH) assumption in the order-q subgroup.
          </div>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 2 — Encrypt / Decrypt
   ════════════════════════════════════════════════════════════════════ */
function EncDec() {
  const [bits, setBits] = useState(32);
  const [msg, setMsg]   = useState("42");
  const [keys, setKeys] = useState(null);
  const [enc, setEnc]   = useState(null);
  const [dec, setDec]   = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState("");

  const runAll = async () => {
    setBusy(true); setErr(""); setEnc(null); setDec(null);
    try {
      const k = await post("/pa16/keygen", { bits });
      if (k.error) throw new Error(k.error);
      setKeys(k);
      const m = parseInt(msg, 10);
      if (isNaN(m) || m < 1) throw new Error("m must be an integer ≥ 1");
      const e = await post("/pa16/encrypt", { p: k.p, q: k.q, g: k.g, h: k.h, m });
      if (e.error) throw new Error(e.error);
      setEnc(e);
      const d = await post("/pa16/decrypt", { p: k.p, x: k.x, c1: e.c1, c2: e.c2 });
      if (d.error) throw new Error(d.error);
      setDec(d);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <p className="sub">
        ElGamal encryption is <strong>randomized</strong> — encrypting the same
        message twice always yields different ciphertexts. Decryption recovers the
        original message exactly.
      </p>
      <div className="form-row">
        <label>Message m (integer)</label>
        <input className="text-input" value={msg} onChange={e => setMsg(e.target.value)} />
      </div>
      <div className="example-row">
        {[16, 24, 32].map(b => (
          <button key={b} className={`example-btn${bits === b ? " active" : ""}`}
            onClick={() => setBits(b)}>{b}-bit</button>
        ))}
      </div>
      <button className="run-btn" onClick={runAll} disabled={busy}>
        {busy ? "Running…" : "Keygen → Encrypt → Decrypt"}
      </button>
      {err && <div className="err">{err}</div>}
      {keys && enc && dec && (
        <div className="result-card">
          <div className="result-headline">
            Encrypt-Decrypt Round Trip &nbsp;
            <Badge ok={dec.m === String(msg) || dec.m === msg} label={dec.m === String(msg) || parseInt(dec.m) === parseInt(msg) ? "✓ m recovered" : "✗ mismatch"} />
          </div>
          <div className="eg-key-grid">
            <div className="eg-section">
              <div className="eg-section-title">Encryption</div>
              <Field label="m (plaintext)" value={msg} />
              <Field label="r (ephemeral)" value={trunc(enc.r, 28)} />
              <Field label="c1 = g^r mod p" value={trunc(enc.c1, 28)} />
              <Field label="c2 = m·h^r mod p" value={trunc(enc.c2, 28)} />
            </div>
            <div className="eg-section">
              <div className="eg-section-title">Decryption</div>
              <Field label="s = c1^x mod p" value={trunc(enc.s, 28)} />
              <Field label="m = c2·s⁻¹ mod p" value={dec.m} />
              <Field label="Match" value={parseInt(dec.m) === parseInt(msg) ? "✓ Correct" : "✗ Error"} mono={false} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 3 — IND-CPA Demo (encrypt same m twice, see different ciphertexts)
   ════════════════════════════════════════════════════════════════════ */
function IndCPA() {
  const [bits, setBits]  = useState(32);
  const [msg, setMsg]    = useState("99");
  const [keys, setKeys]  = useState(null);
  const [result, setRes] = useState(null);
  const [busy, setBusy]  = useState(false);
  const [err, setErr]    = useState("");

  const run = async () => {
    setBusy(true); setErr(""); setRes(null); setKeys(null);
    try {
      const k = await post("/pa16/keygen", { bits });
      if (k.error) throw new Error(k.error);
      setKeys(k);
      const m = parseInt(msg, 10);
      if (isNaN(m) || m < 1) throw new Error("m must be an integer ≥ 1");
      const r = await post("/pa16/ind-cpa-demo", { p: k.p, q: k.q, g: k.g, h: k.h, x: k.x, m });
      if (r.error) throw new Error(r.error);
      setRes(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <p className="sub">
        IND-CPA (indistinguishability under chosen-plaintext attack): an adversary
        cannot tell which of two messages was encrypted, because every ciphertext
        uses fresh randomness. Encrypt the same m twice and observe different c1, c2.
      </p>
      <div className="form-row">
        <label>Message m</label>
        <input className="text-input" value={msg} onChange={e => setMsg(e.target.value)} />
      </div>
      <div className="example-row">
        {[16, 24, 32].map(b => (
          <button key={b} className={`example-btn${bits === b ? " active" : ""}`}
            onClick={() => setBits(b)}>{b}-bit</button>
        ))}
      </div>
      <button className="run-btn" onClick={run} disabled={busy}>
        {busy ? "Running…" : "Encrypt m Twice"}
      </button>
      {err && <div className="err">{err}</div>}
      {result && (
        <div className="result-card">
          <div className="result-headline">
            Ciphertexts for m = {result.m} &nbsp;
            <Badge ok={result.ciphertexts_differ} label={result.ciphertexts_differ ? "✓ Differ (IND-CPA)" : "✗ Same (broken!)"} />
          </div>
          <div className="eg-key-grid">
            <div className="eg-section">
              <div className="eg-section-title">Encryption #1</div>
              <Field label="r₁" value={trunc(result.enc_1.r, 28)} />
              <Field label="c1₁" value={trunc(result.enc_1.c1, 28)} />
              <Field label="c2₁" value={trunc(result.enc_1.c2, 28)} />
            </div>
            <div className="eg-section">
              <div className="eg-section-title">Encryption #2</div>
              <Field label="r₂" value={trunc(result.enc_2.r, 28)} />
              <Field label="c1₂" value={trunc(result.enc_2.c1, 28)} />
              <Field label="c2₂" value={trunc(result.enc_2.c2, 28)} />
            </div>
          </div>
          <div className="note-box">{result.note}</div>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TAB 4 — Multiplicative Homomorphism
   ════════════════════════════════════════════════════════════════════ */
function Homomorphic() {
  const [bits, setBits] = useState(32);
  const [m1, setM1]     = useState("3");
  const [m2, setM2]     = useState("5");
  const [keys, setKeys] = useState(null);
  const [result, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState("");

  const run = async () => {
    setBusy(true); setErr(""); setRes(null); setKeys(null);
    try {
      const k = await post("/pa16/keygen", { bits });
      if (k.error) throw new Error(k.error);
      setKeys(k);
      const r = await post("/pa16/homomorphic", {
        p: k.p, q: k.q, g: k.g, h: k.h, x: k.x,
        m1: parseInt(m1), m2: parseInt(m2),
      });
      if (r.error) throw new Error(r.error);
      setRes(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <p className="sub">
        ElGamal is <strong>multiplicatively homomorphic</strong>: component-wise
        multiplication of two ciphertexts yields an encryption of the product of
        their plaintexts. Enc(m₁) ⊗ Enc(m₂) = Enc(m₁ · m₂ mod p).
      </p>
      <div className="form-row-inline">
        <div className="form-row">
          <label>m₁</label>
          <input className="text-input small" value={m1} onChange={e => setM1(e.target.value)} />
        </div>
        <div className="form-row">
          <label>m₂</label>
          <input className="text-input small" value={m2} onChange={e => setM2(e.target.value)} />
        </div>
      </div>
      <div className="example-row">
        {[16, 24, 32].map(b => (
          <button key={b} className={`example-btn${bits === b ? " active" : ""}`}
            onClick={() => setBits(b)}>{b}-bit</button>
        ))}
      </div>
      <button className="run-btn" onClick={run} disabled={busy}>
        {busy ? "Running…" : "Demonstrate Homomorphism"}
      </button>
      {err && <div className="err">{err}</div>}
      {result && (
        <div className="result-card">
          <div className="result-headline">
            Enc({m1}) ⊗ Enc({m2}) = Enc({result.m_product_mod_p}) &nbsp;
            <Badge ok={result.correct} label={result.correct ? "✓ Correct" : "✗ Error"} />
          </div>
          <Field label="m₁" value={result.m1} />
          <Field label="m₂" value={result.m2} />
          <Field label="m₁ · m₂ mod p" value={result.m_product_mod_p} />
          <Field label="Enc(m₁) c1" value={trunc(result.enc_m1.c1, 28)} />
          <Field label="Enc(m₂) c1" value={trunc(result.enc_m2.c1, 28)} />
          <Field label="Product c1" value={trunc(result.enc_product.c1, 28)} />
          <Field label="Decrypted product" value={result.dec_product} />
          <div className="note-box">{result.note}</div>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   ROOT COMPONENT
   ════════════════════════════════════════════════════════════════════ */
const TABS = [
  { id: "keygen",  label: "Key Generation" },
  { id: "encdec",  label: "Encrypt / Decrypt" },
  { id: "indcpa",  label: "IND-CPA Demo" },
  { id: "homo",    label: "Homomorphism" },
];

export default function PA16Panel() {
  const [tab, setTab] = useState("keygen");
  return (
    <div className="panel-root">
      <h2 className="panel-title">PA#16 — ElGamal Public-Key Cryptosystem</h2>
      <p className="panel-desc">
        ElGamal PKC over a safe-prime DH group. Randomized encryption gives IND-CPA security
        under the Decisional Diffie-Hellman (DDH) assumption. Multiplicatively homomorphic.
        Built on PA#11 (DH groups) and PA#13 (prime generation).
      </p>
      <div className="pa-tabs">
        {TABS.map(t => (
          <button key={t.id} className={`pa-tab${tab === t.id ? " active" : ""}`}
            onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>
      {tab === "keygen"  && <KeyGen />}
      {tab === "encdec"  && <EncDec />}
      {tab === "indcpa"  && <IndCPA />}
      {tab === "homo"    && <Homomorphic />}
    </div>
  );
}
