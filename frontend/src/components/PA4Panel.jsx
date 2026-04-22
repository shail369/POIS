import { useMemo, useState } from "react";
import "./PA4Panel.css";
import "./PA3Panel.css";

const MODE_TABS = ["CBC", "OFB", "CTR"];

const toHex = (s) =>
  Array.from(new TextEncoder().encode(s))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

export default function PA4Panel() {
  const [mode, setMode] = useState("CBC");
  const [key, setKey] = useState("1a2b3c4d");
  const [message, setMessage] = useState("message0message1message2");

  const [messageA, setMessageA] = useState("shailshahtatyavagasia");
  const [messageB, setMessageB] = useState("devkananiaryanrchugh");

  const [encResult, setEncResult] = useState(null);
  const [decResult, setDecResult] = useState(null);
  const [trace, setTrace] = useState(null);

  const [flipBlock, setFlipBlock] = useState(0);
  const [flipResult, setFlipResult] = useState(null);

  const [reuseIv, setReuseIv] = useState(false);
  const [cbcReuse, setCbcReuse] = useState(null);
  const [ofbReuse, setOfbReuse] = useState(null);

  const [error, setError] = useState("");

  const encrypt = async () => {
    try {
      const res = await fetch("http://localhost:5000/pa4/encrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode, key, message }),
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || "Encrypt failed");

      setEncResult(data);
      setDecResult(null);
      setError("");
    } catch (e) {
      setError(e.message || "Unable to reach PA#4 API");
    }
  };

  const decrypt = async () => {
    if (!encResult?.ciphertext) {
      setError("Encrypt first.");
      return;
    }

    try {
      const payload = {
        mode,
        key,
        ciphertext: encResult.ciphertext,
      };

      if (encResult.iv) payload.iv = encResult.iv;
      if (encResult.nonce) payload.nonce = encResult.nonce;

      const res = await fetch("http://localhost:5000/pa4/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || "Decrypt failed");

      setDecResult(data);
      setError("");
    } catch (e) {
      setError(e.message || "Unable to reach PA#4 API");
    }
  };

  const runTrace = async (selectedMode = mode) => {
    try {
      const res = await fetch("http://localhost:5000/pa4/trace", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: selectedMode, key, message }),
      });

      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || "Trace failed");

      setTrace(data);
      setError("");
    } catch (e) {
      setError(e.message || "Unable to reach PA#4 API");
    }
  };

  const runFlipBit = async (blockIndex) => {
    try {
      const res = await fetch("http://localhost:5000/pa4/flip-bit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode, key, message, blockIndex, bitIndex: 0 }),
      });

      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || "Flip-bit failed");

      setFlipResult(data);
      setError("");
    } catch (e) {
      setError(e.message || "Unable to reach PA#4 API");
    }
  };

  const runAttackDemos = async () => {
    try {
      const [cbcRes, ofbRes] = await Promise.all([
        fetch("http://localhost:5000/pa4/attack/cbc-iv-reuse", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key, messageA, messageB }),
        }),
        fetch("http://localhost:5000/pa4/attack/ofb-keystream-reuse", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key, messageA, messageB }),
        }),
      ]);

      const cbcData = await cbcRes.json();
      const ofbData = await ofbRes.json();

      if (!cbcRes.ok || cbcData.error) {
        throw new Error(cbcData.error || "CBC attack demo failed");
      }
      if (!ofbRes.ok || ofbData.error) {
        throw new Error(ofbData.error || "OFB attack demo failed");
      }

      setCbcReuse(cbcData);
      setOfbReuse(ofbData);
      setError("");
    } catch (e) {
      setError(e.message || "Unable to reach PA#4 API");
    }
  };

  const onTabChange = (nextMode) => {
    setMode(nextMode);
    setEncResult(null);
    setDecResult(null);
    setFlipResult(null);
    setError("");
    runTrace(nextMode); // re-run animation on tab switch
  };

  const blockSummaries = useMemo(() => {
    if (!trace?.blocks) return [];
    return trace.blocks.map((b) => {
      if (trace.mode === "CBC") {
        return {
          index: b.index,
          left: `P${b.index}: ${b.plain}`,
          mid: `⊕ Prev: ${b.prev}`,
          right: `E_k: ${b.cipher}`,
        };
      }
      if (trace.mode === "OFB") {
        return {
          index: b.index,
          left: `State in: ${b.stateIn}`,
          mid: `KS${b.index}: ${b.keystream}`,
          right: `C${b.index}: ${b.cipher}`,
        };
      }
      return {
        index: b.index,
        left: `CTR${b.index}: ${b.counter}`,
        mid: `KS${b.index}: ${b.keystream}`,
        right: `C${b.index}: ${b.cipher}`,
      };
    });
  }, [trace]);

  return (
    <div className="panel">
      <h3>PA#4 Block Cipher Modes Animator</h3>

      <div className="pa4-tabs">
        {MODE_TABS.map((tab) => (
          <button
            key={tab}
            className={`pa4-tab ${tab === mode ? "active" : ""}`}
            onClick={() => onTabChange(tab)}
          >
            {tab}
          </button>
        ))}
      </div>

      <div className="pa4-grid">
        <label>
          Key (hex/int)
          <input value={key} onChange={(e) => setKey(e.target.value)} />
        </label>

        <label>
          3-block message
          <input
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="BLOCK001BLOCK002BLOCK003"
          />
        </label>

        <div className="cpa-row">
          <button onClick={encrypt}>Encrypt(mode, k, M)</button>
          <button onClick={decrypt}>Decrypt(mode, k, C)</button>
          <button onClick={() => runTrace(mode)}>Run Animation Trace</button>
        </div>

        {error && <p className="cpa-error">{error}</p>}

        {encResult && (
          <div className="output-box">
            <div>mode = {encResult.mode}</div>
            {encResult.iv && <div>iv = {encResult.iv}</div>}
            {encResult.nonce && <div>nonce = {encResult.nonce}</div>}
            <div>ciphertext = {encResult.ciphertext}</div>
          </div>
        )}

        {decResult && (
          <div className="output-box">
            <div>decrypted = {decResult.message}</div>
            <div>hex = {decResult.messageHex}</div>
          </div>
        )}

        <div className="pa4-animator">
          <h4>{mode} flow (3 blocks)</h4>
          <div className="pa4-block-row">
            {blockSummaries.map((b) => (
              <button
                key={b.index}
                className="pa4-block"
                onClick={() => {
                  setFlipBlock(b.index);
                  runFlipBit(b.index);
                }}
                title="Click to flip bit in this ciphertext block"
              >
                <div className="pa4-block-title">Block {b.index}</div>
                <div>{b.left}</div>
                <div className="pa4-arrow">↓ XOR / ENC ↓</div>
                <div>{b.mid}</div>
                <div className="pa4-arrow">↓ output ↓</div>
                <div>{b.right}</div>
              </button>
            ))}
          </div>

          <div className="cpa-row">
            <button onClick={() => runFlipBit(flipBlock)}>
              Flip bit in selected ciphertext block ({flipBlock})
            </button>
          </div>

          {flipResult && (
            <div className="output-box">
              <div>Corrupted plaintext blocks: {flipResult.corruptedPlaintextBlocks.join(", ") || "none"}</div>
              <div>Expected pattern:</div>
              <div>- CBC: current + next block</div>
              <div>- OFB: same block only</div>
              <div>- CTR: same block only</div>
            </div>
          )}
        </div>

        <div className="pa4-attack-box">
          <h4>Attack demos</h4>

          <label>
            Message A
            <input value={messageA} onChange={(e) => setMessageA(e.target.value)} />
          </label>

          <label>
            Message B
            <input value={messageB} onChange={(e) => setMessageB(e.target.value)} />
          </label>

          <label className="cpa-toggle">
            <span>Reuse IV toggle (CBC demo highlight)</span>
            <div className="switch">
              <input
                type="checkbox"
                checked={reuseIv}
                onChange={(e) => {
                  setReuseIv(e.target.checked);
                  if (e.target.checked) runAttackDemos();
                }}
              />
              <span className="slider"></span>
            </div>
          </label>

          <div className="cpa-row">
            <button onClick={runAttackDemos}>Run attack demonstrations</button>
          </div>

          {reuseIv && cbcReuse && (
            <div className="output-box">
              <div>CBC same-IV demo</div>
              <div>IV = {cbcReuse.iv}</div>
              <div>
                Matching plaintext blocks: {cbcReuse.matchingPlainBlocks.join(", ") || "none"}
              </div>
              <div className="pa4-red">
                Matching ciphertext blocks (leak): {cbcReuse.matchingCipherBlocks.join(", ") || "none"}
              </div>
            </div>
          )}

          {ofbReuse && (
            <div className="output-box">
              <div>OFB keystream reuse demo</div>
              <div>C1 xor C2 = {ofbReuse.cipherXor}</div>
              <div>M1 xor M2 = {ofbReuse.plainXor}</div>
              <div>{ofbReuse.xorsMatch ? "✅ XORs match (leak confirmed)" : "❌ mismatch"}</div>
            </div>
          )}

          <div className="output-box">
            <div>Plaintext(hex) preview: {toHex(message)}</div>
            <div>OFB decrypt == encrypt operation: demonstrated in tests + API behavior.</div>
            <div>CTR counters are independent and can be computed in parallel.</div>
          </div>
        </div>
      </div>
    </div>
  );
}
