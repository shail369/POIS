import { useState, useCallback } from "react";
import "./PA7Panel.css";

const API = "http://localhost:5000";

const post = async (path, body) => {
  const res  = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok || data.error) throw new Error(data.error || "API error");
  return data;
};

const TABS = [
  { id: "trace",     label: "MD Hash + Chain" },
  { id: "compare",   label: "Compress Compare" },
  { id: "collision", label: "Collision Demo" },
];

// ── Chain visualization component ─────────────────────────────────────────
function ChainViz({ chain, blocks }) {
  if (!chain || chain.length === 0) return null;
  return (
    <div className="pa7-chain">
      {chain.map((cv, i) => {
        const isIV     = i === 0;
        const isDigest = i === chain.length - 1;
        const blockHex = blocks && blocks[i - 1] ? blocks[i - 1].hex : null;
        return (
          <div key={i} className="pa7-chain-node" style={{ display: "flex", alignItems: "center" }}>
            {i > 0 && (
              <div className="pa7-chain-arrow">
                {blockHex && (
                  <div className="pa7-arrow-block" title={blockHex}>
                    B{i - 1}: {blockHex.slice(0, 8)}…
                  </div>
                )}
                <div className="pa7-arrow-line" />
              </div>
            )}
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
              <div className={`pa7-state-box ${isIV ? "iv" : isDigest ? "digest" : "mid"}`}>
                {cv.slice(0, 16)}…
              </div>
              <div className="pa7-state-label">
                {isIV ? "IV" : isDigest ? "Digest" : `h${i}`}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Block grid with padding annotations ──────────────────────────────────
function BlockGrid({ blocks, paddingInfo }) {
  if (!blocks || blocks.length === 0) return null;
  return (
    <div>
      <div className="pa7-legend">
        <div className="pa7-legend-item">
          <div className="pa7-legend-dot" style={{ background: "#3b82f6" }} /> Data bytes
        </div>
        <div className="pa7-legend-item">
          <div className="pa7-legend-dot" style={{ background: "#f59e0b" }} /> Padding/length
        </div>
        <div className="pa7-legend-item">
          <div className="pa7-legend-dot" style={{ background: "#16a34a" }} /> Pure padding block
        </div>
      </div>
      <div className="pa7-blocks-grid">
        {blocks.map((blk, i) => {
          const cls = blk.has_data && !blk.has_pad ? "data"
                    : blk.has_data                  ? "mixed"
                    : "pad";
          return (
            <div key={i} className={`pa7-block-card ${cls}`}>
              <div style={{ fontWeight: "bold", color: "#94a3b8", marginBottom: 4 }}>
                Block {i}{blk.has_data ? " (data" : " ("}
                {blk.has_pad ? "+pad" : ""}{blk.has_length ? "+length" : ""}
                {")"}
              </div>
              <div className="pa7-block-hex">{blk.hex}</div>
            </div>
          );
        })}
      </div>
      {paddingInfo && (
        <div className="pa7-info" style={{ marginTop: 10, fontSize: "0.8rem" }}>
          Original: {paddingInfo.original_bytes}B ({paddingInfo.original_bits} bits) →
          Padded: {paddingInfo.padded_bytes}B |
          0x80 at byte {paddingInfo.marker_byte_pos} |
          64-bit length at byte {paddingInfo.length_field_pos}
        </div>
      )}
    </div>
  );
}

export default function PA7Panel() {
  const [activeTab, setActiveTab] = useState("trace");
  const [error, setError]         = useState("");

  // ── Trace tab ──────────────────────────────────────────────────────────
  const [msg,         setMsg]        = useState("hello world");
  const [compressFn,  setCompressFn] = useState("xor");
  const [traceResult, setTraceResult] = useState(null);
  const [loading,     setLoading]    = useState(false);

  const runTrace = async () => {
    setLoading(true); setError("");
    try {
      const data = await post("/pa7/trace", { message: msg, compressFn });
      setTraceResult(data);
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  // ── Compare tab ────────────────────────────────────────────────────────
  const [cmpMsg,    setCmpMsg]    = useState("compare me");
  const [cmpResult, setCmpResult] = useState(null);

  const runCompare = async () => {
    setError("");
    try {
      const data = await post("/pa7/compress-compare", { message: cmpMsg });
      setCmpResult(data);
    } catch (e) { setError(e.message); }
  };

  // ── Collision tab ──────────────────────────────────────────────────────
  const [suffix,      setSuffix]    = useState("any_suffix_works");
  const [collResult,  setCollResult] = useState(null);
  const [collLoading, setCollLoading] = useState(false);

  const runCollision = async () => {
    setCollLoading(true); setError("");
    try {
      const data = await post("/pa7/collision-demo", { compressFn: "xor", suffix });
      setCollResult(data);
    } catch (e) { setError(e.message); }
    setCollLoading(false);
  };

  return (
    <div className="panel">
      <h3>PA#7 — Merkle-Damgård Hash Transform</h3>

      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => { setActiveTab(t.id); setError(""); }}
            style={{
              fontWeight: activeTab === t.id ? "bold" : "normal",
              background: activeTab === t.id ? "#1e40af" : "#1e293b",
              color: "#e2e8f0", border: "none", borderRadius: 8,
              padding: "8px 14px", cursor: "pointer",
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {error && <p className="pa7-err">⚠ {error}</p>}

      {/* ═══ TRACE TAB ═══ */}
      {activeTab === "trace" && (
        <div className="pa7-grid">
          <div className="pa7-info">
            <b>Merkle-Damgård</b>: H(M) = f(f(f(IV, B₀), B₁), …, Bₙ) where B₀…Bₙ are blocks
            of padded M. The chain below shows each chaining value after each compression round.
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <label className="pa7-grid">
              Message
              <input value={msg} onChange={e => setMsg(e.target.value)} />
            </label>
            <label className="pa7-grid">
              Compress function
              <select value={compressFn} onChange={e => setCompressFn(e.target.value)}>
                <option value="xor">XOR Compress (trivially broken)</option>
                <option value="rotate">Rotate-Add Compress (stronger toy)</option>
              </select>
            </label>
          </div>

          <div className="pa7-row">
            <button onClick={runTrace} disabled={loading}>
              {loading ? "Computing…" : "Hash + Show Chain"}
            </button>
          </div>

          {traceResult && (
            <>
              <div className="output-box" style={{ fontFamily: "monospace" }}>
                <b>Digest:</b> {traceResult.digest} &nbsp;|&nbsp;
                <b>Blocks:</b> {traceResult.n_blocks} &nbsp;|&nbsp;
                <b>Padded:</b> {traceResult.padding_info.padded_bytes}B
              </div>

              <div style={{ marginTop: 6, marginBottom: 2, fontWeight: "bold", color: "#94a3b8" }}>
                Chain Visualization
              </div>
              <ChainViz chain={traceResult.chain} blocks={traceResult.blocks} />

              <div style={{ marginTop: 6, fontWeight: "bold", color: "#94a3b8" }}>
                Block Breakdown (with padding)
              </div>
              <BlockGrid blocks={traceResult.blocks} paddingInfo={traceResult.padding_info} />
            </>
          )}
        </div>
      )}

      {/* ═══ COMPARE TAB ═══ */}
      {activeTab === "compare" && (
        <div className="pa7-grid">
          <div className="pa7-info">
            Both compress functions receive the <b>same padded blocks</b> but produce
            different digests. XOR compress is trivially broken (collisions by construction).
            Rotate-Add is harder (but still not collision-resistant).
          </div>

          <label className="pa7-grid">
            Message
            <input value={cmpMsg} onChange={e => setCmpMsg(e.target.value)} />
          </label>

          <div className="pa7-row">
            <button onClick={runCompare}>Compare Both Compress Functions</button>
          </div>

          {cmpResult && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <div style={{
                background: "#1c0f2e", border: "1.5px solid #7c3aed",
                borderRadius: 10, padding: 14
              }}>
                <div style={{ fontWeight: "bold", color: "#c4b5fd", marginBottom: 8 }}>
                  XOR Compress ⚠ (trivially broken)
                </div>
                <div style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>
                  <div><b>Digest:</b> {cmpResult.xor.digest}</div>
                  <div style={{ marginTop: 6, color: "#64748b" }}>
                    Chain: {cmpResult.xor.chain.join(" → ")}
                  </div>
                </div>
              </div>

              <div style={{
                background: "#0a1c1a", border: "1.5px solid #0d9488",
                borderRadius: 10, padding: 14
              }}>
                <div style={{ fontWeight: "bold", color: "#5eead4", marginBottom: 8 }}>
                  Rotate-Add Compress (stronger toy)
                </div>
                <div style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>
                  <div><b>Digest:</b> {cmpResult.rotate.digest}</div>
                  <div style={{ marginTop: 6, color: "#64748b" }}>
                    Chain: {cmpResult.rotate.chain.join(" → ")}
                  </div>
                </div>
              </div>

              <div className="pa7-info" style={{ gridColumn: "1 / -1" }}>
                Digests match: <b>{cmpResult.digests_match ? "YES (unexpected!)" : "NO (expected — different compress → different hash)"}</b>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══ COLLISION TAB ═══ */}
      {activeTab === "collision" && (
        <div className="pa7-grid">
          <div className="pa7-info">
            <b>Theorem:</b> A collision in compress propagates to a full MD collision.
            <br />
            XOR compress lets us construct B₁ ≠ B₂ with compress(IV, B₁) = compress(IV, B₂) = IV.
            Then for <em>any</em> suffix S: H(B₁ ‖ S) = H(B₂ ‖ S).
          </div>

          <label className="pa7-grid">
            Suffix S (any string — demonstrates the "for any suffix" property)
            <input value={suffix} onChange={e => setSuffix(e.target.value)} />
          </label>

          <div className="pa7-row">
            <button onClick={runCollision} disabled={collLoading}>
              {collLoading ? "Running…" : "Construct Collision + Propagate"}
            </button>
          </div>

          {collResult && collResult.found && (
            <>
              {/* Compress collision highlight */}
              <div style={{
                background: "#1a0a0a", border: "1.5px solid #ef4444",
                borderRadius: 10, padding: 14, marginTop: 8
              }}>
                <div style={{ fontWeight: "bold", color: "#f87171", marginBottom: 8 }}>
                  Step 1 — Compress Collision (Round 1)
                </div>
                <div style={{ fontFamily: "monospace", fontSize: "0.82rem", lineHeight: 1.8 }}>
                  <div>B₁ = <span style={{ color: "#a855f7" }}>{collResult.compress_collision.block1_hex}</span></div>
                  <div>B₂ = <span style={{ color: "#22c55e" }}>{collResult.compress_collision.block2_hex}</span></div>
                  <div style={{ marginTop: 6 }}>
                    compress(IV, B₁) = compress(IV, B₂) = <b style={{ color: "#fcd34d" }}>
                      {collResult.compress_collision.compress_output}
                    </b>
                  </div>
                  <div>Blocks equal: <b style={{ color: collResult.compress_collision.blocks_equal ? "#ef4444" : "#4ade80" }}>
                    {collResult.compress_collision.blocks_equal ? "YES (bug!)" : "NO (genuine collision)"}
                  </b>
                  </div>
                </div>
              </div>

              {/* MD collision split panel */}
              <div style={{ fontWeight: "bold", color: "#94a3b8", marginTop: 10 }}>
                Step 2 — Full MD Collision (suffix: "{suffix}")
              </div>

              <div className="pa7-collision-split">
                <div className="pa7-collision-side path1">
                  <div style={{ fontWeight: "bold", color: "#c084fc", marginBottom: 8 }}>
                    M₁ = B₁ ‖ S
                  </div>
                  <ChainViz
                    chain={collResult.trace1?.chain?.slice(0, 3)}
                    blocks={collResult.trace1?.blocks?.slice(0, 2)}
                  />
                  <div className="pa7-block-hex" style={{ fontSize: "0.75rem", marginTop: 6 }}>
                    Hash: <b>{collResult.hash1}</b>
                  </div>
                </div>

                <div className="pa7-collision-side path2">
                  <div style={{ fontWeight: "bold", color: "#4ade80", marginBottom: 8 }}>
                    M₂ = B₂ ‖ S
                  </div>
                  <ChainViz
                    chain={collResult.trace2?.chain?.slice(0, 3)}
                    blocks={collResult.trace2?.blocks?.slice(0, 2)}
                  />
                  <div className="pa7-block-hex" style={{ fontSize: "0.75rem", marginTop: 6 }}>
                    Hash: <b>{collResult.hash2}</b>
                  </div>
                </div>
              </div>

              <div className="pa7-collision-convergence">
                {collResult.full_collision
                  ? `✓ FULL MD COLLISION CONFIRMED: H(B₁‖S) = H(B₂‖S) = ${collResult.hash1}`
                  : "✗ Collision did NOT propagate (unexpected — check compress_fn logic)"}
              </div>

              <div className="pa7-info" style={{ fontSize: "0.8rem" }}>
                {collResult.explanation}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
