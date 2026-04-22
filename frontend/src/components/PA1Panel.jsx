import { useState, useEffect } from "react";
import "./PA1Panel.css";

export default function PA1Panel() {
  const [seed, setSeed] = useState("1a2b3c4d5e6f7788");
  const [length, setLength] = useState(64);

  const [bits, setBits] = useState("");
  const [stats, setStats] = useState(null);

  const hexToDecimal = (hex) => {
    try {
      return BigInt("0x" + hex).toString();
    } catch {
      return "123";
    }
  };

  const fetchPRG = async () => {
    const res = await fetch("http://localhost:5000/prg", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        seed: hexToDecimal(seed),
        length,
      }),
    });

    const data = await res.json();
    setBits(data.bits);
    setStats(null);
  };

  // 🧪 RUN TESTS
  const runTests = async () => {
    const res = await fetch("http://localhost:5000/test", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ bits }),
    });

    const data = await res.json();
    setStats(data);
  };

  // ⚡ LIVE UPDATE
  useEffect(() => {
    fetchPRG();
  }, [seed, length]);

  // 📊 ratio
  const bitRatio = bits
    ? (bits.split("1").length - 1) / bits.length
    : 0;

  return (
    <div className="panel">
      <h3>PRG Viewer</h3>

      <input
        value={seed}
        onChange={(e) => setSeed(e.target.value)}
        placeholder="Hex seed"
      />

      <input
        type="range"
        min="8"
        max="256"
        value={length}
        onChange={(e) => setLength(Number(e.target.value))}
      />

      <p>Length: {length}</p>

      <div className="output-box">{bits}</div>

      <button onClick={runTests}>
        Run Randomness Test
      </button>

    {stats && (
  <div className="stats">
    
    {/* Frequency */}
    <p>
      <b>Frequency:</b>{" "}
      p = {stats.frequency.p_value.toFixed(4)}{" "}
      {stats.frequency.pass ? "✅ PASS" : "❌ FAIL"}
    </p>

    {/* Runs */}
    <p>
      <b>Runs:</b>{" "}
      p = {stats.runs.p_value.toFixed(4)}{" "}
      {stats.runs.pass ? "✅ PASS" : "❌ FAIL"}
    </p>

    {/* Serial */}
    <p>
      <b>Serial:</b>{" "}
      p1 = {stats.serial.p_value1.toFixed(4)},{" "}
      p2 = {stats.serial.p_value2.toFixed(4)}{" "}
      {stats.serial.pass ? "✅ PASS" : "❌ FAIL"}
    </p>

    {/* Ratio Bar */}
    <div className="ratio-bar">
      <div
        className="ratio-fill"
        style={{ width: `${bitRatio * 100}%` }}
      />
    </div>

    <p>1s Ratio: {(bitRatio * 100).toFixed(2)}%</p>
  </div>
)}
    </div>
  );
}