import { useState } from "react";
import "./PA2Panel.css";

export default function PA2Panel() {
  const [key, setKey] = useState("1a2b3c4d");
  const [x, setX] = useState("0101");

  const [tree, setTree] = useState([]);
  const [result, setResult] = useState("");

  const fetchPRF = async () => {
    const res = await fetch("http://localhost:5000/prf", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        key,
        x,
      }),
    });

    const data = await res.json();

    setTree(data.tree);
    setResult(data.result);
  };

  const computePath = (x) => {
    let path = [];

    for (let i = 0; i < x.length; i++) {
      const prefix = x.slice(0, i + 1);
      const index = parseInt(prefix, 2);
      path.push(index);
    }

    return path;
  };

  const path = computePath(x);

  const isPathNode = (level, index) => {
    return path[level] === index;
  };

  return (
    <div className="panel">
      <h3>GGM PRF Visualizer</h3>

      <input
        value={key}
        onChange={(e) => setKey(e.target.value)}
        placeholder="Key (hex)"
      />

      <input
        value={x}
        onChange={(e) => setX(e.target.value)}
        placeholder="Input (bits)"
      />

      <button onClick={fetchPRF}>Generate Tree</button>

      <div className="tree-container">
        <div className="tree">
          {tree.map((level, i) => (
            <div key={i} className="tree-level">
              {level.map((node, j) => (
                <div
                  key={j}
                  className="tree-node"
                  style={{
                    background: isPathNode(i, j) ? "#3b82f6" : "#1e293b",
                    opacity: isPathNode(i, j) ? 1 : 0.4,
                  }}
                >
                  {node.toString(16).slice(0, 6)}
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* RESULT */}
      <div className="output-box">F(k, x) = {result}</div>
    </div>
  );
}
