import { useState } from "react";
import PA1Panel from "./components/PA1Panel";
import PA2Panel from "./components/PA2Panel";
import PA3Panel from "./components/PA3Panel";
import PA4Panel from "./components/PA4Panel";

function App() {
  const [view, setView] = useState("PA1");

  return (
    <div className="container">

      {/* Toggle Buttons */}
      <div style={{ marginBottom: "20px" }}>
        <button onClick={() => setView("PA1")}>
          PRG (PA#1)
        </button>

        <button onClick={() => setView("PA2")}>
          PRF (PA#2)
        </button>

        <button onClick={() => setView("PA3")}>
          CPA (PA#3)
        </button>

        <button onClick={() => setView("PA4")}>
          Modes (PA#4)
        </button>
      </div>

      {/* Conditional Rendering */}
      {view === "PA1" && <PA1Panel />}
  {view === "PA2" && <PA2Panel />}
  {view === "PA3" && <PA3Panel />}
  {view === "PA4" && <PA4Panel />}

    </div>
  );
}

export default App;