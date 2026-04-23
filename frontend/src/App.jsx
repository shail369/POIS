import { useState } from "react";
import PA1Panel from "./components/PA1Panel";
import PA2Panel from "./components/PA2Panel";
import PA3Panel from "./components/PA3Panel";
import PA4Panel from "./components/PA4Panel";
import PA5Panel from "./components/PA5Panel";
import PA6Panel from "./components/PA6Panel";
import PA7Panel from "./components/PA7Panel";
import PA8Panel from "./components/PA8Panel";

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

        <button onClick={() => setView("PA5")}>
          MAC (PA#5)
        </button>

        <button onClick={() => setView("PA6")}>
          CCA (PA#6)
        </button>

        <button onClick={() => setView("PA7")}>
          MD Hash (PA#7)
        </button>

        <button onClick={() => setView("PA8")}>
          CRHF (PA#8)
        </button>
      </div>

      {/* Conditional Rendering */}
      {view === "PA1" && <PA1Panel />}
  {view === "PA2" && <PA2Panel />}
  {view === "PA3" && <PA3Panel />}
  {view === "PA4" && <PA4Panel />}
  {view === "PA5" && <PA5Panel />}
  {view === "PA6" && <PA6Panel />}
  {view === "PA7" && <PA7Panel />}
  {view === "PA8" && <PA8Panel />}

    </div>
  );
}

export default App;