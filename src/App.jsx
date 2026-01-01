import "./styles.css";
import { useEffect, useState } from "react";
import Home from "./pages/Home";
import Onboarding from "./pages/Onboarding";

export default function App() {
  const [ready, setReady] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/me")
      .then(r => r.json())
      .then(me => {
        if (me.intentions && me.intentions.length) {
          setReady(true);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return <div className="container"><p>Laden...</p></div>;

  return ready ? <Home /> : <Onboarding onDone={() => setReady(true)} />;
}
