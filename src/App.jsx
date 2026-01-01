import "./styles.css";
import { useEffect, useState } from "react";
import Home from "./pages/Home";
import Onboarding from "./pages/Onboarding";

export default function App() {
  const [ready, setReady] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initAuth = async () => {
      let token = localStorage.getItem("token");
      
      if (!token) {
        const res = await fetch("/api/auth/anon", { method: "POST" });
        const data = await res.json();
        token = data.token;
        localStorage.setItem("token", token);
      }

      try {
        const res = await fetch("/api/me", {
          headers: { "x-token": token }
        });
        const me = await res.json();
        
        if (me && me.intentions && me.intentions.length) {
          setReady(true);
        }
      } catch (err) {
        console.error("Auth error:", err);
      } finally {
        setLoading(false);
      }
    };

    initAuth();
  }, []);

  if (loading) return <div className="container"><p>Laden...</p></div>;

  return ready ? <Home /> : <Onboarding onDone={() => setReady(true)} />;
}
