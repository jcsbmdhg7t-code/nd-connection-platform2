import { useState, useEffect } from "react";
import ConsentModal from "./ConsentModal";
import Chat from "./Chat";

export default function MatchCard({ user }) {
  const [asked, setAsked] = useState(false);
  const [choice, setChoice] = useState(null);
  const [openChat, setOpenChat] = useState(false);
  const [reporting, setReporting] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    fetch(`/api/consent/${user.id}`, {
      headers: { "x-token": token }
    })
      .then(r => r.json())
      .then(data => setChoice(data.choice))
      .catch(err => console.error("Error fetching consent:", err));
  }, [user.id]);

  const report = async () => {
    const reason = prompt("Waarom wil je deze gebruiker rapporteren?");
    if (!reason) return;
    
    const token = localStorage.getItem("token");
    const meRes = await fetch("/api/me", { headers: { "x-token": token } });
    const me = await meRes.json();
    
    await fetch("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-token": token },
      body: JSON.stringify({ from: me.id, against: user.id, reason })
    });
    
    await fetch(`/api/block/${me.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-token": token },
      body: JSON.stringify({ target: user.id })
    });
    
    alert("Gebruiker gerapporteerd en geblokkeerd.");
    window.location.reload();
  };

  const handleConsent = (newChoice) => {
    setChoice(newChoice);
    setAsked(false);
    if (newChoice === "open") {
      setOpenChat(true);
    }
  };

  if (openChat) {
    return <Chat user={user} onBack={() => setOpenChat(false)} />;
  }

  if (choice === "no") {
    return null;
  }

  return (
    <div className="card">
      <h3>{user.name}</h3>
      <p><strong>Intenties:</strong> {user.intentions.join(", ")}</p>
      <p><strong>Communicatie:</strong> {user.communication}</p>
      <p><strong>Energie:</strong> {user.energyLevel}</p>

      <p style={ { marginTop: 10 } }>
        Waarom voorgesteld: vergelijkbaar tempo en communicatie.
      </p>

      <div style={ { marginTop: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' } }>
        {choice === "open" ? (
          <div>
            <p style={ { color: "var(--accent)", fontWeight: "bold", marginBottom: "8px" } }>
              ✓ Je staat open voor contact.
            </p>
            <button className="button" onClick={() => setOpenChat(true)}>
              Open Chat
            </button>
          </div>
        ) : asked ? (
          <ConsentModal user={user} onDone={handleConsent} />
        ) : (
          <button className="button" onClick={() => setAsked(true)}>
            {choice === "later" ? "Nu wel open staan" : "Sta open voor contact"}
          </button>
        )}
        
        <button 
          onClick={report}
          style={ { 
            background: 'transparent', 
            border: 'none', 
            color: 'var(--muted)', 
            cursor: 'pointer',
            fontSize: '0.8rem',
            textDecoration: 'underline'
          } }
        >
          Rapporteer
        </button>
      </div>
    </div>
  );
}
