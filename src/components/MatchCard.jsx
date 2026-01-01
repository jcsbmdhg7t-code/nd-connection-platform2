import { useState, useEffect } from "react";
import ConsentModal from "./ConsentModal";
import Chat from "./Chat";

export default function MatchCard({ user }) {
  const [asked, setAsked] = useState(false);
  const [choice, setChoice] = useState(null);
  const [openChat, setOpenChat] = useState(false);

  useEffect(() => {
    fetch(`/api/consent/${user.id}`)
      .then(r => r.json())
      .then(data => setChoice(data.choice))
      .catch(err => console.error("Error fetching consent:", err));
  }, [user.id]);

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

      <div style={ { marginTop: 12 } }>
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
      </div>
    </div>
  );
}
