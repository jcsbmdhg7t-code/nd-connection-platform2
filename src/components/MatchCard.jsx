import { useState, useEffect } from "react";
import ConsentModal from "./ConsentModal";

export default function MatchCard({ user }) {
  const [choice, setChoice] = useState(null);
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    fetch(`/api/consent/${user.id}`)
      .then(r => r.json())
      .then(data => setChoice(data.choice))
      .catch(err => console.error("Error fetching consent:", err));
  }, [user.id]);

  const handleChoice = (newChoice) => {
    setChoice(newChoice);
    setShowModal(false);
  };

  if (showModal) {
    return <ConsentModal user={user} onDone={handleChoice} />;
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
          <p style={ { color: "var(--accent)", fontWeight: "bold" } }>
            ✓ Je hebt aangegeven open te staan voor contact.
          </p>
        ) : choice === "later" ? (
          <div>
            <p style={ { color: "var(--muted)", marginBottom: "8px" } }>
              Je bekijkt dit voorstel later.
            </p>
            <button className="button" onClick={() => setShowModal(true)}>
              Nu wel open staan
            </button>
          </div>
        ) : (
          <button className="button" onClick={() => setShowModal(true)}>
            Bekijk voorstel
          </button>
        )}
      </div>
    </div>
  );
}
