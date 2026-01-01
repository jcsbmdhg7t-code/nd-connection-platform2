import { useState, useEffect } from "react";

export default function MatchCard({ user }) {
  const [choice, setChoice] = useState(null);

  useEffect(() => {
    fetch(`/api/consent/${user.id}`)
      .then(r => r.json())
      .then(data => setChoice(data.choice))
      .catch(err => console.error("Error fetching consent:", err));
  }, [user.id]);

  const handleChoice = async (newChoice) => {
    try {
      await fetch(`/api/consent/${user.id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ choice: newChoice })
      });
      setChoice(newChoice);
    } catch (err) {
      console.error("Error saving consent:", err);
    }
  };

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
            <button className="button" onClick={() => handleChoice("open")}>
              Nu wel open staan
            </button>
          </div>
        ) : choice === "no" ? (
          <p style={ { color: "var(--muted)" } }>Voorstel verborgen.</p>
        ) : (
          <>
            <button className="button" onClick={() => handleChoice("open")}>
              Sta open voor contact
            </button>
            <div style={ { height: 8 } } />
            <button className="button secondary" onClick={() => handleChoice("later")}>
              Nu niet
            </button>
          </>
        )}
      </div>
    </div>
  );
}
