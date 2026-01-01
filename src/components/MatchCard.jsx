import { useState } from "react";
import ConsentModal from "./ConsentModal";

export default function MatchCard({ user }) {
  const [asked, setAsked] = useState(false);

  return (
    <div className="card">
      <h3>{user.name}</h3>
      <p><strong>Intenties:</strong> {user.intentions.join(", ")}</p>
      <p><strong>Communicatie:</strong> {user.communication}</p>
      <p><strong>Energie:</strong> {user.energyLevel}</p>

      <p style={ { marginTop: 10 } }>
        Waarom voorgesteld: vergelijkbaar tempo en communicatie.
      </p>

      {!asked ? (
        <button className="button" onClick={() => setAsked(true)}>
          Sta open voor contact
        </button>
      ) : (
        <ConsentModal user={user} onDone={() => setAsked(false)} />
      )}
    </div>
  );
}
