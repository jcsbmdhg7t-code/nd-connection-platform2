import { useEffect, useState } from "react";
import MatchCard from "../components/MatchCard";

export default function Home() {
  const [matches, setMatches] = useState([]);

  useEffect(() => {
    const token = localStorage.getItem("token");
    fetch("/matches", {
      headers: { "x-token": token }
    })
      .then(r => r.json())
      .then(setMatches);
  }, []);

  return (
    <div className="container">
      <h2>Voor jou voorgesteld</h2>
      <p>Rustige voorstellen op basis van afstemming, niet swipen.</p>

      {matches.length === 0 && (
        <p>Er zijn nu even geen nieuwe voorstellen.</p>
      )}

      {matches.map(m => (
        <MatchCard key={m.id} user={m} />
      ))}
    </div>
  );
}
