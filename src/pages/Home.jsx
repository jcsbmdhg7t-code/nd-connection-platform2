import { useEffect, useState } from "react";
import MatchCard from "../components/MatchCard";

export default function Home() {
  const [matches, setMatches] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");
    fetch("/matches", {
      headers: { "x-token": token }
    })
      .then(r => r.json())
      .then(d => {
        setMatches(d);
        setLoading(false);
      });
  }, []);

  if (loading) return (
    <div className="container" style={ { display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' } }>
      <p>Even verbinden…</p>
    </div>
  );

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
