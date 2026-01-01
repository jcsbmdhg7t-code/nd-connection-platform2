export default function Moderation({ user, onAction }) {
  const handleReport = async () => {
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
    if (onAction) onAction();
  };

  const handleBlock = async () => {
    if (!confirm("Weet je zeker dat je deze gebruiker wilt blokkeren?")) return;
    
    const token = localStorage.getItem("token");
    const meRes = await fetch("/api/me", { headers: { "x-token": token } });
    const me = await meRes.json();
    
    await fetch(`/api/block/${me.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-token": token },
      body: JSON.stringify({ target: user.id })
    });
    
    alert("Gebruiker geblokkeerd.");
    if (onAction) onAction();
  };

  return (
    <div className="card" style={ { marginTop: '12px', border: '1px solid #333' } }>
      <button className="button secondary" onClick={handleReport} style={ { marginBottom: '8px' } }>
        Rapporteer
      </button>
      <button className="button secondary" onClick={handleBlock}>
        Blokkeer
      </button>
    </div>
  );
}
