import { useState, useEffect } from "react";

export default function Chat({ user, onBack }) {
  const [list, setList] = useState([]);
  const [text, setText] = useState("");
  const [assist, setAssist] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    const fetchMessages = () => {
      fetch(`/api/chat/${user.id}`, {
        headers: { "x-token": token }
      })
        .then(r => r.json())
        .then(setList)
        .catch(err => console.error("Error fetching messages:", err));
    };

    fetchMessages();
    const interval = setInterval(fetchMessages, 3000);
    return () => clearInterval(interval);
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
    onBack();
    window.location.reload();
  };

  const send = async (e) => {
    if (e) e.preventDefault();
    if (!text.trim()) return;

    const token = localStorage.getItem("token");
    const msg = assist
      ? `Ik merk dat ik me zo voel: ${text}. Mijn behoefte is duidelijkheid.`
      : text;

    try {
      await fetch(`/api/chat/${user.id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-token": token },
        body: JSON.stringify({ from: "me", text: msg })
      });
      setText("");
      // Refresh messages immediately
      const r = await fetch(`/api/chat/${user.id}`, {
        headers: { "x-token": token }
      });
      const data = await r.json();
      setList(data);
    } catch (err) {
      console.error("Error sending message:", err);
    }
  };

  return (
    <div className="container" style={ { display: 'flex', flexDirection: 'column', height: '90vh' } }>
      <div style={ { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' } }>
        <div style={ { display: 'flex', alignItems: 'center' } }>
          <button className="button secondary" style={ { width: 'auto', padding: '8px 16px' } } onClick={onBack}>
            ← Terug
          </button>
          <h2 style={ { margin: '0 0 0 16px' } }>{user.name}</h2>
        </div>
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

      <div style={ { flex: 1, overflowY: 'auto', marginBottom: '16px' } }>
        {list.length === 0 && (
          <p style={ { textAlign: 'center', color: 'var(--muted)' } }>Begin het gesprek...</p>
        )}
        {list.map((m, i) => (
          <div 
            key={i} 
            className="card" 
            style={ { 
              marginLeft: m.from === "me" ? "40px" : "0",
              marginRight: m.from === "me" ? "0" : "40px",
              background: m.from === "me" ? "var(--accent)" : "var(--card)",
              color: m.from === "me" ? "#0b0e14" : "var(--text)"
            } }
          >
            <strong>{m.from}:</strong> <p style={ { color: 'inherit', margin: 0, display: 'inline' } }>{m.text}</p>
          </div>
        ))}
      </div>

      <div style={ { marginBottom: '12px' } }>
        <label className="card" style={ { display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', padding: '10px' } }>
          <input type="checkbox" checked={assist} onChange={() => setAssist(!assist)} />
          Help me dit verbindend formuleren
        </label>
      </div>

      <form onSubmit={send} style={ { display: 'flex', gap: '8px' } }>
        <textarea
          className="card"
          rows={2}
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="Typ je bericht…"
          style={ { flex: 1, marginBottom: 0, resize: 'none' } }
        />
        <button className="button" style={ { width: 'auto' } } type="submit">Verstuur</button>
      </form>
    </div>
  );
}
