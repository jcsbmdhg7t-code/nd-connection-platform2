import { useState, useEffect } from "react";

export default function Chat({ user, onBack }) {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");

  useEffect(() => {
    const fetchMessages = () => {
      fetch(`/api/chat/${user.id}`)
        .then(r => r.json())
        .then(setMessages)
        .catch(err => console.error("Error fetching messages:", err));
    };

    fetchMessages();
    const interval = setInterval(fetchMessages, 3000);
    return () => clearInterval(interval);
  }, [user.id]);

  const send = async (e) => {
    e.preventDefault();
    if (!text.trim()) return;

    try {
      await fetch(`/api/chat/${user.id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ from: "me", text })
      });
      setText("");
      // Refresh messages immediately
      const r = await fetch(`/api/chat/${user.id}`);
      const data = await r.json();
      setMessages(data);
    } catch (err) {
      console.error("Error sending message:", err);
    }
  };

  return (
    <div className="container" style={ { display: 'flex', flexDirection: 'column', height: '90vh' } }>
      <div style={ { display: 'flex', alignItems: 'center', marginBottom: '16px' } }>
        <button className="button secondary" style={ { width: 'auto', padding: '8px 16px' } } onClick={onBack}>
          ← Terug
        </button>
        <h2 style={ { margin: '0 0 0 16px' } }>{user.name}</h2>
      </div>

      <div style={ { flex: 1, overflowY: 'auto', marginBottom: '16px' } }>
        {messages.length === 0 && (
          <p style={ { textAlign: 'center', color: 'var(--muted)' } }>Begin het gesprek...</p>
        )}
        {messages.map((m, i) => (
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
            <p style={ { color: 'inherit', margin: 0 } }>{m.text}</p>
          </div>
        ))}
      </div>

      <form onSubmit={send} style={ { display: 'flex', gap: '8px' } }>
        <input 
          type="text" 
          value={text} 
          onChange={e => setText(e.target.value)} 
          className="card" 
          style={ { flex: 1, marginBottom: 0 } } 
          placeholder="Typ een bericht..."
        />
        <button className="button" style={ { width: 'auto' } } type="submit">Verstuur</button>
      </form>
    </div>
  );
}
