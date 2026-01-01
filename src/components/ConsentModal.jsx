export default function ConsentModal({ user, onDone }) {
  const choose = async (choice) => {
    try {
      await fetch(`/api/consent/${user.id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ choice })
      });
      onDone(choice);
    } catch (err) {
      console.error("Error saving consent:", err);
    }
  };

  return (
    <div className="card">
      <h3>Sta je open voor contact met {user.name}?</h3>
      <button className="button" onClick={() => choose("open")}>Ja</button>
      <div style={ { height: 8 } } />
      <button className="button secondary" onClick={() => choose("later")}>Later</button>
      <div style={ { height: 8 } } />
      <button className="button secondary" onClick={() => choose("no")}>Nee</button>
    </div>
  );
}
