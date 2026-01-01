export default function MatchCard({ user }) {
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
        <button className="button">
          Sta open voor contact
        </button>
        <div style={ { height: 8 } } />
        <button className="button secondary">
          Nu niet
        </button>
      </div>
    </div>
  );
}
