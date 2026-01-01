export default function Home() {
  return (
    <div className="container">
      <div className="card">
        <h1>Home Page</h1>
        <p>Welcome to your React MVP app.</p>
      </div>
      <div className="card">
        <h3>Quick Actions</h3>
        <button className="button">Primary Action</button>
        <div style={ { height: '12px' } }></div>
        <button className="button secondary">Secondary Action</button>
      </div>
    </div>
  );
}
