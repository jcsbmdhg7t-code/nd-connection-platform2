import { useState } from "react";

export default function Onboarding({ onDone }) {
  const [step, setStep] = useState(1);
  const [form, setForm] = useState({
    intentions: [],
    energyLevel: "",
    communication: "",
    sensoryTriggers: [],
    wantsNvcHelp: false
  });

  const toggle = (key, value) => {
    setForm(f => ({
      ...f,
      [key]: f[key].includes(value)
        ? f[key].filter(v => v !== value)
        : [...f[key], value]
    }));
  };

  const save = async () => {
    const token = localStorage.getItem("nd_token");
    await fetch("/api/me", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "x-token": token
      },
      body: JSON.stringify(form)
    });
    onDone();
  };

  return (
    <div className="container">
      {step === 1 && (
        <>
          <h2>Waar sta je voor open?</h2>
          {["Romantisch", "Vriendschap", "Community", "Diepe gesprekken"].map(i => (
            <label key={i} className="card" style={ { display: 'block', cursor: 'pointer' } }>
              <input
                type="checkbox"
                checked={form.intentions.includes(i.toLowerCase())}
                onChange={() => toggle("intentions", i.toLowerCase())}
              /> {i}
            </label>
          ))}
          <button className="button" onClick={() => setStep(2)}>Verder</button>
        </>
      )}

      {step === 2 && (
        <>
          <h2>Energie & prikkels</h2>
          <p>Dit helpt ons het tempo en de hoeveelheid contact af te stemmen. Alles is optioneel.</p>

          <select
            value={form.energyLevel}
            onChange={e => setForm({ ...form, energyLevel: e.target.value })}
            className="card"
            style={ { width: '100%', marginBottom: '12px' } }
          >
            <option value="">Hoe voelt sociaal contact meestal?</option>
            <option value="laag">🌱 Rustig</option>
            <option value="wisselend">🔄 Wisselend</option>
            <option value="hoog">🔥 Actief</option>
          </select>

          <p>Wat kan soms te veel zijn?</p>

          {[
            "Veel geluid",
            "Drukke omgevingen",
            "Veel berichten tegelijk"
          ].map(p => (
            <label key={p} className="card" style={ { display: 'block', cursor: 'pointer' } }>
              <input
                type="checkbox"
                checked={form.sensoryTriggers.includes(p.toLowerCase())}
                onChange={() => toggle("sensoryTriggers", p.toLowerCase())}
              /> {p}
            </label>
          ))}

          <button className="button" onClick={() => setStep(3)}>Verder</button>
        </>
      )}

      {step === 3 && (
        <>
          <h2>Communicatie</h2>
          {["schriftelijk", "direct", "reflectief"].map(c => (
            <label key={c} className="card" style={ { display: 'block', cursor: 'pointer' } }>
              <input
                type="radio"
                name="comm"
                checked={form.communication === c}
                onChange={() => setForm({ ...form, communication: c })}
              /> {c}
            </label>
          ))}
          <button className="button" onClick={() => setStep(4)}>Verder</button>
        </>
      )}

      {step === 4 && (
        <>
          <h2>Verbindende communicatie</h2>
          <label className="card" style={ { display: 'block', cursor: 'pointer' } }>
            <input
              type="checkbox"
              checked={form.wantsNvcHelp}
              onChange={() => setForm({ ...form, wantsNvcHelp: !form.wantsNvcHelp })}
            /> Ik sta open voor hulp bij verbindend communiceren
          </label>

          <button className="button" onClick={save}>Afronden</button>
        </>
      )}
    </div>
  );
}
