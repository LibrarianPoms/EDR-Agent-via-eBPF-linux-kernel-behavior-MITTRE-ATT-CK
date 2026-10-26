#!/usr/bin/env python3
"""
Tableau de bord "attaquant" - Semaine 6 (bonus / stretch goal)

Affiche l'historique des tentatives d'attaque du point de vue de
l'attaquant (ce qu'il a techniquement accompli), et - a des fins
purement pedagogiques et comparatives - croise ces tentatives avec le
journal de l'agent EDR pour indiquer si chaque attaque a ete detectee.

IMPORTANT (a mentionner dans le rapport) : dans un scenario reel, un
attaquant n'a PAS acces au journal du defenseur. Cette correlation
n'est possible ici que parce qu'il s'agit d'un environnement de
laboratoire controle sur une seule VM, ou les deux journaux sont
accessibles au meme utilisateur. Ce tableau de bord sert a illustrer
et comparer visuellement les deux perspectives (attaque vs detection),
pas a simuler un vrai panneau de controle d'attaquant (C2).

Usage: python3 attacker_dashboard.py
Puis ouvrir : http://localhost:5001
"""

from flask import Flask, jsonify, render_template_string
import json
import os
import time

app = Flask(__name__)

ATTACKER_LOG_DIR = os.path.expanduser("~/attacker_logs")
ATTEMPTS_FILE = os.path.join(ATTACKER_LOG_DIR, "attempts.jsonl")

DEFENDER_LOG_DIR = os.path.expanduser("~/edr_agent_logs")
DEFENDER_ALERTS_FILE = os.path.join(DEFENDER_LOG_DIR, "alerts.jsonl")

PAGE = """
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Vue Attaquant — Journal des tentatives</title>
<style>
  :root {
    --bg: #150b0b; --card: #201212; --card2: #2a1616; --border: #3d2020;
    --text: #f0e6e6; --muted: #a68a8a;
    --success: #ff5c3b; --fail: #6b6b6b;
    --detected: #ff3b3b; --undetected: #35d488; --accent: #ff8a3b;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--text); padding: 26px 34px 60px;
  }
  h1 { font-size: 22px; margin-bottom: 2px; }
  .subtitle { color: var(--muted); margin-bottom: 6px; font-size: 13px; }
  .disclaimer {
    background: var(--card2); border: 1px solid var(--border); border-radius: 10px;
    padding: 10px 14px; font-size: 12px; color: var(--muted); margin-bottom: 20px;
    max-width: 900px; line-height: 1.5;
  }
  .stats-grid {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
    margin-bottom: 22px;
  }
  .stat-card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px 18px;
  }
  .stat-value { font-size: 26px; font-weight: 700; }
  .stat-label { color: var(--muted); font-size: 11.5px; margin-top: 4px; }
  .stat-card.det .stat-value { color: var(--detected); }
  .stat-card.undet .stat-value { color: var(--undetected); }
  .section-title { font-size: 14.5px; font-weight: 600; margin: 4px 0 12px; }
  .attempt-card {
    background: var(--card); border: 1px solid var(--border); border-left: 4px solid var(--success);
    border-radius: 10px; padding: 14px 18px; margin-bottom: 10px;
  }
  .attempt-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 7px; flex-wrap: wrap; gap: 8px; }
  .attempt-title { font-weight: 600; font-size: 14px; color: var(--accent); }
  .badges { display: flex; gap: 6px; flex-wrap: wrap; }
  .badge { padding: 3px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; }
  .badge.mitre { background: rgba(255,138,59,0.15); color: var(--accent); }
  .badge.detected { background: rgba(255,59,59,0.18); color: var(--detected); }
  .badge.undetected { background: rgba(53,212,136,0.18); color: var(--undetected); }
  .attempt-desc { color: var(--text); font-size: 13.5px; line-height: 1.5; }
  .attempt-meta { color: var(--muted); font-size: 11.5px; margin-top: 8px; }
  .empty-state {
    text-align: center; padding: 44px 20px; color: var(--muted);
    background: var(--card); border-radius: 12px; border: 1px dashed var(--border);
  }
  .empty-state .icon { font-size: 36px; margin-bottom: 8px; }
</style>
</head>
<body>
  <h1>🩸 Vue Attaquant — Journal des tentatives</h1>
  <div class="subtitle">Ce que l'attaquant a techniquement accompli, croise avec le statut de detection cote defenseur</div>
  <div class="disclaimer">
    ⚠ A des fins pedagogiques uniquement : dans un scenario reel, un attaquant n'a pas acces
    au journal du defenseur. Ce croisement n'est possible ici que parce que les deux journaux
    (attaquant et defenseur) sont accessibles sur la meme VM de laboratoire.
  </div>

  <div class="stats-grid">
    <div class="stat-card"><div class="stat-value" id="stat-total">-</div><div class="stat-label">Tentatives totales</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-success">-</div><div class="stat-label">Techniquement reussies</div></div>
    <div class="stat-card det"><div class="stat-value" id="stat-detected">-</div><div class="stat-label">Detectees par l'EDR</div></div>
    <div class="stat-card undet"><div class="stat-value" id="stat-undetected">-</div><div class="stat-label">Non detectees</div></div>
  </div>

  <div class="section-title">Historique des tentatives</div>
  <div id="attempts-container"><div class="empty-state"><div class="icon">🗡️</div>Aucune tentative enregistree pour le moment.</div></div>

<script>
async function refresh() {
  try {
    const res = await fetch('/api/attempts');
    const attempts = await res.json();

    document.getElementById('stat-total').textContent = attempts.length;
    document.getElementById('stat-success').textContent = attempts.filter(a => a.success).length;
    document.getElementById('stat-detected').textContent = attempts.filter(a => a.detected).length;
    document.getElementById('stat-undetected').textContent = attempts.filter(a => a.success && !a.detected).length;

    const container = document.getElementById('attempts-container');
    if (attempts.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="icon">🗡️</div>Aucune tentative enregistree pour le moment.</div>';
      return;
    }

    container.innerHTML = attempts.slice().reverse().map(a => `
      <div class="attempt-card">
        <div class="attempt-top">
          <span class="attempt-title">${a.success ? '⚔' : '✖'} ${a.technique}</span>
          <div class="badges">
            <span class="badge mitre">${a.mitre_id}</span>
            <span class="badge ${a.detected ? 'detected' : 'undetected'}">${a.detected ? '🔴 Detectee' : '🟢 Non detectee'}</span>
          </div>
        </div>
        <div class="attempt-desc">${a.details}</div>
        <div class="attempt-meta">${a.datetime} · PID attaquant ${a.actor_pid} · Cible : ${a.target_process || 'N/A'} (PID ${a.target_pid ?? 'N/A'})</div>
      </div>
    `).join('');
  } catch (e) {
    console.error(e);
  }
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(PAGE)

def load_jsonl(path):
    items = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    items.append(json.loads(line))
    except FileNotFoundError:
        pass
    return items

@app.route("/api/attempts")
def api_attempts():
    attempts = load_jsonl(ATTEMPTS_FILE)
    defender_alerts = load_jsonl(DEFENDER_ALERTS_FILE)

    # Correlation simple : une tentative est consideree "detectee" si une
    # alerte defenseur existe avec le meme mitre_id et un timestamp proche
    # (fenetre de 10s), en se basant sur le PID acteur ou cible.
    for a in attempts:
        a["detected"] = False
        for alert in defender_alerts:
            same_technique_family = a["mitre_id"] == alert.get("mitre_id")
            close_in_time = abs(a["timestamp"] - alert.get("timestamp", 0)) <= 10
            same_actor = a["actor_pid"] == alert.get("actor_pid")
            if same_technique_family and close_in_time and same_actor:
                a["detected"] = True
                break

    return jsonify(attempts)

if __name__ == "__main__":
    print("[+] Tableau de bord Attaquant disponible sur http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
