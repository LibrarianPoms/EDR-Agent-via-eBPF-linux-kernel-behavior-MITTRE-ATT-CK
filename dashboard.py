#!/usr/bin/env python3
"""
Dashboard defenseur - Semaine 6
Lit les fichiers alerts.jsonl et stats.json generes par l'agent EDR
(step9_lolbins_credaccess.py) et les affiche dans une interface web
lisible par un non-expert, avec code couleur par severite.

Usage: python3 dashboard.py
Puis ouvrir : http://localhost:5000 (dans le navigateur DE LA VM)

Prerequis : l'agent (step9) doit avoir tourne au moins une fois pour que
~/edr_agent_logs/alerts.jsonl et stats.json existent.
"""

from flask import Flask, jsonify, render_template_string
import json
import os

app = Flask(__name__)

LOG_DIR = os.path.expanduser("~/edr_agent_logs")
ALERTS_FILE = os.path.join(LOG_DIR, "alerts.jsonl")
STATS_FILE = os.path.join(LOG_DIR, "stats.json")

PAGE = """
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Agent EDR — Tableau de bord</title>
<style>
  :root {
    --bg: #0b0f1a; --card: #131a2b; --border: #232b40;
    --text: #e6e9f0; --muted: #8a93a6;
    --critique: #ff3b3b; --critique-bg: #2c1214;
    --high: #ff9500; --high-bg: #2a1d0d;
    --medium: #ffd43b; --medium-bg: #2a2712;
    --safe: #35d488; --accent: #4c8dff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--text); padding: 28px 36px;
  }
  h1 { font-size: 23px; margin-bottom: 2px; }
  .subtitle { color: var(--muted); margin-bottom: 22px; font-size: 13.5px; }
  .stats-grid {
    display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px;
    margin-bottom: 26px;
  }
  .stat-card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px 18px;
  }
  .stat-value { font-size: 26px; font-weight: 700; }
  .stat-label { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .stat-card.alert .stat-value { color: var(--critique); }
  .status-badge {
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--card); border: 1px solid var(--border);
    padding: 5px 13px; border-radius: 20px; font-size: 12.5px; margin-bottom: 20px;
  }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%; background: var(--safe);
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  .filters {
    display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;
  }
  .filter-btn {
    background: var(--card); border: 1px solid var(--border); color: var(--muted);
    padding: 6px 14px; border-radius: 18px; font-size: 12.5px; cursor: pointer;
    transition: all 0.15s;
  }
  .filter-btn.active { color: var(--text); border-color: var(--accent); background: #1a2540; }
  .section-title {
    font-size: 15px; font-weight: 600; margin: 22px 0 12px;
  }
  .alert-card {
    border: 1px solid var(--border); border-left: 4px solid var(--high);
    border-radius: 10px; padding: 14px 18px; margin-bottom: 10px;
  }
  .alert-card.CRITIQUE { background: var(--critique-bg); border-left-color: var(--critique); }
  .alert-card.HIGH { background: var(--high-bg); border-left-color: var(--high); }
  .alert-card.MEDIUM { background: var(--medium-bg); border-left-color: var(--medium); }
  .alert-top {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 7px; flex-wrap: wrap; gap: 8px;
  }
  .alert-title { font-weight: 600; font-size: 14px; }
  .alert-title.CRITIQUE { color: var(--critique); }
  .alert-title.HIGH { color: var(--high); }
  .alert-title.MEDIUM { color: var(--medium); }
  .badges { display: flex; gap: 6px; flex-wrap: wrap; }
  .badge {
    padding: 3px 10px; border-radius: 6px; font-size: 11px; font-weight: 600;
  }
  .badge.sev-CRITIQUE { background: rgba(255,59,59,0.18); color: var(--critique); }
  .badge.sev-HIGH { background: rgba(255,149,0,0.18); color: var(--high); }
  .badge.sev-MEDIUM { background: rgba(255,212,59,0.18); color: var(--medium); }
  .badge.mitre { background: rgba(76,141,255,0.15); color: var(--accent); }
  .alert-desc { color: var(--text); font-size: 13.5px; line-height: 1.5; }
  .alert-meta { color: var(--muted); font-size: 11.5px; margin-top: 8px; }
  .empty-state {
    text-align: center; padding: 44px 20px; color: var(--muted);
    background: var(--card); border-radius: 12px; border: 1px dashed var(--border);
  }
  .empty-state .icon { font-size: 36px; margin-bottom: 8px; }
</style>
</head>
<body>
  <h1>Agent EDR — Tableau de bord</h1>
  <div class="subtitle">Detection comportementale des menaces via eBPF — T1055 (injection), T1218 (LOLBins), T1003 (identifiants)</div>
  <div class="status-badge"><span class="status-dot"></span> <span id="status-text">Connexion...</span></div>

  <div class="stats-grid">
    <div class="stat-card"><div class="stat-value" id="stat-total">-</div><div class="stat-label">Evenements analyses</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-filtered">-</div><div class="stat-label">Bruit filtre</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-shown">-</div><div class="stat-label">Evenements pertinents</div></div>
    <div class="stat-card alert"><div class="stat-value" id="stat-alerts">-</div><div class="stat-label">Alertes totales</div></div>
    <div class="stat-card alert"><div class="stat-value" id="stat-critical">-</div><div class="stat-label">Alertes critiques</div></div>
  </div>

  <div class="filters">
    <div class="filter-btn active" data-filter="ALL">Toutes</div>
    <div class="filter-btn" data-filter="CRITIQUE">Critique</div>
    <div class="filter-btn" data-filter="HIGH">High</div>
    <div class="filter-btn" data-filter="MEDIUM">Medium</div>
  </div>

  <div class="section-title">Alertes recentes</div>
  <div id="alerts-container"><div class="empty-state"><div class="icon">🛡️</div>Aucune alerte pour le moment. Le systeme est surveille activement.</div></div>

<script>
let currentFilter = "ALL";
let latestAlerts = [];

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
    renderAlerts();
  });
});

function renderAlerts() {
  const container = document.getElementById('alerts-container');
  const filtered = currentFilter === "ALL"
    ? latestAlerts
    : latestAlerts.filter(a => a.severity === currentFilter);

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">🛡️</div>Aucune alerte' + (currentFilter !== "ALL" ? " de niveau " + currentFilter : "") + ' pour le moment.</div>';
    return;
  }

  container.innerHTML = filtered.slice().reverse().map(a => `
    <div class="alert-card ${a.severity}">
      <div class="alert-top">
        <span class="alert-title ${a.severity}">⚠ ${a.mitre_name}</span>
        <div class="badges">
          <span class="badge sev-${a.severity}">${a.severity}</span>
          <span class="badge mitre">${a.mitre_id}</span>
        </div>
      </div>
      <div class="alert-desc">${a.description_fr}</div>
      <div class="alert-meta">${a.datetime} · Acteur : ${a.actor_process} (PID ${a.actor_pid}) · Cible : ${a.target_process || 'N/A'} (PID ${a.target_pid}) · Reponse : ${a.response_action}</div>
    </div>
  `).join('');
}

async function refresh() {
  try {
    const statsRes = await fetch('/api/stats');
    const stats = await statsRes.json();
    document.getElementById('stat-total').textContent = stats.events_total ?? 0;
    document.getElementById('stat-filtered').textContent = stats.events_filtered ?? 0;
    document.getElementById('stat-shown').textContent = stats.events_shown ?? 0;
    document.getElementById('stat-alerts').textContent = stats.alerts_total ?? 0;
    document.getElementById('status-text').textContent =
        stats.status === 'running' ? "Agent actif - surveillance en cours" : "Agent arrete";

    const alertsRes = await fetch('/api/alerts');
    const alerts = await alertsRes.json();
    latestAlerts = alerts;
    document.getElementById('stat-critical').textContent = alerts.filter(a => a.severity === 'CRITIQUE').length;
    renderAlerts();
  } catch (e) {
    document.getElementById('status-text').textContent = "Agent non demarre";
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

@app.route("/api/stats")
def api_stats():
    try:
        with open(STATS_FILE) as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify({"status": "not_started"})

@app.route("/api/alerts")
def api_alerts():
    alerts = []
    try:
        with open(ALERTS_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    alerts.append(json.loads(line))
    except FileNotFoundError:
        pass
    return jsonify(alerts[-100:])

if __name__ == "__main__":
    print("[+] Dashboard EDR disponible sur http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
