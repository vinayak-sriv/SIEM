#!/usr/bin/env python3
"""
dashboard.py — SIEM AI Agent web dashboard.

Reads alerts_enriched.jsonl and serves a live-updating web UI.

Usage:
    python3 dashboard.py --config config.yaml
    python3 dashboard.py --port 8080
    python3 dashboard.py --reports ./reports --token change-me

Open http://localhost:5000 in your browser.

Install Flask if you haven't already:
    python -m venv .venv && .venv/bin/pip install -r requirements.txt
"""

import argparse
import json
import logging
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

try:
    from flask import Flask, abort, jsonify, render_template_string, request
except ModuleNotFoundError as exc:
    import sys
    raise SystemExit(
        f"Could not import Flask ({exc}).\n"
        f"Fix: {sys.executable} -m pip install flask\n"
        f"Then re-run: {sys.executable} dashboard.py"
    ) from exc

log = logging.getLogger("Dashboard")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

# ── HTML / CSS / JS ───────────────────────────────────────────────────────────
_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SIEM AI Agent</title>
<style>
  :root {
    --bg:        #050a0f;
    --surface:   #0b1520;
    --border:    #0d2137;
    --accent:    #00d4ff;
    --accent2:   #00ff9d;
    --critical:  #ff2d55;
    --high:      #ff6b2d;
    --medium:    #ffc107;
    --low:       #546e7a;
    --text:      #c8d8e8;
    --muted:     #4a6070;
    --font-mono: Consolas, 'Cascadia Mono', 'Courier New', monospace;
    --font-ui:   'Segoe UI', Arial, sans-serif;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-ui);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Grid background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  .wrap { position: relative; z-index: 1; max-width: 1400px; margin: 0 auto; padding: 24px; }

  /* ── Header ── */
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    padding-bottom: 20px;
    margin-bottom: 28px;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .logo-icon {
    width: 42px; height: 42px;
    border: 2px solid var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
    box-shadow: 0 0 16px rgba(0,212,255,0.25);
  }

  .logo-text h1 {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 2px;
    color: #fff;
    text-transform: uppercase;
  }

  .logo-text p {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--accent);
    letter-spacing: 1px;
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 20px;
  }

  .live-badge {
    display: flex;
    align-items: center;
    gap: 7px;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--accent2);
    letter-spacing: 1px;
  }

  .live-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--accent2);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(0,255,157,0.4); }
    50% { opacity: 0.7; box-shadow: 0 0 0 5px rgba(0,255,157,0); }
  }

  #last-update {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted);
  }

  /* ── Demo status strip ── */
  .system-strip {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin-bottom: 18px;
  }

  .system-pill {
    background: rgba(11, 21, 32, 0.86);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
    min-width: 0;
  }

  .system-key {
    color: var(--muted);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 5px;
  }

  .system-val {
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 12px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .system-val.ok { color: var(--accent2); }
  .system-val.warn { color: var(--medium); }

  /* ── Stats row ── */
  .stats {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 14px;
    margin-bottom: 28px;
  }

  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 18px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
  }

  .stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
  }

  .stat-card.total::before   { background: var(--accent); }
  .stat-card.critical::before { background: var(--critical); }
  .stat-card.high::before    { background: var(--high); }
  .stat-card.medium::before  { background: var(--medium); }
  .stat-card.low::before     { background: var(--low); }

  .stat-label {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 8px;
  }

  .stat-value {
    font-family: var(--font-mono);
    font-size: 32px;
    font-weight: 400;
    line-height: 1;
  }

  .stat-card.total   .stat-value { color: var(--accent); }
  .stat-card.critical .stat-value { color: var(--critical); }
  .stat-card.high    .stat-value { color: var(--high); }
  .stat-card.medium  .stat-value { color: var(--medium); }
  .stat-card.low     .stat-value { color: #78909c; }

  /* ── Controls ── */
  .controls {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 18px;
    flex-wrap: wrap;
  }

  .filter-btn {
    font-family: var(--font-ui);
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 7px 16px;
    border-radius: 5px;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--muted);
    cursor: pointer;
    transition: all 0.15s;
  }

  .filter-btn:hover { border-color: var(--accent); color: var(--accent); }
  .filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(0,212,255,0.08); }

  .search-box {
    margin-left: auto;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 7px 14px;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text);
    width: 240px;
    transition: border-color 0.15s;
  }

  .search-box:focus { outline: none; border-color: var(--accent); }
  .search-box::placeholder { color: var(--muted); }

  /* ── Alert table ── */
  .table-wrap {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }

  table { width: 100%; border-collapse: collapse; }

  thead tr {
    background: rgba(0,212,255,0.05);
    border-bottom: 1px solid var(--border);
  }

  th {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--muted);
    padding: 12px 16px;
    text-align: left;
  }

  tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
    cursor: pointer;
    animation: slideIn 0.3s ease both;
  }

  @keyframes slideIn {
    from { opacity: 0; transform: translateX(-10px); }
    to   { opacity: 1; transform: translateX(0); }
  }

  tbody tr:hover { background: rgba(0,212,255,0.04); }
  tbody tr:last-child { border-bottom: none; }

  td {
    padding: 13px 16px;
    font-size: 14px;
    vertical-align: middle;
  }

  .sev-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 400;
    padding: 3px 10px;
    border-radius: 3px;
    white-space: nowrap;
    letter-spacing: 0.5px;
  }

  .sev-badge.critical { background: rgba(255,45,85,0.15);  color: var(--critical); border: 1px solid rgba(255,45,85,0.3); }
  .sev-badge.high     { background: rgba(255,107,45,0.15); color: var(--high);     border: 1px solid rgba(255,107,45,0.3); }
  .sev-badge.medium   { background: rgba(255,193,7,0.12);  color: var(--medium);   border: 1px solid rgba(255,193,7,0.25); }
  .sev-badge.low      { background: rgba(84,110,122,0.15); color: #78909c;         border: 1px solid rgba(84,110,122,0.3); }

  .rule-id {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--accent);
  }

  .agent-name { font-weight: 600; color: #e0eaf4; }
  .source-ip  { font-family: var(--font-mono); font-size: 12px; color: var(--muted); }
  .ts         { font-family: var(--font-mono); font-size: 11px; color: var(--muted); white-space: nowrap; }

  .rule-desc {
    max-width: 280px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 13px;
  }

  /* ── Modal ── */
  .modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(5,10,15,0.85);
    z-index: 100;
    align-items: center;
    justify-content: center;
    padding: 24px;
    backdrop-filter: blur(4px);
  }

  .modal-overlay.open { display: flex; }

  .modal {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    max-width: 760px;
    width: 100%;
    max-height: 85vh;
    overflow-y: auto;
    animation: modalIn 0.2s ease;
  }

  @keyframes modalIn {
    from { opacity: 0; transform: scale(0.96); }
    to   { opacity: 1; transform: scale(1); }
  }

  .modal-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    padding: 22px 24px 18px;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--surface);
    z-index: 1;
  }

  .modal-title { font-size: 17px; font-weight: 700; color: #fff; margin-bottom: 4px; }
  .modal-sub   { font-family: var(--font-mono); font-size: 11px; color: var(--muted); }

  .modal-close {
    background: none;
    border: none;
    color: var(--muted);
    font-size: 22px;
    cursor: pointer;
    padding: 0 4px;
    transition: color 0.15s;
    line-height: 1;
  }
  .modal-close:hover { color: var(--critical); }

  .modal-body { padding: 22px 24px; }

  .meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 22px;
  }

  .meta-item {
    background: rgba(0,212,255,0.04);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 14px;
  }

  .meta-key {
    font-size: 10px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 4px;
  }

  .meta-val {
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--text);
    word-break: break-all;
  }

  .section {
    margin-bottom: 20px;
  }

  .section-label {
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 10px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border);
  }

  .section.explanation .section-label { color: var(--accent); }
  .section.impact      .section-label { color: var(--critical); }
  .section.remediation .section-label { color: var(--accent2); }

  .section-body {
    font-size: 14px;
    line-height: 1.7;
    color: var(--text);
    white-space: pre-wrap;
    word-break: break-word;
  }

  /* code blocks inside remediation */
  .section-body code {
    font-family: var(--font-mono);
    font-size: 12px;
    background: #0a1a2a;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 14px;
    display: block;
    margin: 6px 0;
    overflow-x: auto;
    line-height: 1.6;
    color: var(--accent2);
  }

  /* ── Empty / error states ── */
  .empty {
    text-align: center;
    padding: 60px 20px;
    color: var(--muted);
  }

  .empty .empty-icon { font-size: 42px; margin-bottom: 14px; opacity: 0.4; }
  .empty p { font-family: var(--font-mono); font-size: 13px; }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--muted); }

  @media (max-width: 900px) {
    .stats { grid-template-columns: repeat(3, 1fr); }
    .system-strip { grid-template-columns: repeat(2, 1fr); }
    .meta-grid { grid-template-columns: 1fr; }
  }
  @media (max-width: 600px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    .system-strip { grid-template-columns: 1fr; }
    .controls { flex-direction: column; align-items: stretch; }
    .search-box { margin-left: 0; width: 100%; }
  }
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div class="logo">
      <div class="logo-icon">🛡</div>
      <div class="logo-text">
        <h1>SIEM AI Agent</h1>
        <p>WAZUH + OLLAMA // ALERT DASHBOARD</p>
      </div>
    </div>
    <div class="header-right">
      <div class="live-badge">
        <div class="live-dot"></div>
        LIVE
      </div>
      <div id="last-update">Fetching...</div>
    </div>
  </header>

  <div class="system-strip">
    <div class="system-pill">
      <div class="system-key">API</div>
      <div class="system-val warn" id="sys-api">Checking...</div>
    </div>
    <div class="system-pill">
      <div class="system-key">LLM Model</div>
      <div class="system-val" id="sys-model">tinyllama</div>
    </div>
    <div class="system-pill">
      <div class="system-key">Threshold</div>
      <div class="system-val" id="sys-threshold">Level >= 10</div>
    </div>
    <div class="system-pill">
      <div class="system-key">Report Store</div>
      <div class="system-val" id="sys-reports">./reports</div>
    </div>
  </div>

  <div class="stats">
    <div class="stat-card total">
      <div class="stat-label">Total Alerts</div>
      <div class="stat-value" id="s-total">—</div>
    </div>
    <div class="stat-card critical">
      <div class="stat-label">Critical Total</div>
      <div class="stat-value" id="s-critical">—</div>
    </div>
    <div class="stat-card high">
      <div class="stat-label">High Total</div>
      <div class="stat-value" id="s-high">—</div>
    </div>
    <div class="stat-card medium">
      <div class="stat-label">Medium-High Total</div>
      <div class="stat-value" id="s-medium">—</div>
    </div>
    <div class="stat-card low">
      <div class="stat-label">Low Total</div>
      <div class="stat-value" id="s-low">—</div>
    </div>
  </div>

  <div class="controls">
    <button class="filter-btn active" data-sev="all">All</button>
    <button class="filter-btn" data-sev="critical">Critical</button>
    <button class="filter-btn" data-sev="high">High</button>
    <button class="filter-btn" data-sev="medium">Medium-High</button>
    <input class="search-box" type="text" id="search" placeholder="Search rule, agent, IP...">
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule</th>
          <th>Description</th>
          <th>Agent</th>
          <th>Source IP</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody id="alert-tbody">
        <tr><td colspan="6"><div class="empty"><div class="empty-icon">⌛</div><p>Loading alerts...</p></div></td></tr>
      </tbody>
    </table>
  </div>

</div>

<!-- Detail modal -->
<div class="modal-overlay" id="modal" onclick="closeModal(event)">
  <div class="modal" id="modal-box">
    <div class="modal-header">
      <div>
        <div class="modal-title" id="m-title"></div>
        <div class="modal-sub"  id="m-sub"></div>
      </div>
      <button class="modal-close" onclick="document.getElementById('modal').classList.remove('open')">✕</button>
    </div>
    <div class="modal-body">
      <div class="meta-grid" id="m-meta"></div>
      <div class="section explanation">
        <div class="section-label">📋 Explanation</div>
        <div class="section-body" id="m-explanation"></div>
      </div>
      <div class="section impact">
        <div class="section-label">💥 Impact</div>
        <div class="section-body" id="m-impact"></div>
      </div>
      <div class="section remediation">
        <div class="section-label">🔧 Remediation</div>
        <div class="section-body" id="m-remediation"></div>
      </div>
    </div>
  </div>
</div>

<script>
  let allAlerts = [];
  let activeFilter = 'all';
  const dashboardToken = new URLSearchParams(window.location.search).get('token') || '';

  // ── Helpers ───────────────────────────────────────────────────────────────
  function severityKey(label) {
    const l = label.toUpperCase();
    if (l.includes('CRITICAL')) return 'critical';
    if (l.includes('MEDIUM'))   return 'medium';
    if (l.includes('HIGH'))     return 'high';
    return 'low';
  }

  function sevClass(label) {
    return severityKey(label);
  }

  function fmtTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString('en-GB', { day:'2-digit', month:'short',
      hour:'2-digit', minute:'2-digit', second:'2-digit', hour12: false });
  }

  function escHtml(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // Wrap ```...``` blocks in <code> tags for remediation display
  function fmtRemediation(text) {
    return escHtml(text).replace(
      /```[a-z]*\n?([\s\S]*?)```/g,
      (_, inner) => `<code>${inner.trim()}</code>`
    );
  }

  function apiUrl(path) {
    if (!dashboardToken) return path;
    const sep = path.includes('?') ? '&' : '?';
    return `${path}${sep}token=${encodeURIComponent(dashboardToken)}`;
  }

  // ── Render table ──────────────────────────────────────────────────────────
  function render() {
    const q = document.getElementById('search').value.toLowerCase();
    const tbody = document.getElementById('alert-tbody');

    const filtered = allAlerts.filter(a => {
      if (activeFilter !== 'all' && severityKey(a.severityLabel || '') !== activeFilter)
        return false;
      if (q && !a._search.includes(q))
        return false;
      return true;
    });

    if (!filtered.length) {
      const message = allAlerts.length
        ? 'No alerts match your filter.'
        : 'Dashboard online. Waiting for enriched Wazuh alerts.';
      const detail = allAlerts.length
        ? 'Try another severity filter or search term.'
        : 'Start middleware, trigger the Kali attack simulation, then watch this table populate.';
      tbody.innerHTML = `<tr><td colspan="6"><div class="empty">
        <div class="empty-icon">${allAlerts.length ? '🔍' : '⏳'}</div>
        <p>${message}</p>
        <p style="margin-top:8px;color:#6d8598">${detail}</p></div></td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map((a, i) => {
      const sc = sevClass(a.severityLabel || '');
      const ts = fmtTime(a.generatedAt || a.timestamp);
      return `<tr onclick="openModal(${a._idx})" style="animation-delay:${Math.min(i*0.03,0.4)}s">
        <td><span class="sev-badge ${sc}">${escHtml(a.severityLabel || '—')}</span></td>
        <td><span class="rule-id">${escHtml(a.ruleId || '—')}</span></td>
        <td><div class="rule-desc" title="${escHtml(a.ruleDesc||'')}">${escHtml(a.ruleDesc || '—')}</div></td>
        <td><span class="agent-name">${escHtml(a.agentName || '—')}</span></td>
        <td><span class="source-ip">${escHtml(a.sourceIP || '—')}</span></td>
        <td><span class="ts">${ts}</span></td>
      </tr>`;
    }).join('');
  }

  // ── Stats ─────────────────────────────────────────────────────────────────
  function updateStats(alerts, totalAlerts, severityTotals) {
    const count = (sev) => severityTotals?.[sev] ?? alerts.filter(a => severityKey(a.severityLabel || '') === sev).length;
    document.getElementById('s-total').textContent    = totalAlerts ?? alerts.length;
    document.getElementById('s-critical').textContent = count('critical');
    document.getElementById('s-high').textContent     = count('high');
    document.getElementById('s-medium').textContent   = count('medium');
    document.getElementById('s-low').textContent      = count('low');
  }

  // ── Fetch ─────────────────────────────────────────────────────────────────
  async function fetchAlerts() {
    try {
      const r = await fetch(apiUrl('/api/alerts'));
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const data = await r.json();
      allAlerts = (data.alerts || []).map((alert, idx) => ({
        ...alert,
        _idx: idx,
        _search: JSON.stringify(alert).toLowerCase()
      }));
      updateStats(allAlerts, data.total, data.severityTotals);
      render();
      document.getElementById('last-update').textContent =
        'Updated ' + new Date().toLocaleTimeString('en-GB');
    } catch(e) {
      console.error('Fetch failed:', e);
      document.getElementById('last-update').textContent = 'API fetch failed';
      document.getElementById('sys-api').textContent = 'ERROR';
      document.getElementById('sys-api').className = 'system-val warn';
    }
  }

  async function fetchStatus() {
    try {
      const r = await fetch(apiUrl('/api/status'));
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const s = await r.json();
      const api = document.getElementById('sys-api');
      api.textContent = 'ONLINE';
      api.className = 'system-val ok';
      document.getElementById('sys-model').textContent =
        `${s.model || 'unknown'}${s.ollamaUrl ? ' @ ' + s.ollamaUrl : ''}`;
      document.getElementById('sys-threshold').textContent =
        `Level >= ${s.threshold || 10}`;
      document.getElementById('sys-reports').textContent =
        `${s.reportsDir || 'reports'} (${s.count || 0} total / ${s.windowCount || 0} shown)`;
    } catch(e) {
      const api = document.getElementById('sys-api');
      api.textContent = 'ERROR';
      api.className = 'system-val warn';
    }
  }

  // ── Modal ─────────────────────────────────────────────────────────────────
  function openModal(idx) {
    const a = allAlerts[idx];
    if (!a) return;

    document.getElementById('m-title').textContent =
      (a.severityLabel || '') + ' — ' + (a.ruleDesc || '');
    document.getElementById('m-sub').textContent =
      'Alert ID: ' + (a.alertId || '').slice(0, 12) +
      '  ·  Generated: ' + fmtTime(a.generatedAt || a.timestamp);

    const meta = [
      ['Rule ID',    a.ruleId  || '—'],
      ['Agent',      (a.agentName || '—') + ' · ' + (a.agentIP || '—')],
      ['Source IP',  a.sourceIP  || '—'],
      ['Groups',     (a.groups||[]).join(', ') || '—'],
      ['Severity',   'Level ' + (a.severityLevel || '—') + ' — ' + (a.severityLabel || '—')],
      ['Timestamp',  fmtTime(a.timestamp)],
    ];
    document.getElementById('m-meta').innerHTML = meta.map(([k,v]) =>
      `<div class="meta-item">
        <div class="meta-key">${escHtml(k)}</div>
        <div class="meta-val">${escHtml(v)}</div>
      </div>`
    ).join('');

    document.getElementById('m-explanation').textContent = a.explanation || '—';
    document.getElementById('m-impact').textContent      = a.impact      || '—';
    // Remediation gets code-block formatting
    document.getElementById('m-remediation').innerHTML   =
      fmtRemediation(a.remediation || '—');

    document.getElementById('modal').classList.add('open');
  }

  function closeModal(e) {
    if (e.target === document.getElementById('modal'))
      document.getElementById('modal').classList.remove('open');
  }

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape')
      document.getElementById('modal').classList.remove('open');
  });

  // ── Filter buttons ────────────────────────────────────────────────────────
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeFilter = btn.dataset.sev;
      render();
    });
  });

  document.getElementById('search').addEventListener('input', render);

  // ── Init ──────────────────────────────────────────────────────────────────
  fetchStatus();
  fetchAlerts();
  setInterval(fetchStatus, 10000);
  setInterval(fetchAlerts, 10000);   // refresh every 10 seconds
</script>
</body>
</html>"""


# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
REPORTS_DIR = "./reports"
DASHBOARD_TOKEN = os.environ.get("SIEM_DASHBOARD_TOKEN", "")
DASHBOARD_META = {
    "model": "tinyllama",
    "ollama_url": "http://10.99.85.71:11434",
    "threshold": 10,
}
_ALERT_CACHE = {
    "path": None,
    "mtime_ns": None,
    "size": None,
    "limit": None,
    "alerts": [],
    "total": 0,
    "offset": 0,
    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
}


def _token_ok() -> bool:
    if not DASHBOARD_TOKEN:
        return True
    supplied = request.headers.get("X-Dashboard-Token") or request.args.get("token")
    return supplied == DASHBOARD_TOKEN


@app.before_request
def _require_dashboard_token():
    if not _token_ok():
        abort(401)


def _load_alerts(limit: int = 200) -> list:
    """
    Read the master JSONL log and return the most recent `limit` alerts,
    newest first.
    """
    jsonl_path = _jsonl_path()
    if not jsonl_path.exists():
        _ALERT_CACHE.update({
            "path": jsonl_path,
            "mtime_ns": None,
            "size": None,
            "limit": limit,
            "alerts": [],
            "total": 0,
            "offset": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        })
        return []

    stat = jsonl_path.stat()
    if (
        _ALERT_CACHE["path"] == jsonl_path and
        _ALERT_CACHE["mtime_ns"] == stat.st_mtime_ns and
        _ALERT_CACHE["size"] == stat.st_size and
        _ALERT_CACHE["limit"] == limit
    ):
        return list(_ALERT_CACHE["alerts"])

    try:
        same_file = _ALERT_CACHE["path"] == jsonl_path
        can_increment = (
            same_file and
            _ALERT_CACHE["limit"] == limit and
            _ALERT_CACHE["size"] is not None and
            stat.st_size >= _ALERT_CACHE["size"]
        )

        if can_increment:
            alerts = deque(reversed(_ALERT_CACHE["alerts"]), maxlen=limit)
            total = int(_ALERT_CACHE.get("total") or 0)
            severity_counts = dict(_ALERT_CACHE.get("severity_counts") or {})
            with jsonl_path.open("rb") as f:
                f.seek(int(_ALERT_CACHE.get("offset") or 0))
                for raw_line in f:
                    record = _parse_jsonl_alert(raw_line)
                    if record is None:
                        continue
                    alerts.append(record)
                    total += 1
                    sev = _severity_key(record.get("severityLabel") or "")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                offset = f.tell()
        else:
            alerts = deque(maxlen=limit)
            total = 0
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            with jsonl_path.open("rb") as f:
                for raw_line in f:
                    record = _parse_jsonl_alert(raw_line)
                    if record is None:
                        continue
                    alerts.append(record)
                    total += 1
                    sev = _severity_key(record.get("severityLabel") or "")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                offset = f.tell()
    except OSError as e:
        log.error(f"Could not read {jsonl_path}: {e}")
        _ALERT_CACHE.update({
            "path": None,
            "mtime_ns": None,
            "size": None,
            "limit": None,
            "alerts": [],
            "total": 0,
            "offset": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        })
        return []

    latest = list(reversed(alerts))
    _ALERT_CACHE.update({
        "path": jsonl_path,
        "mtime_ns": stat.st_mtime_ns,
        "size": stat.st_size,
        "limit": limit,
        "alerts": latest,
        "total": total,
        "offset": offset,
        "severity_counts": severity_counts,
    })
    return list(latest)


def _parse_jsonl_alert(raw_line: bytes):
    line = raw_line.decode("utf-8", errors="replace").strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    return record if isinstance(record, dict) else None


def _alert_count() -> int:
    """Return the total valid alert count, not just the dashboard window size."""
    _load_alerts()
    return int(_ALERT_CACHE.get("total") or 0)


def _severity_key(label: str) -> str:
    """Normalize display labels like 'MEDIUM-HIGH' without double-counting."""
    label = (label or "").upper()
    if "CRITICAL" in label:
        return "critical"
    if "MEDIUM" in label:
        return "medium"
    if "HIGH" in label:
        return "high"
    return "low"


def _jsonl_path() -> Path:
    return Path(REPORTS_DIR) / "alerts_enriched.jsonl"


@app.route("/")
def index():
    return render_template_string(_TEMPLATE)


@app.route("/api/alerts")
def api_alerts():
    """Return the latest alerts as JSON — polled by the dashboard every 10s."""
    alerts = _load_alerts()
    return jsonify({
        "alerts": alerts,
        "count":  len(alerts),
        "total":  int(_ALERT_CACHE.get("total") or 0),
        "severityTotals": dict(_ALERT_CACHE.get("severity_counts") or {}),
        "asOf":   _utc_now_iso(),
    })


@app.route("/api/stats")
def api_stats():
    """Quick summary counts by severity."""
    _load_alerts()
    counts = dict(_ALERT_CACHE.get("severity_counts") or {})
    return jsonify({
        "total":    int(_ALERT_CACHE.get("total") or 0),
        "scope":    "all_time",
        "critical": counts.get("critical", 0),
        "high":     counts.get("high", 0),
        "medium":   counts.get("medium", 0),
        "low":      counts.get("low", 0),
    })


@app.route("/api/status")
def api_status():
    """Dashboard health and demo metadata for the top status strip."""
    alerts = _load_alerts()
    jsonl_path = _jsonl_path()
    payload = {
        "ok": True,
        "reportsDir": str(Path(REPORTS_DIR).name or "reports"),
        "jsonlExists": jsonl_path.exists(),
        "count": _alert_count(),
        "windowCount": len(alerts),
        "model": DASHBOARD_META["model"],
        "threshold": DASHBOARD_META["threshold"],
        "asOf": _utc_now_iso(),
    }
    if DASHBOARD_TOKEN and _token_ok():
        payload.update({
            "reportsDir": str(Path(REPORTS_DIR)),
            "jsonlPath": str(jsonl_path),
            "ollamaUrl": DASHBOARD_META["ollama_url"],
        })
    return jsonify(payload)


def parse_args():
    p = argparse.ArgumentParser(description="SIEM AI Agent Dashboard")
    p.add_argument("--port",    type=int, default=5000, help="Port to listen on (default: 5000)")
    p.add_argument("--host",    default="127.0.0.1",    help="Host to bind (default: 127.0.0.1)")
    p.add_argument("--config",  help="Path to config.yaml for dashboard metadata")
    p.add_argument("--reports", default=None,           help="Path to reports directory")
    p.add_argument("--model",   default=None,           help="Model name shown on the dashboard")
    p.add_argument("--ollama-url", default=None,
                   help="Ollama URL shown on the dashboard")
    p.add_argument("--threshold", type=int, default=None,
                   help="Severity threshold shown on the dashboard")
    p.add_argument("--token", default=None,
                   help="Require this token for dashboard and API access")
    p.add_argument("--debug",   action="store_true",    help="Enable Flask debug mode")
    return p.parse_args()


def _load_dashboard_config(path: str) -> dict:
    """Load dashboard metadata from the project config file."""
    try:
        from config_loader import load_config
        return load_config(path)
    except Exception as exc:
        raise SystemExit(f"Could not load dashboard config {path}: {exc}") from exc


def _dashboard_settings(args) -> dict:
    settings = {
        "reports": "./reports",
        "model": "tinyllama",
        "ollama_url": "http://10.99.85.71:11434",
        "threshold": 10,
        "token": os.environ.get("SIEM_DASHBOARD_TOKEN", ""),
    }

    if args.config:
        cfg = _load_dashboard_config(args.config)
        settings.update({
            "reports": cfg.get("output", {}).get("report_dir", settings["reports"]),
            "model": cfg.get("ollama", {}).get("model", settings["model"]),
            "ollama_url": cfg.get("ollama", {}).get("base_url", settings["ollama_url"]),
            "threshold": cfg.get("filter", {}).get("min_severity_level", settings["threshold"]),
        })

    if args.reports is not None:
        settings["reports"] = args.reports
    if args.model is not None:
        settings["model"] = args.model
    if args.ollama_url is not None:
        settings["ollama_url"] = args.ollama_url
    if args.threshold is not None:
        settings["threshold"] = args.threshold
    if args.token is not None:
        settings["token"] = args.token

    try:
        settings["threshold"] = int(settings["threshold"])
    except (TypeError, ValueError) as exc:
        raise SystemExit("Dashboard threshold must be an integer") from exc

    return settings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
    args = parse_args()
    settings = _dashboard_settings(args)
    if args.debug and args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Refusing to run Flask debug mode on a non-loopback host")
    REPORTS_DIR = settings["reports"]
    DASHBOARD_TOKEN = settings["token"]
    DASHBOARD_META.update({
        "model": settings["model"],
        "ollama_url": settings["ollama_url"],
        "threshold": settings["threshold"],
    })

    log.info(f"Dashboard starting — http://{args.host}:{args.port}")
    log.info(f"Reading alerts from: {Path(REPORTS_DIR) / 'alerts_enriched.jsonl'}")

    app.run(host=args.host, port=args.port, debug=args.debug)
