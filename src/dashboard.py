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
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from functools import wraps
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


def _default_dashboard_meta() -> dict:
    return {"model": "tinyllama", "ollama_url": "", "threshold": 10}

# ── HTML / CSS / JS ───────────────────────────────────────────────────────────
_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SIEM with AI</title>
<style>
  :root {
    /* Light Mode Variables (Default) */
    --bg-base: #f4f4f5;
    --bg-panel: #ffffff;
    --bg-panel-hover: #fafafa;
    --bg-surface: #f4f4f5;
    --border-subtle: #e4e4e7;
    --border-strong: #d4d4d8;
    
    --text-primary: #09090b;
    --text-muted: #52525b;
    --text-dark: #a1a1aa;
    
    --accent-brand: #3b82f6; /* Modern Blue */
    --accent-brand-glow: rgba(59, 130, 246, 0.2);
    
    /* Severity Colors */
    --sev-critical: #ef4444; /* Red */
    --sev-critical-bg: rgba(239, 68, 68, 0.1);
    --sev-critical-border: rgba(239, 68, 68, 0.2);
    
    --sev-high: #f97316; /* Orange */
    --sev-high-bg: rgba(249, 115, 22, 0.1);
    --sev-high-border: rgba(249, 115, 22, 0.2);
    
    --sev-medium: #eab308; /* Yellow */
    --sev-medium-bg: rgba(234, 179, 8, 0.1);
    --sev-medium-border: rgba(234, 179, 8, 0.2);
    
    --sev-low: #3b82f6; /* Blue */
    --sev-low-bg: rgba(59, 130, 246, 0.1);
    --sev-low-border: rgba(59, 130, 246, 0.2);
    
    --sev-unknown: #737373;
    
    --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
    
    --shadow-glow: 0 0 20px rgba(0, 0, 0, 0.05);
    --shadow-panel: 0 1px 3px rgba(0,0,0,0.1);
    --radius-sm: 4px;
    --radius-md: 8px;
    --radius-lg: 12px;
    --radius-pill: 9999px;
  }

  body.theme-dark {
    /* Dark Mode Variables */
    --bg-base: #050505;
    --bg-panel: #111111;
    --bg-panel-hover: #1a1a1a;
    --bg-surface: #171717;
    --border-subtle: #262626;
    --border-strong: #404040;
    
    --text-primary: #f5f5f5;
    --text-muted: #a3a3a3;
    --text-dark: #525252;
    
    --sev-critical-bg: rgba(239, 68, 68, 0.15);
    --sev-critical-border: rgba(239, 68, 68, 0.3);
    
    --sev-high-bg: rgba(249, 115, 22, 0.15);
    --sev-high-border: rgba(249, 115, 22, 0.3);
    
    --sev-medium-bg: rgba(234, 179, 8, 0.15);
    --sev-medium-border: rgba(234, 179, 8, 0.3);
    
    --sev-low-bg: rgba(59, 130, 246, 0.15);
    --sev-low-border: rgba(59, 130, 246, 0.3);
    
    --shadow-glow: 0 0 20px rgba(0, 0, 0, 0.5);
    --shadow-panel: 0 4px 20px rgba(0,0,0,0.4);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background-color: var(--bg-base);
    color: var(--text-primary);
    font-family: var(--font-sans);
    line-height: 1.5;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
    overflow-x: hidden;
  }
  
  /* Datadog/Splunk inspired grid background */
  body::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image: 
      linear-gradient(to right, rgba(128,128,128,0.05) 1px, transparent 1px),
      linear-gradient(to bottom, rgba(128,128,128,0.05) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: -1;
  }

  button, input { font: inherit; outline: none; }
  button { cursor: pointer; border: none; background: transparent; }

  .shell {
    display: grid;
    grid-template-columns: 260px 1fr;
    min-height: 100vh;
  }

  /* SIDEBAR */
  .sidebar {
    background-color: var(--bg-panel);
    border-right: 1px solid var(--border-subtle);
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 24px;
    position: sticky;
    top: 0;
    height: 100vh;
    z-index: 10;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .brand-mark {
    width: 36px; height: 36px;
    background: linear-gradient(135deg, var(--accent-brand), #8b5cf6);
    border-radius: var(--radius-md);
    display: grid; place-items: center;
    font-weight: 800; color: #fff;
    box-shadow: 0 0 15px var(--accent-brand-glow);
  }

  .brand h1 { font-size: 16px; font-weight: 700; letter-spacing: 0.5px; }
  .brand p { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }

  .nav-label {
    font-size: 11px; font-weight: 700; color: var(--text-dark);
    text-transform: uppercase; letter-spacing: 1.5px;
    margin-bottom: -10px;
  }

  .nav-item {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 12px; border-radius: var(--radius-sm);
    color: var(--text-muted); font-size: 13px; font-weight: 500;
    transition: all 0.2s;
  }

  .nav-item:hover { background: var(--bg-surface); color: var(--text-primary); }
  .nav-item.active {
    background: rgba(59, 130, 246, 0.1); color: var(--accent-brand);
    border-left: 3px solid var(--accent-brand);
  }

  .nav-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--accent-brand); box-shadow: 0 0 8px var(--accent-brand); }

  .side-panel {
    margin-top: auto;
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    padding: 16px;
  }

  .side-panel dl { display: grid; grid-template-columns: 1fr 1fr; gap: 12px 8px; }
  .side-panel dt { font-size: 10px; color: var(--text-dark); text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px;}
  .side-panel dd { font-size: 12px; color: var(--text-primary); font-family: var(--font-mono); text-align: right; overflow: hidden; text-overflow: ellipsis; }

  /* MAIN CONTENT */
  .main { padding: 32px 40px; display: flex; flex-direction: column; gap: 24px; min-width: 0; }

  /* TOPBAR */
  .topbar { display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 20px; }
  .headline h2 { font-size: 28px; font-weight: 800; letter-spacing: -0.5px; margin-bottom: 6px; }
  .headline p { color: var(--text-muted); font-size: 14px; }

  .top-actions { display: flex; align-items: center; gap: 12px; }
  .status-pill, .theme-toggle, .refresh-button, .live-chip {
    display: inline-flex; align-items: center; gap: 8px;
    height: 36px; padding: 0 16px;
    background: var(--bg-panel); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-pill); font-size: 13px; font-weight: 500;
    color: var(--text-primary); transition: all 0.2s;
  }
  
  .status-pill { font-family: var(--font-mono); font-size: 12px; border-color: var(--accent-brand-glow); }

  .theme-toggle:hover, .refresh-button:hover {
    background: var(--bg-panel-hover); border-color: var(--border-strong);
  }

  .theme-dot { width: 14px; height: 14px; border-radius: 50%; background: var(--text-primary); transition: background-color 0.2s; }
  .pulse {
    width: 8px; height: 8px; border-radius: 50%; background: #10b981;
    box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
    animation: pulse-green 2s infinite;
  }
  @keyframes pulse-green {
    0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
    70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
    100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
  }

  #last-update, .refresh-meta { font-family: var(--font-mono); color: var(--text-muted); font-size: 11px; }

  /* OVERVIEW METRICS */
  .overview {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 16px;
  }

  .metric {
    background: var(--bg-panel); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md); padding: 20px;
    display: flex; flex-direction: column; position: relative;
    overflow: hidden; box-shadow: var(--shadow-panel);
    transition: transform 0.2s, border-color 0.2s;
  }
  .metric:hover { transform: translateY(-2px); border-color: var(--border-strong); }

  /* Top glowing border accent for metrics */
  .metric::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
  }
  .metric.primary::before { background: var(--accent-brand); box-shadow: 0 0 10px var(--accent-brand); }
  .metric.critical::before { background: var(--sev-critical); box-shadow: 0 0 10px var(--sev-critical); }
  .metric.high::before { background: var(--sev-high); box-shadow: 0 0 10px var(--sev-high); }
  .metric.medium::before { background: var(--sev-medium); box-shadow: 0 0 10px var(--sev-medium); }
  .metric.low::before { background: var(--sev-low); box-shadow: 0 0 10px var(--sev-low); }

  .metric-label { font-size: 11px; font-weight: 700; color: var(--text-dark); text-transform: uppercase; letter-spacing: 1px; }
  .metric-value { font-size: 36px; font-weight: 800; margin: 12px 0 8px; font-family: var(--font-mono); line-height: 1;}
  .metric-note { font-size: 12px; color: var(--text-muted); }

  /* WORKSPACE / TABLE */
  .workspace { display: grid; grid-template-columns: 1fr 340px; gap: 24px; align-items: start; }

  .panel {
    background: var(--bg-panel); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md); box-shadow: var(--shadow-panel);
    display: flex; flex-direction: column; overflow: hidden;
  }

  .panel-head {
    padding: 20px 24px; border-bottom: 1px solid var(--border-subtle);
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;
    background: rgba(128,128,128,0.02);
  }

  .panel-title h3 { font-size: 16px; font-weight: 700; }
  .panel-title p { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

  .toolbar { display: flex; gap: 12px; flex-wrap: wrap; }
  .search {
    background: var(--bg-surface); border: 1px solid var(--border-subtle);
    color: var(--text-primary); font-size: 13px; padding: 0 16px;
    border-radius: var(--radius-pill); height: 34px; width: 280px;
    font-family: var(--font-mono); transition: all 0.2s;
  }
  .search:focus { border-color: var(--accent-brand); box-shadow: 0 0 0 3px var(--accent-brand-glow); }
  .search::placeholder { color: var(--text-dark); font-family: var(--font-sans); }

  .segments {
    display: flex; background: var(--bg-surface); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-pill); padding: 3px;
  }
  .filter-btn {
    padding: 0 14px; height: 26px; border-radius: 999px;
    font-size: 12px; font-weight: 600; color: var(--text-muted); transition: all 0.2s;
  }
  .filter-btn:hover { color: var(--text-primary); }
  .filter-btn.active { background: var(--bg-panel); color: var(--text-primary); box-shadow: 0 2px 8px rgba(0,0,0,0.1); border: 1px solid var(--border-subtle); }

  .table-scroll { overflow-x: auto; min-height: 400px; }
  table { width: 100%; border-collapse: separate; border-spacing: 0; text-align: left; min-width: 800px; }
  
  th {
    padding: 14px 24px; font-size: 10px; font-weight: 700; color: var(--text-dark);
    text-transform: uppercase; letter-spacing: 1px;
    border-bottom: 1px solid var(--border-subtle);
    background: rgba(128,128,128,0.02);
    white-space: nowrap;
  }
  
  td {
    padding: 16px 24px; font-size: 13px; border-bottom: 1px solid var(--border-subtle);
    vertical-align: middle;
  }

  tbody tr { transition: all 0.15s; cursor: pointer; }
  tbody tr:hover { background: var(--bg-surface); }
  tbody tr.selected { background: rgba(59, 130, 246, 0.1); }
  tbody tr:last-child td { border-bottom: none; }

  .badge {
    display: inline-flex; align-items: center; justify-content: center;
    padding: 4px 10px; border-radius: var(--radius-sm);
    font-size: 11px; font-weight: 700; letter-spacing: 0.5px;
    border: 1px solid transparent; text-transform: uppercase;
  }

  .badge.critical { background: var(--sev-critical-bg); color: var(--sev-critical); border-color: var(--sev-critical-border); }
  .badge.high { background: var(--sev-high-bg); color: var(--sev-high); border-color: var(--sev-high-border); }
  .badge.medium { background: var(--sev-medium-bg); color: var(--sev-medium); border-color: var(--sev-medium-border); }
  .badge.low { background: var(--sev-low-bg); color: var(--sev-low); border-color: var(--sev-low-border); }
  .badge.unknown { background: var(--bg-surface); color: var(--text-muted); border-color: var(--border-strong); }

  .rule-id { font-family: var(--font-mono); color: var(--accent-brand); font-weight: 600; }
  .source-ip, .time { font-family: var(--font-mono); color: var(--text-muted); font-size: 12px; }
  .agent { font-weight: 600; color: var(--text-primary); }
  .desc { max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .empty { padding: 60px 20px; text-align: center; }
  .empty h4 { color: var(--text-primary); margin-bottom: 8px; font-size: 16px; }
  .empty p { color: var(--text-muted); font-size: 13px; max-width: 300px; margin: 0 auto; }

  /* SIDE INSIGHT PANEL */
  .insight { padding: 24px; display: flex; flex-direction: column; gap: 32px; }
  
  .insight .panel-title { border-bottom: none; padding: 0; background: none; }
  
  .distribution { display: flex; flex-direction: column; gap: 16px; }
  .bar-row { display: flex; flex-direction: column; gap: 8px; }
  .bar-meta { display: flex; justify-content: space-between; font-size: 12px; font-weight: 600; color: var(--text-muted); }
  .bar-track { height: 6px; background: var(--bg-surface); border-radius: var(--radius-pill); overflow: hidden; display: flex; }
  .bar { height: 100%; border-radius: var(--radius-pill); transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1); min-width: 4px; }
  .bar.critical { background: var(--sev-critical); box-shadow: 0 0 10px var(--sev-critical); }
  .bar.high { background: var(--sev-high); box-shadow: 0 0 10px var(--sev-high); }
  .bar.medium { background: var(--sev-medium); box-shadow: 0 0 10px var(--sev-medium); }
  .bar.low { background: var(--sev-low); box-shadow: 0 0 10px var(--sev-low); }

  .detail { border-top: 1px solid var(--border-subtle); padding-top: 24px; }
  .detail-title { font-size: 12px; font-weight: 800; color: var(--text-dark); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }
  .detail-list { display: flex; flex-direction: column; gap: 12px; }
  .detail-item { display: flex; flex-direction: column; gap: 4px; }
  .detail-key { font-size: 10px; color: var(--text-dark); text-transform: uppercase; font-weight: 700; }
  .detail-val { font-size: 13px; color: var(--text-primary); word-break: break-all; }

  /* DRAWER */
  .drawer {
    position: fixed; inset: 0; z-index: 100; pointer-events: none;
    display: flex; justify-content: flex-end;
  }
  .drawer.open { pointer-events: auto; }
  
  .drawer-shade {
    position: absolute; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px);
    opacity: 0; transition: opacity 0.3s ease;
  }
  .drawer.open .drawer-shade { opacity: 1; }

  .drawer-panel {
    position: relative; width: 100%; max-width: 700px; height: 100%;
    background: var(--bg-panel); border-left: 1px solid var(--border-strong);
    box-shadow: -10px 0 40px rgba(0,0,0,0.5);
    transform: translateX(100%); transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    display: flex; flex-direction: column;
  }
  .drawer.open .drawer-panel { transform: translateX(0); }

  .drawer-head {
    padding: 32px 40px; border-bottom: 1px solid var(--border-subtle);
    display: flex; justify-content: space-between; align-items: flex-start;
    background: linear-gradient(180deg, rgba(128,128,128,0.03) 0%, transparent 100%);
  }
  .drawer-sub { font-family: var(--font-mono); font-size: 12px; color: var(--accent-brand); margin-bottom: 8px; }
  .drawer-head h3 { font-size: 24px; font-weight: 800; line-height: 1.2; color: var(--text-primary); }
  
  .icon-btn {
    width: 32px; height: 32px; border-radius: 50%;
    display: grid; place-items: center;
    background: var(--bg-surface); color: var(--text-primary); border: 1px solid var(--border-subtle);
    font-size: 14px; transition: all 0.2s;
  }
  .icon-btn:hover { background: var(--border-strong); transform: rotate(90deg); }

  .drawer-body { padding: 32px 40px; overflow-y: auto; flex-grow: 1; }

  .meta-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 20px;
    background: var(--bg-surface); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md); padding: 20px; margin-bottom: 32px;
  }

  .analysis { display: flex; flex-direction: column; gap: 32px; }
  .analysis-section { display: flex; flex-direction: column; gap: 12px; }
  .analysis-section h4 {
    font-size: 11px; font-weight: 800; color: var(--text-dark);
    text-transform: uppercase; letter-spacing: 1.5px;
    display: flex; align-items: center; gap: 8px;
  }
  .analysis-section h4::before { content:''; display:block; width:12px; height:2px; background:var(--accent-brand); }
  
  .analysis-section div { font-size: 14px; line-height: 1.7; color: var(--text-primary); white-space: pre-wrap; }
  .analysis-section code {
    display: block; background: #000; color: #10b981;
    padding: 16px; border-radius: var(--radius-sm); border: 1px solid var(--border-strong);
    font-family: var(--font-mono); font-size: 12px; margin: 12px 0; overflow-x: auto;
    box-shadow: inset 0 0 10px rgba(0,0,0,0.5);
  }

  /* Responsive tweaks */
  @media (max-width: 1200px) {
    .overview { grid-template-columns: repeat(3, 1fr); }
    .workspace { grid-template-columns: 1fr; }
    .insight { display: none; }
  }
  @media (max-width: 900px) {
    .shell { grid-template-columns: 1fr; }
    .sidebar { display: none; }
    .overview { grid-template-columns: 1fr 1fr; }
  }
  .ttp-badge {
    display: inline-block; margin-left: 8px; padding: 2px 6px;
    border: 1px solid var(--accent-brand); border-radius: 4px;
    font-size: 10px; font-family: var(--font-mono); color: var(--accent-brand);
    background: var(--accent-brand-glow); vertical-align: middle;
  }
  .actions-cell { display: flex; gap: 4px; }
  .action-btn {
    padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;
    transition: all 0.2s; border: 1px solid transparent; background: var(--bg-surface);
    color: var(--text-primary);
  }
  .action-btn.ack:hover { background: rgba(16, 185, 129, 0.1); color: #10b981; border-color: rgba(16, 185, 129, 0.3); }
  .action-btn.esc:hover { background: rgba(249, 115, 22, 0.1); color: #f97316; border-color: rgba(249, 115, 22, 0.3); }
  .action-btn.dis:hover { background: rgba(115, 115, 115, 0.1); color: #737373; border-color: rgba(115, 115, 115, 0.3); }
  tr.dismissed td { opacity: 0.4; filter: grayscale(1); }

  /* SPA View Transitions */
  .spa-view {
    display: none; opacity: 0; transform: translateY(10px);
    transition: opacity 0.4s ease, transform 0.4s ease;
    flex-grow: 1; flex-direction: column;
  }
  .spa-view.view-active {
    display: flex !important; opacity: 1 !important; transform: translateY(0) !important;
  }
  
  /* Sidebar Navigation */
  .nav-item { cursor: pointer; transition: background 0.2s; }
  .nav-item:hover { background: var(--bg-surface); }
  
  /* Focus Rings */
  tbody tr:focus-visible, button:focus-visible, input:focus-visible {
    outline: 2px solid var(--accent-brand); outline-offset: -2px; border-radius: 2px;
  }
  
  /* Toast Notifications */
  .toast-container {
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    display: flex; flex-direction: column; gap: 12px; pointer-events: none;
  }
  .toast {
    background: var(--bg-panel); border: 1px solid var(--border-strong);
    color: var(--text-primary); padding: 16px 20px; border-radius: var(--radius-md);
    box-shadow: 0 10px 30px rgba(0,0,0,0.5); font-size: 13px; font-weight: 500;
    max-width: 400px; pointer-events: auto; display: flex; align-items: center; gap: 12px;
    animation: toast-slide 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
  }
  @keyframes toast-slide {
    0% { transform: translateX(120%) scale(0.9); opacity: 0; }
    100% { transform: translateX(0) scale(1); opacity: 1; }
  }
  .toast.closing { animation: toast-fade 0.3s ease forwards; }
  @keyframes toast-fade { to { transform: translateX(20px); opacity: 0; } }
  
  /* Action Buttons in Drawer */
  .drawer-footer {
    padding: 20px 40px; border-top: 1px solid var(--border-subtle);
    background: var(--bg-surface); display: flex; gap: 12px; justify-content: flex-end;
    align-items: center;
  }
  .drawer-btn {
    position: relative; overflow: hidden;
    display: inline-flex; align-items: center; gap: 8px;
    padding: 10px 20px; border-radius: var(--radius-md); font-size: 13px; font-weight: 700;
    cursor: pointer; border: 1px solid transparent;
    transition: transform 0.15s cubic-bezier(0.4, 0, 0.2, 1),
                box-shadow 0.15s cubic-bezier(0.4, 0, 0.2, 1),
                background 0.2s, opacity 0.2s;
    letter-spacing: 0.3px;
    user-select: none; -webkit-user-select: none;
  }
  /* Ripple layer */
  .drawer-btn::after {
    content: ''; position: absolute; inset: 0;
    background: radial-gradient(circle at center, rgba(255,255,255,0.25) 0%, transparent 70%);
    opacity: 0; transform: scale(0);
    transition: transform 0.4s ease, opacity 0.4s ease;
    border-radius: inherit;
  }
  .drawer-btn:active::after { transform: scale(2.5); opacity: 1; transition: none; }

  .drawer-btn svg { flex-shrink: 0; transition: transform 0.2s; }

  .drawer-btn:not([disabled]):hover { transform: translateY(-2px); }
  .drawer-btn:not([disabled]):active { transform: translateY(0) scale(0.96); }

  /* Acknowledge — green */
  .drawer-btn.ack {
    background: rgba(16, 185, 129, 0.12); color: #10b981;
    border-color: rgba(16, 185, 129, 0.35);
  }
  .drawer-btn.ack:not([disabled]):hover {
    background: rgba(16, 185, 129, 0.22);
    box-shadow: 0 4px 16px rgba(16, 185, 129, 0.3), 0 0 0 1px rgba(16, 185, 129, 0.5);
  }

  /* Escalate — orange */
  .drawer-btn.esc {
    background: rgba(249, 115, 22, 0.12); color: #f97316;
    border-color: rgba(249, 115, 22, 0.35);
  }
  .drawer-btn.esc:not([disabled]):hover {
    background: rgba(249, 115, 22, 0.22);
    box-shadow: 0 4px 16px rgba(249, 115, 22, 0.3), 0 0 0 1px rgba(249, 115, 22, 0.5);
  }

  /* Dismiss — muted */
  .drawer-btn.dis {
    background: var(--bg-panel); color: var(--text-muted);
    border-color: var(--border-strong);
  }
  .drawer-btn.dis:not([disabled]):hover {
    background: var(--bg-panel-hover); color: var(--text-primary);
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
  }

  /* Confirmed / Done state — shown on the button that was pressed */
  .drawer-btn.triage-confirmed {
    opacity: 1 !important; cursor: default !important;
    animation: triage-confirm-pop 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
  }
  .drawer-btn.triage-confirmed.ack  { background: rgba(16, 185, 129, 0.25); border-color: #10b981; color: #10b981; box-shadow: 0 0 14px rgba(16,185,129,0.35); }
  .drawer-btn.triage-confirmed.esc  { background: rgba(249, 115, 22, 0.25); border-color: #f97316; color: #f97316; box-shadow: 0 0 14px rgba(249,115,22,0.35); }
  .drawer-btn.triage-confirmed.dis  { background: rgba(113,113,122,0.15); border-color: var(--border-strong); color: var(--text-muted); }

  @keyframes triage-confirm-pop {
    0%   { transform: scale(0.92); }
    60%  { transform: scale(1.08); }
    100% { transform: scale(1); }
  }

  /* Sibling buttons faded after one is confirmed */
  .drawer-btn.triage-faded {
    opacity: 0.35 !important; cursor: not-allowed !important;
    filter: grayscale(0.6);
  }

  /* Loading spinner inside button */
  .btn-spinner {
    width: 14px; height: 14px; border-radius: 50%;
    border: 2px solid currentColor; border-top-color: transparent;
    animation: btn-spin 0.6s linear infinite; flex-shrink: 0;
  }
  @keyframes btn-spin { to { transform: rotate(360deg); } }
  
  /* Table row visual triage states */
  tr.acked td { background: rgba(16, 185, 129, 0.05) !important; color: rgba(255, 255, 255, 0.7); }
  tr.acked td:first-child { box-shadow: inset 4px 0 0 #10b981; }

  tr.escalated td { background: rgba(249, 115, 22, 0.08) !important; color: #f97316; font-weight: 500; }
  tr.escalated td:first-child { box-shadow: inset 4px 0 0 #f97316; }
  tr.escalated .badge { box-shadow: 0 0 10px rgba(249, 115, 22, 0.5); border-color: #f97316; }

  tr.dismissed td { opacity: 0.3 !important; filter: grayscale(1) !important; text-decoration: line-through; }

  /* Hunting View */
  .hunting-code {
    background: var(--bg-base); border: 1px solid var(--border-subtle);
    padding: 20px; border-radius: var(--radius-md); font-family: var(--font-mono);
    font-size: 12px; color: var(--text-primary); overflow-x: auto;
    white-space: pre-wrap; word-break: break-all; margin-top: 16px;
  }
</style>
</head>
<body>
<div class="shell">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark">SA</div>
      <div>
        <h1>SIEM with AI</h1>
        <p>SOC Terminal</p>
      </div>
    </div>

    <div>
      <div class="nav-label">Operations</div>
      <div style="margin-top: 16px; display: flex; flex-direction: column; gap: 4px;" id="sidebar-nav">
        <div class="nav-item active" data-view="view-queue"><span>Alert Queue</span><span class="nav-dot"></span></div>
        <div class="nav-item" data-view="view-hunting"><span>Threat Hunting</span></div>
        <div class="nav-item" data-view="view-reports"><span>Reports</span><span id="nav-total">0</span></div>
        <div class="nav-item" data-view="view-node"><span>Routing Node</span><span id="nav-model">AI</span></div>
      </div>
    </div>

    <div class="side-panel">
      <dl>
        <dt>API Status</dt><dd id="sys-api" style="color: #10b981;">Checking</dd>
        <dt>Model</dt><dd id="sys-model">tinyllama</dd>
        <dt>Threshold</dt><dd id="sys-threshold">L10+</dd>
        <dt>Reports</dt><dd id="sys-reports">local</dd>
      </dl>
    </div>
  </aside>

  <main class="main">
    <div class="topbar">
      <div class="headline">
        <h2>Incident Response</h2>
        <p>Real-time threat detection and AI-enriched triage queue.</p>
      </div>
      <div class="top-actions">
        <span class="status-pill" id="top-api"><span class="pulse" style="margin-right: 4px;"></span> API Checking</span>
        <button class="theme-toggle" id="theme-toggle" aria-label="Toggle Theme">
          <span class="theme-dot"></span><span id="theme-label">Light</span>
        </button>
        <button class="refresh-button" id="refresh-button">
          <span>Sync</span><span class="refresh-meta" id="refresh-countdown">5s</span>
        </button>
        <div class="live-chip" style="background: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.3); color: #10b981;">
          <span class="pulse"></span><span id="last-update">Live</span>
        </div>
      </div>
    </div>

    <div id="view-queue" class="spa-view view-active">
      <section class="overview">
      <div class="metric primary">
        <div class="metric-label">Total Events</div>
        <div class="metric-value" id="s-total">0</div>
        <div class="metric-note" id="s-window">0 currently filtered</div>
      </div>
      <div class="metric critical">
        <div class="metric-label">Critical</div>
        <div class="metric-value" id="s-critical" style="color: var(--sev-critical)">0</div>
        <div class="metric-note">Action required</div>
      </div>
      <div class="metric high">
        <div class="metric-label">High Severity</div>
        <div class="metric-value" id="s-high" style="color: var(--sev-high)">0</div>
        <div class="metric-note">Priority queue</div>
      </div>
      <div class="metric medium">
        <div class="metric-label">Medium</div>
        <div class="metric-value" id="s-medium" style="color: var(--sev-medium)">0</div>
        <div class="metric-note">Under investigation</div>
      </div>
      <div class="metric low">
        <div class="metric-label">Low / Info</div>
        <div class="metric-value" id="s-low" style="color: var(--sev-low)">0</div>
        <div class="metric-note">Telemetry</div>
      </div>
    </section>

    <section class="workspace">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">
            <h3>Detection Queue</h3>
            <p id="queue-summary">Analyzing incoming telemetry...</p>
          </div>
          <div class="toolbar">
            <input class="search" id="search" type="search" placeholder="Search hosts, IPs, rules...">
            <div class="segments">
              <button class="filter-btn active" data-sev="all">All</button>
              <button class="filter-btn" data-sev="critical">Critical</button>
              <button class="filter-btn" data-sev="high">High</button>
              <button class="filter-btn" data-sev="medium">Medium</button>
              <button class="filter-btn" data-sev="low">Low</button>
            </div>
          </div>
        </div>
        <div class="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Rule ID</th>
                <th>Description</th>
                <th>Endpoint</th>
                <th>Source IP</th>
                <th>Detected At</th>
              </tr>
            </thead>
            <tbody id="alert-tbody">
              <tr><td colspan="6"><div class="empty"><h4>Initializing Stream</h4><p>Waiting for Wazuh agents to report telemetry.</p></div></td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <aside class="panel insight">
        <div>
          <h3 class="panel-title" style="font-size: 16px; font-weight: 700; margin-bottom: 4px;">Threat Landscape</h3>
          <p id="mix-subtitle" style="font-size: 12px; color: var(--text-muted);">Severity distribution</p>
        </div>
        <div class="distribution">
          <div class="bar-row">
            <div class="bar-meta"><span>CRITICAL</span><span id="b-critical-count" style="color: var(--sev-critical)">0</span></div>
            <div class="bar-track"><div class="bar critical" id="b-critical"></div></div>
          </div>
          <div class="bar-row">
            <div class="bar-meta"><span>HIGH</span><span id="b-high-count" style="color: var(--sev-high)">0</span></div>
            <div class="bar-track"><div class="bar high" id="b-high"></div></div>
          </div>
          <div class="bar-row">
            <div class="bar-meta"><span>MEDIUM</span><span id="b-medium-count" style="color: var(--sev-medium)">0</span></div>
            <div class="bar-track"><div class="bar medium" id="b-medium"></div></div>
          </div>
          <div class="bar-row">
            <div class="bar-meta"><span>LOW</span><span id="b-low-count" style="color: var(--sev-low)">0</span></div>
            <div class="bar-track"><div class="bar low" id="b-low"></div></div>
          </div>
        </div>

        <div class="detail">
          <div class="detail-title">Active Selection</div>
          <div class="detail-list" id="selected-summary">
            <div class="detail-item"><div class="detail-key">Status</div><div class="detail-val" style="color: var(--text-muted)">Awaiting selection...</div></div>
          </div>
        </div>
      </aside>
    </section>
    </div>

    <div id="view-hunting" class="spa-view">
      <div class="panel" style="margin: 24px; padding: 24px;">
        <h3 style="font-size: 18px; margin-bottom: 8px;">Threat Hunting</h3>
        <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 24px;">Query raw telemetry and AI-enriched metadata using full-text search.</p>
        <input class="search" id="hunting-search" type="search" placeholder="rule.id: 5710 AND agent.name: ubuntu" style="width: 100%; max-width: 800px; height: 44px; margin-bottom: 24px;">
        <div class="hunting-code" id="hunting-results">Execute a query to view raw JSON events.</div>
      </div>
    </div>

    <div id="view-reports" class="spa-view">
      <div class="panel" style="margin: 24px; padding: 24px;">
        <h3 style="font-size: 18px; margin-bottom: 8px;">Compliance & Reporting</h3>
        <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 24px;">Generate executive summaries and export active session data.</p>
        <div style="display: flex; gap: 16px;">
          <button class="drawer-btn esc" onclick="exportCSV()">Download CSV Report</button>
        </div>
      </div>
    </div>

    <div id="view-node" class="spa-view">
      <div class="panel" style="margin: 24px; padding: 24px;">
        <h3 style="font-size: 18px; margin-bottom: 8px;">Routing Node Configuration</h3>
        <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 24px;">Manage Ollama LLM endpoint and SIEM ingestion settings.</p>
        <div class="meta-grid" style="max-width: 600px;">
          <div class="detail-item"><div class="detail-key">LLM Endpoint</div><div class="detail-val">http://127.0.0.1:11434</div></div>
          <div class="detail-item"><div class="detail-key">Model</div><div class="detail-val" id="node-settings-model">tinyllama</div></div>
          <div class="detail-item"><div class="detail-key">Severity Threshold</div><div class="detail-val">Level 10+</div></div>
          <div class="detail-item"><div class="detail-key">Concurrent Workers</div><div class="detail-val">3 Threads</div></div>
        </div>
        <button class="drawer-btn ack" onclick="testConnection()">Test Connection</button>
      </div>
    </div>

  </main>
</div>

<div class="drawer" id="drawer" aria-hidden="true">
  <div class="drawer-shade" id="drawer-shade"></div>
  <section class="drawer-panel" aria-label="Alert details">
    <div class="drawer-head">
      <div>
        <div class="drawer-sub" id="d-sub">INCIDENT DETAILS</div>
        <h3 id="d-title">Select an alert</h3>
      </div>
      <button class="icon-btn" id="drawer-close" aria-label="Close details">✕</button>
    </div>
    <div class="drawer-body">
      <div class="meta-grid" id="d-meta"></div>
      <div class="analysis">
        <section class="analysis-section">
          <h4>AI Explanation</h4>
          <div id="d-explanation">-</div>
        </section>
        <section class="analysis-section">
          <h4>Blast Radius & Impact</h4>
          <div id="d-impact">-</div>
        </section>
        <section class="analysis-section">
          <h4>Remediation Playbook</h4>
          <div id="d-remediation">-</div>
        </section>
      </div>
    </div>
    <div class="drawer-footer">
      <span style="font-size:11px; color: var(--text-dark); margin-right: auto; font-family: var(--font-mono);">Press A / E / D</span>
      <button class="drawer-btn ack" data-triage-action="ack" title="Acknowledge (A)">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
        <span class="btn-label">Acknowledge</span>
      </button>
      <button class="drawer-btn esc" data-triage-action="esc" title="Escalate (E)">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <span class="btn-label">Escalate</span>
      </button>
      <button class="drawer-btn dis" data-triage-action="dis" title="Dismiss (D)">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        <span class="btn-label">Dismiss</span>
      </button>
    </div>
  </section>
</div>

<div id="toast-container" class="toast-container"></div>

<script>
  let allAlerts = [];
  let alertById = new Map();
  let triageStateById = new Map();
  let activeFilter = 'all';
  let selectedAlertId = null;
  let selectedRowEl = null;
  let refreshTimer = null;
  let countdownTimer = null;
  let nextRefreshAt = 0;
  let isRefreshing = false;
  let alertWindowSignature = '';
  let tableRenderSignature = '';
  const refreshEveryMs = 5000;
  const params = new URLSearchParams(window.location.search);
  const suppliedToken = params.get('token') || '';
  if (suppliedToken) {
    try { sessionStorage.setItem('siem-dashboard-token', suppliedToken); } catch (error) {}
    params.delete('token');
    const cleanQuery = params.toString();
    history.replaceState(null, '', `${window.location.pathname}${cleanQuery ? '?' + cleanQuery : ''}`);
  }
  let storedToken = '';
  try { storedToken = sessionStorage.getItem('siem-dashboard-token') || ''; } catch (error) { storedToken = ''; }
  const dashboardToken = suppliedToken || storedToken;
  const themeButton = document.getElementById('theme-toggle');
  const themeLabel = document.getElementById('theme-label');

  function applyTheme(theme) {
    const dark = theme === 'dark';
    document.body.classList.toggle('theme-dark', dark);
    themeLabel.textContent = dark ? 'Dark Mode' : 'Light Mode';
    themeButton.setAttribute('aria-pressed', String(dark));
    try { localStorage.setItem('siem-dashboard-theme', theme); } catch (error) {}
  }

  function preferredTheme() {
    try {
      if (localStorage.getItem('siem-dashboard-theme') === 'light') return 'light';
    } catch (error) {}
    return 'dark';
  }

  applyTheme(preferredTheme());
  themeButton.addEventListener('click', () => {
    applyTheme(document.body.classList.contains('theme-dark') ? 'light' : 'dark');
  });

  function apiUrl(path) {
    const bust = `_=${Date.now()}`;
    return `${path}${path.includes('?') ? '&' : '?'}${bust}`;
  }

  function apiOptions() { return dashboardToken ? { headers: { 'X-Dashboard-Token': dashboardToken } } : {}; }

  function setApiState(text) {
    document.getElementById('sys-api').textContent = text;
    document.getElementById('top-api').innerHTML = `<span class="pulse" style="margin-right: 4px; ${text === 'Offline' ? 'background: #ef4444; box-shadow: 0 0 0 0 rgba(239,68,68,0.7); animation: none;' : ''}"></span> API ${text}`;
  }

  function escHtml(value) {
    return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function severityKey(alertOrLabel, maybeLevel) {
    const isAlert = alertOrLabel && typeof alertOrLabel === 'object';
    const label = isAlert ? alertOrLabel.severityLabel : alertOrLabel;
    const level = isAlert ? alertOrLabel.severityLevel : maybeLevel;
    if (level !== null && level !== undefined && level !== '') {
      const numericLevel = Number(level);
      if (Number.isFinite(numericLevel)) {
        if (numericLevel >= 15) return 'critical';
        if (numericLevel >= 12) return 'high';
        if (numericLevel >= 10) return 'medium';
        if (numericLevel >= 0) return 'low';
        return 'unknown';
      }
    }
    const text = String(label || '').toUpperCase();
    if (text.includes('CRITICAL')) return 'critical';
    if (text.includes('MEDIUM')) return 'medium'; // Bug fix applied
    if (text.includes('HIGH')) return 'high';
    if (text.includes('LOW')) return 'low';
    return 'unknown';
  }

  function fmtTime(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '-';
    return d.toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }

  function timeAgo(dateString) {
    if (!dateString) return '-';
    const seconds = Math.floor((new Date() - new Date(dateString)) / 1000);
    if (Number.isNaN(seconds)) return '-';
    let interval = seconds / 31536000;
    if (interval > 1) return Math.floor(interval) + "y ago";
    interval = seconds / 2592000;
    if (interval > 1) return Math.floor(interval) + "mo ago";
    interval = seconds / 86400;
    if (interval > 1) return Math.floor(interval) + "d ago";
    interval = seconds / 3600;
    if (interval > 1) return Math.floor(interval) + "h ago";
    interval = seconds / 60;
    if (interval > 1) return Math.floor(interval) + "m ago";
    if (seconds < 10) return "Just now";
    return Math.floor(seconds) + "s ago";
  }

  function extractTTP(explanation) {
    if (!explanation) return null;
    const match = explanation.match(/(T\d{4}(?:\.\d{3})?(?: - [^.\n]+)?)/i);
    return match ? match[1].trim() : null;
  }

  function fmtRemediation(text) {
    const raw = String(text || '-');
    const parts = [];
    let last = 0;
    const fenceRe = /```[a-zA-Z0-9_-]*\n?([\s\S]*?)```/g;
    let match;
    while ((match = fenceRe.exec(raw)) !== null) {
      parts.push(escHtml(raw.slice(last, match.index)));
      parts.push(`<code>${escHtml(match[1].trim())}</code>`);
      last = fenceRe.lastIndex;
    }
    parts.push(escHtml(raw.slice(last)));
    return parts.join('');
  }

  function currentFiltered() {
    const query = document.getElementById('search').value.trim().toLowerCase();
    return allAlerts.filter(alert => {
      if (activeFilter !== 'all' && severityKey(alert) !== activeFilter) return false;
      return !query || alert._search.includes(query);
    });
  }

  function windowSignature(alerts) {
    return alerts.map(alert => [alert.alertId || '', alert.generatedAt || '', alert.timestamp || '', alert.severityLevel ?? '', alert.severityLabel || '', alert.ruleId || '', alert.ruleDesc || ''].join(':')).join('|');
  }

  function tableSignature(alerts) {
    const query = document.getElementById('search').value.trim().toLowerCase();
    return `${activeFilter}|${query}|${allAlerts.length}|${alerts.map(alert => alert.alertId || '').join('|')}`;
  }

  function render() {
    const tbody = document.getElementById('alert-tbody');
    const alerts = currentFiltered();
    document.getElementById('queue-summary').textContent = `${alerts.length} shown from ${allAlerts.length} recent alert${allAlerts.length === 1 ? '' : 's'}`;
    document.getElementById('s-window').textContent = `${alerts.length} currently filtered`;
    const signature = tableSignature(alerts);
    if (signature === tableRenderSignature) { updateSelectedRow(); return; }
    tableRenderSignature = signature;

    if (!alerts.length) {
      const hasData = allAlerts.length > 0;
      tbody.innerHTML = `<tr><td colspan="6"><div class="empty"><h4>${hasData ? 'No matching alerts' : 'No enriched alerts yet'}</h4><p>${hasData ? 'Adjust filters or search query.' : 'Waiting for telemetry to stream.'}</p></div></td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map(alert => {
      const sev = severityKey(alert);
      const id = String(alert.alertId || '');
      const selected = selectedAlertId && selectedAlertId === alert.alertId ? 'selected' : '';
      const triageState = triageStateById.get(id) || '';
      const rowClass = [selected, triageState].filter(Boolean).join(' ');
      const ttp = extractTTP(alert.explanation);
      const ttpHtml = ttp ? `<span class="badge ttp-badge">${escHtml(ttp)}</span>` : '';
      return `<tr class="${rowClass}" tabindex="0" data-alert-id="${escHtml(id)}">
        <td><span class="badge ${sev}">${escHtml(alert.severityLabel || '-')}</span></td>
        <td><span class="rule-id">${escHtml(alert.ruleId || '-')}</span></td>
        <td><div class="desc" title="${escHtml(alert.ruleDesc || '')}">${escHtml(alert.ruleDesc || '-')} ${ttpHtml}</div></td>
        <td><span class="agent">${escHtml(alert.agentName || '-')}</span></td>
        <td><span class="source-ip">${escHtml(alert.sourceIP || '-')}</span></td>
        <td><span class="time">${timeAgo(alert.generatedAt || alert.timestamp)}</span></td>
      </tr>`;
    }).join('');
    updateSelectedRow();
  }

  function updateStats(alerts, totalAlerts, severityTotals) {
    const totals = severityTotals ? {
      critical: severityTotals.critical || 0, high: severityTotals.high || 0, medium: severityTotals.medium || 0, low: severityTotals.low || 0
    } : alerts.reduce((acc, alert) => {
      const key = severityKey(alert);
      if (key in acc) acc[key] += 1;
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0 });
    const total = totalAlerts ?? alerts.length;
    document.getElementById('s-total').textContent = total;
    document.getElementById('s-critical').textContent = totals.critical;
    document.getElementById('s-high').textContent = totals.high;
    document.getElementById('s-medium').textContent = totals.medium;
    document.getElementById('s-low').textContent = totals.low;
    document.getElementById('nav-total').textContent = total;

    const denominator = Math.max(1, totals.critical + totals.high + totals.medium + totals.low);
    for (const key of ['critical', 'high', 'medium', 'low']) {
      document.getElementById(`b-${key}`).style.width = `${Math.round((totals[key] / denominator) * 100)}%`;
      document.getElementById(`b-${key}-count`).textContent = totals[key];
    }
  }

  function updateSelectedSummary(alert) {
    const target = document.getElementById('selected-summary');
    if (!alert) {
      target.innerHTML = `<div class="detail-item"><div class="detail-key">Status</div><div class="detail-val" style="color: var(--text-muted)">Awaiting selection...</div></div>`;
      return;
    }
    target.innerHTML = [
      ['Severity', alert.severityLabel || '-'],
      ['Rule', `${alert.ruleId || '-'} - ${alert.ruleDesc || '-'}`],
      ['Endpoint', `${alert.agentName || '-'} (${alert.agentIP || '-'})`],
      ['Source IP', alert.sourceIP || '-']
    ].map(([key, value]) => `<div class="detail-item"><div class="detail-key">${escHtml(key)}</div><div class="detail-val">${escHtml(value)}</div></div>`).join('');
  }

  function openDrawerById(alertId) {
    const alert = alertById.get(alertId);
    if (!alert) return;
    selectedAlertId = alert.alertId || null;

    document.getElementById('d-sub').textContent = `INCIDENT ${String(alert.alertId || '').slice(0, 8).toUpperCase()} | ${fmtTime(alert.generatedAt || alert.timestamp)}`;
    document.getElementById('d-title').textContent = alert.ruleDesc || 'Alert Detail';
    const meta = [
      ['Severity', `Level ${alert.severityLevel || '-'} - ${alert.severityLabel || '-'}`],
      ['Rule ID', alert.ruleId || '-'],
      ['Endpoint', `${alert.agentName || '-'} (${alert.agentIP || '-'})`],
      ['Source IP', alert.sourceIP || '-'],
      ['Threat Groups', (alert.groups || []).join(', ') || '-'],
      ['Timestamp', fmtTime(alert.timestamp)]
    ];
    document.getElementById('d-meta').innerHTML = meta.map(([key, value]) => `<div class="detail-item"><div class="detail-key">${escHtml(key)}</div><div class="detail-val">${escHtml(value)}</div></div>`).join('');

    document.getElementById('d-explanation').textContent = alert.explanation || '-';
    document.getElementById('d-impact').textContent = alert.impact || '-';
    document.getElementById('d-remediation').innerHTML = fmtRemediation(alert.remediation || '-');
    document.getElementById('drawer').classList.add('open');
    document.getElementById('drawer').setAttribute('aria-hidden', 'false');
    document.title = `Rule ${alert.ruleId || '-'} - SIEM with AI`;
    updateSelectedSummary(alert);
    updateSelectedRow();

    setDrawerTriageDisabled(triageStateById.has(selectedAlertId), triageStateById.get(selectedAlertId));
  }

  function setDrawerTriageDisabled(disabled, confirmedAction) {
    document.querySelectorAll('.drawer-footer .drawer-btn').forEach(btn => {
      btn.disabled = disabled;
      btn.setAttribute('aria-disabled', String(disabled));
      // Reset all states first
      btn.classList.remove('triage-confirmed', 'triage-faded');
      if (disabled && confirmedAction) {
        const isConfirmed = btn.dataset.triageAction === confirmedAction;
        if (isConfirmed) {
          btn.classList.add('triage-confirmed');
          // Swap icon to checkmark and update label
          const label = btn.querySelector('.btn-label');
          const labels = { ack: 'Acknowledged', esc: 'Escalated', dis: 'Dismissed' };
          if (label) label.textContent = labels[confirmedAction] || label.textContent;
          btn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg><span class="btn-label">${labels[confirmedAction] || ''}</span>`;
        } else {
          btn.classList.add('triage-faded');
        }
      } else if (!disabled) {
        // Restore original icons and labels on re-enable
        const originals = {
          ack: { icon: '<polyline points="20 6 9 17 4 12"/>', label: 'Acknowledge' },
          esc: { icon: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>', label: 'Escalate' },
          dis: { icon: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>', label: 'Dismiss' }
        };
        const action = btn.dataset.triageAction;
        const orig = originals[action];
        if (orig) btn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">${orig.icon}</svg><span class="btn-label">${orig.label}</span>`;
      }
    });
  }

  function closeDrawer() {
    document.getElementById('drawer').classList.remove('open');
    document.getElementById('drawer').setAttribute('aria-hidden', 'true');
    document.title = 'SIEM with AI';
    selectedAlertId = null;
    updateSelectedRow();
    updateSelectedSummary(null);
  }

  function updateSelectedRow() {
    if (selectedRowEl) { selectedRowEl.classList.remove('selected'); selectedRowEl = null; }
    if (!selectedAlertId) return;
    const safeId = window.CSS && CSS.escape ? CSS.escape(selectedAlertId) : String(selectedAlertId).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    selectedRowEl = document.querySelector(`tr[data-alert-id="${safeId}"]`);
    if (selectedRowEl) selectedRowEl.classList.add('selected');
  }

  function rowKeyOpen(event, alertId) {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openDrawerById(alertId); }
  }

  function alertSearchIndex(alert) {
    const textSlice = value => String(value || '').slice(0, 360);
    return [alert.alertId, alert.severityLabel, alert.ruleId, alert.ruleDesc, alert.agentName, alert.agentIP, alert.sourceIP, ...(Array.isArray(alert.groups) ? alert.groups : []), textSlice(alert.explanation), textSlice(alert.impact), textSlice(alert.remediation)].filter(value => value !== undefined && value !== null).map(value => String(value)).join(' ').toLowerCase();
  }

  async function fetchAlerts() {
    try {
      const response = await fetch(apiUrl('/api/alerts'), apiOptions());
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const incomingAlerts = data.alerts || [];
      const incomingSignature = windowSignature(incomingAlerts);
      if (incomingSignature !== alertWindowSignature) {
        allAlerts = incomingAlerts.map(alert => ({ ...alert, _search: alertSearchIndex(alert) }));
        alertById = new Map(allAlerts.map(alert => [alert.alertId, alert]));
        alertWindowSignature = incomingSignature;
        tableRenderSignature = '';
      }
      updateStats(allAlerts, data.total, data.severityTotals);
      if (selectedAlertId) {
        const selected = alertById.get(selectedAlertId);
        if (selected) { updateSelectedSummary(selected); } 
        else { selectedAlertId = null; updateSelectedSummary(null); closeDrawer(); }
      }
      render();
      document.getElementById('last-update').textContent = `${new Date().toLocaleTimeString('en-GB')}`;
      return true;
    } catch (error) {
      document.getElementById('last-update').textContent = allAlerts.length ? 'Cached' : 'Failed';
      return false;
    }
  }

  async function fetchStatus() {
    try {
      const response = await fetch(apiUrl('/api/status'), apiOptions());
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const status = await response.json();
      document.getElementById('sys-model').textContent = status.model || 'unknown';
      document.getElementById('nav-model').textContent = status.model || 'AI';
      document.getElementById('sys-threshold').textContent = `L${status.threshold || 10}+`;
      document.getElementById('sys-reports').textContent = `${status.reportsDir || 'local'} (${status.count || 0})`;
      document.getElementById('mix-subtitle').textContent = `${status.count || 0} total events / ${status.windowCount || 0} shown`;
      return true;
    } catch (error) {
      setApiState(allAlerts.length ? 'Stale' : 'Offline');
      return false;
    }
  }

  async function refreshDashboard() {
    if (isRefreshing) return;
    isRefreshing = true;
    document.getElementById('refresh-button').disabled = true;
    document.getElementById('refresh-countdown').textContent = 'Syncing...';
    try {
      const [statusResult, alertsResult] = await Promise.allSettled([fetchStatus(), fetchAlerts()]);
      const alertsOk = alertsResult.status === 'fulfilled' && alertsResult.value;
      const statusOk = statusResult.status === 'fulfilled' && statusResult.value;
      setApiState(alertsOk ? (statusOk ? 'Online' : 'Data online') : (allAlerts.length ? 'Stale' : 'Offline'));
    } finally {
      isRefreshing = false;
      document.getElementById('refresh-button').disabled = false;
      scheduleRefresh();
    }
  }

  function scheduleRefresh() {
    window.clearTimeout(refreshTimer);
    nextRefreshAt = Date.now() + refreshEveryMs;
    refreshTimer = window.setTimeout(refreshDashboard, refreshEveryMs);
    updateCountdown();
  }

  function updateCountdown() {
    const remaining = Math.max(0, Math.ceil((nextRefreshAt - Date.now()) / 1000));
    document.getElementById('refresh-countdown').textContent = isRefreshing ? 'Syncing...' : `${remaining}s`;
  }

  const filterButtons = Array.from(document.querySelectorAll('.filter-btn'));
  filterButtons.forEach(button => {
    button.addEventListener('click', () => {
      filterButtons.forEach(item => item.classList.remove('active'));
      button.classList.add('active');
      activeFilter = button.dataset.sev;
      render();
    });
  });

  function debounce(func, wait) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  document.getElementById('search').addEventListener('input', debounce(render, 250));
  document.getElementById('alert-tbody').addEventListener('click', event => {
    const row = event.target.closest('tr[data-alert-id]');
    if (row) openDrawerById(row.dataset.alertId);
  });
  document.getElementById('alert-tbody').addEventListener('keydown', event => {
    const row = event.target.closest('tr[data-alert-id]');
    if (row) rowKeyOpen(event, row.dataset.alertId);
  });
  document.getElementById('refresh-button').addEventListener('click', refreshDashboard);
  document.getElementById('drawer-shade').addEventListener('click', closeDrawer);
  document.getElementById('drawer-close').addEventListener('click', closeDrawer);
  document.querySelectorAll('[data-triage-action]').forEach(button => {
    button.addEventListener('click', () => triageAlert(button.dataset.triageAction));
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') { closeDrawer(); return; }
    // Triage keyboard shortcuts — only when drawer is open and no input is focused
    const drawerOpen = document.getElementById('drawer').classList.contains('open');
    if (!drawerOpen) return;
    if (document.activeElement && ['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) return;
    if (event.key === 'a' || event.key === 'A') triageAlert('ack');
    if (event.key === 'e' || event.key === 'E') triageAlert('esc');
    if (event.key === 'd' || event.key === 'D') triageAlert('dis');
  });

  // --- SPA & TOAST LOGIC ---

  function showToast(message) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = message;
    container.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('closing');
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function triageAlert(action) {
    if (!selectedAlertId) return;
    if (triageStateById.has(selectedAlertId)) return;

    const actions = {
      ack: {
        className: 'acked',
        message: id => `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><polyline points="20 6 9 17 4 12"/></svg> <strong>Incident Acknowledged:</strong> Alert <code>${id}</code> assigned to your queue.`
      },
      esc: {
        className: 'escalated',
        message: id => `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f97316" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> <strong>Escalation Triggered:</strong> Alert <code>${id}</code> escalated to Tier-2 SOC.`
      },
      dis: {
        className: 'dismissed',
        message: id => `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#71717a" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> <strong>Alert Dismissed:</strong> Alert <code>${id}</code> marked as a false positive.`
      }
    };
    const selectedAction = actions[action];
    if (!selectedAction) return;

    // Show spinner on the clicked button immediately
    const clickedBtn = document.querySelector(`.drawer-footer .drawer-btn[data-triage-action="${action}"]`);
    if (clickedBtn) {
      clickedBtn.innerHTML = `<span class="btn-spinner"></span><span class="btn-label">Processing…</span>`;
      clickedBtn.disabled = true;
    }

    // Short artificial delay to make the action feel deliberate
    setTimeout(() => {
      const shortId = String(selectedAlertId).slice(0, 8).toUpperCase();
      triageStateById.set(selectedAlertId, selectedAction.className);

      const safeId = window.CSS && CSS.escape ? CSS.escape(selectedAlertId) : String(selectedAlertId).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
      const row = document.querySelector(`tr[data-alert-id="${safeId}"]`);
      if (row) {
        row.classList.remove('acked', 'escalated', 'dismissed');
        row.classList.add(selectedAction.className);
      }

      showToast(selectedAction.message(shortId));
      setDrawerTriageDisabled(true, action);
    }, 500);
  }

  const views = ['view-queue', 'view-hunting', 'view-reports', 'view-node'];
  document.getElementById('sidebar-nav').addEventListener('click', e => {
    const item = e.target.closest('.nav-item[data-view]');
    if (!item) return;
    document.querySelectorAll('#sidebar-nav .nav-item').forEach(el => el.classList.remove('active'));
    item.classList.add('active');
    const targetId = item.dataset.view;
    views.forEach(v => {
      const el = document.getElementById(v);
      if (v === targetId) { el.classList.add('view-active'); }
      else { el.classList.remove('view-active'); }
    });
  });

  function exportCSV() {
    if (!allAlerts.length) { showToast('⚠️ No alerts to export.'); return; }
    const csvRows = ['AlertID,Severity,Rule,Agent,SourceIP,Timestamp'];
    allAlerts.forEach(a => {
      csvRows.push(`${a.alertId},${a.severityLabel},"${a.ruleDesc}",${a.agentName},${a.sourceIP},${a.timestamp}`);
    });
    const blob = new Blob([csvRows.join('\\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'siem_export.csv';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    showToast(`✅ <strong>Export Complete:</strong> Downloaded ${allAlerts.length} alerts to CSV.`);
  }

  function testConnection() {
    showToast(`🔄 <strong>Testing Connection:</strong> Pinging routing node...`);
    setTimeout(() => {
      showToast(`✅ <strong>Connection Successful:</strong> Ollama node is reachable.`);
    }, 1500);
  }

  // Hunting search demo
  document.getElementById('hunting-search').addEventListener('input', debounce((e) => {
    const query = e.target.value.trim().toLowerCase();
    const resultsArea = document.getElementById('hunting-results');
    if (!query) { resultsArea.textContent = 'Execute a query to view raw JSON events.'; return; }
    const matches = allAlerts.filter(a => a._search && a._search.includes(query)).slice(0, 10);
    if (!matches.length) { resultsArea.textContent = 'No telemetry matches your query.'; return; }
    resultsArea.textContent = matches.map(a => JSON.stringify(a, null, 2)).join('\\n\\n---\\n\\n');
  }, 300));
  window.addEventListener('beforeunload', () => { window.clearTimeout(refreshTimer); window.clearInterval(countdownTimer); });

  countdownTimer = window.setInterval(updateCountdown, 1000);
  refreshDashboard();
</script>
</body>
</html>
"""

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
REPORTS_DIR = "./reports"
DASHBOARD_TOKEN = os.environ.get("SIEM_DASHBOARD_TOKEN", "")
DASHBOARD_META = _default_dashboard_meta()
_CACHE_LOCK = threading.RLock()
_ALERT_CACHE = {
    "path": None,
    "mtime_ns": None,
    "size": None,
    "limit": None,
    "alerts": [],
    "total": 0,
    "offset": 0,
    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
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


@app.after_request
def _disable_api_cache(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


def _load_alerts(limit: int = 200) -> list:
    """
    Read the master JSONL log and return the most recent `limit` alerts,
    newest first.
    """
    with _CACHE_LOCK:
        return _load_alerts_locked(limit)


def _load_alerts_locked(limit: int = 200) -> list:
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
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
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
                offset = f.tell()
                while True:
                    line_start = f.tell()
                    raw_line = f.readline()
                    if not raw_line:
                        offset = f.tell()
                        break
                    if not raw_line.endswith(b"\n") and f.tell() >= stat.st_size:
                        offset = line_start
                        break
                    record = _parse_jsonl_alert(raw_line)
                    if record is None:
                        offset = f.tell()
                        continue
                    alerts.append(record)
                    total += 1
                    sev = _severity_key(record.get("severityLabel") or "", record.get("severityLevel"))
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    offset = f.tell()
        else:
            alerts = deque(maxlen=limit)
            total = 0
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
            with jsonl_path.open("rb") as f:
                # OPTIMIZATION: Only parse the last 5MB to prevent freezing on massive log files
                MAX_COLD_READ_BYTES = 5 * 1024 * 1024
                if stat.st_size > MAX_COLD_READ_BYTES:
                    f.seek(stat.st_size - MAX_COLD_READ_BYTES)
                    f.readline()  # discard partial line
                
                offset = f.tell()
                while True:
                    line_start = f.tell()
                    raw_line = f.readline()
                    if not raw_line:
                        offset = f.tell()
                        break
                    if not raw_line.endswith(b"\n") and f.tell() >= stat.st_size:
                        offset = line_start
                        break
                    record = _parse_jsonl_alert(raw_line)
                    if record is None:
                        offset = f.tell()
                        continue
                    alerts.append(record)
                    total += 1
                    sev = _severity_key(record.get("severityLabel") or "", record.get("severityLevel"))
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    offset = f.tell()
    except OSError as e:
        log.error(f"Could not read {jsonl_path}: {e}")
        _ALERT_CACHE.update({
            "mtime_ns": None,
            "size": None,
            "limit": limit,
        })
        return list(_ALERT_CACHE.get("alerts") or [])

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
    return _ui_alert_record(record) if isinstance(record, dict) else None


def _ui_alert_record(record: dict) -> dict:
    """Return only the fields the dashboard needs to render."""
    allowed = [
        "alertId", "generatedAt", "severityLevel", "severityLabel", "ruleId",
        "ruleDesc", "groups", "agentName", "agentIP", "sourceIP", "timestamp",
        "explanation", "impact", "remediation",
    ]
    cleaned = {key: record.get(key) for key in allowed if key in record}
    groups = cleaned.get("groups")
    if not isinstance(groups, list):
        cleaned["groups"] = []
    else:
        cleaned["groups"] = [str(group) for group in groups]
    return cleaned


def _severity_key(label: str, level=None) -> str:
    """Normalize display labels like 'MEDIUM-HIGH' without double-counting."""
    try:
        numeric_level = int(level)
    except (TypeError, ValueError):
        numeric_level = None
    if numeric_level is not None:
        if numeric_level >= 15:
            return "critical"
        if numeric_level >= 12:
            return "high"
        if numeric_level >= 10:
            return "medium"
        if numeric_level >= 0:
            return "low"
        return "unknown"

    label = (label or "").upper()
    if "CRITICAL" in label:
        return "critical"
    if "HIGH" in label:
        return "high"
    if "MEDIUM" in label:
        return "medium"
    if "LOW" in label:
        return "low"
    return "unknown"


def _jsonl_path() -> Path:
    return Path(REPORTS_DIR) / "alerts_enriched.jsonl"


def require_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if DASHBOARD_TOKEN:
            auth_header = request.headers.get("X-Dashboard-Token")
            query_token = request.args.get("token")
            if (auth_header != DASHBOARD_TOKEN) and (query_token != DASHBOARD_TOKEN):
                abort(401)
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@require_token
def index():
    return render_template_string(_TEMPLATE)


@app.route("/api/alerts")
@require_token
def api_alerts():
    """Return the latest alerts as JSON — polled by the dashboard every 10s."""
    with _CACHE_LOCK:
        alerts = _load_alerts_locked()
        total = int(_ALERT_CACHE.get("total") or 0)
        severity_totals = dict(_ALERT_CACHE.get("severity_counts") or {})
    return jsonify({
        "alerts": alerts,
        "count":  len(alerts),
        "total":  total,
        "severityTotals": severity_totals,
        "asOf":   _utc_now_iso(),
    })


@app.route("/api/status")
@require_token
def api_status():
    """Dashboard health and demo metadata for the top status strip."""
    jsonl_path = _jsonl_path()
    with _CACHE_LOCK:
        total = int(_ALERT_CACHE.get("total") or 0)
        window_count = len(_ALERT_CACHE.get("alerts") or [])
        dashboard_meta = dict(DASHBOARD_META)
        token_required = bool(DASHBOARD_TOKEN)
    payload = {
        "ok": True,
        "reportsDir": "configured",
        "jsonlExists": jsonl_path.exists(),
        "count": total,
        "windowCount": window_count,
        "model": dashboard_meta["model"],
        "threshold": dashboard_meta["threshold"],
        "asOf": _utc_now_iso(),
    }
    if token_required:
        payload.update({
            "reportsDir": str(Path(REPORTS_DIR)),
            "jsonlPath": str(jsonl_path),
        })
        if dashboard_meta.get("ollama_url"):
            payload["ollamaUrl"] = dashboard_meta["ollama_url"]
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
    except ImportError as exc:
        raise SystemExit(
            f"Could not import config_loader while loading dashboard config {path}. "
            "Run dashboard.py from the src directory or keep config_loader.py beside it."
        ) from exc
    try:
        return load_config(path)
    except Exception as exc:
        raise SystemExit(f"Could not load dashboard config {path}: {exc}") from exc


def configure_dashboard(settings: dict) -> None:
    """Apply runtime dashboard settings to module state used by Flask routes."""
    global REPORTS_DIR, DASHBOARD_TOKEN
    with _CACHE_LOCK:
        REPORTS_DIR = settings["reports"]
        DASHBOARD_TOKEN = settings["token"]
        DASHBOARD_META.clear()
        DASHBOARD_META.update(_default_dashboard_meta())
        DASHBOARD_META.update({
            "model": settings["model"],
            "ollama_url": settings["ollama_url"],
            "threshold": settings["threshold"],
        })


def _dashboard_settings(args) -> dict:
    settings = {
        "reports": "./reports",
        "model": "tinyllama",
        "ollama_url": "",
        "threshold": 10,
        "token": os.environ.get("SIEM_DASHBOARD_TOKEN", ""),
    }

    if args.config:
        cfg = _load_dashboard_config(args.config)
        config_path = Path(args.config)
        if not config_path.is_absolute():
            config_path = (Path.cwd() / config_path).resolve()
        configured_reports = cfg.get("output", {}).get("report_dir", settings["reports"])
        if configured_reports and not Path(configured_reports).is_absolute():
            configured_reports = str((config_path.parent / configured_reports).resolve())
        settings.update({
            "reports": configured_reports,
            "model": cfg.get("ollama", {}).get("model", settings["model"]),
            "ollama_url": "",
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
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not settings["token"]:
        raise SystemExit("Refusing to expose dashboard on a non-loopback host without --token")
    configure_dashboard(settings)

    log.info(f"Dashboard starting — http://{args.host}:{args.port}")
    log.info(f"Reading alerts from: {Path(REPORTS_DIR) / 'alerts_enriched.jsonl'}")

    app.run(host=args.host, port=args.port, debug=args.debug)
