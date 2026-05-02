#!/usr/bin/env bash
# install.sh — installs the SIEM AI Agent as a systemd service on Ubuntu Server.
# Run as root on the machine where Wazuh Manager is already installed.
set -e

AGENT_DIR="/opt/siem-ai-agent"
SERVICE_USER="siem-agent"
PYTHON_BIN=$(which python3)
PYTHON_VERSION_OK=$("$PYTHON_BIN" - <<'PY'
import sys
print("yes" if sys.version_info >= (3, 9) else "no")
PY
)
if [[ "$PYTHON_VERSION_OK" != "yes" ]]; then
  echo "Python 3.9 or newer is required."
  exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/main.py" ]]; then
  SRC_DIR="$SCRIPT_DIR"
  REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [[ -f "$SCRIPT_DIR/src/main.py" ]]; then
  SRC_DIR="$SCRIPT_DIR/src"
  REPO_DIR="$SCRIPT_DIR"
else
  echo "Could not locate project source files relative to $SCRIPT_DIR"
  exit 1
fi

echo "======================================================"
echo "  SIEM AI Agent — Installer"
echo "======================================================"

# 1. Prepare install directory
echo "[1/6] Preparing $AGENT_DIR..."
mkdir -p "$AGENT_DIR/reports" "$AGENT_DIR/logs"

# 2. Create directory and copy files
echo "[2/6] Copying project files..."
cp "$SRC_DIR"/models.py "$SRC_DIR"/ollama_service.py "$SRC_DIR"/middleware.py \
   "$SRC_DIR"/notifier.py "$SRC_DIR"/report_logger.py "$SRC_DIR"/config_loader.py \
   "$SRC_DIR"/main.py "$SRC_DIR"/dashboard.py "$AGENT_DIR/"
cp "$SRC_DIR/config.yaml" "$AGENT_DIR/config.yaml.example"
cp "$REPO_DIR/requirements.txt" "$AGENT_DIR/requirements.txt" 2>/dev/null || true
cp "$REPO_DIR/wazuh-training-set.jsonl" "$AGENT_DIR/wazuh-training-set.jsonl" 2>/dev/null || true
cp "$REPO_DIR/custom-wazuh-model_gguf/Modelfile" "$AGENT_DIR/Modelfile" 2>/dev/null || true

echo "      Creating virtual environment..."
"$PYTHON_BIN" -m venv "$AGENT_DIR/.venv"
"$AGENT_DIR/.venv/bin/python" -m pip install --upgrade pip
if [ -f "$AGENT_DIR/requirements.txt" ]; then
  "$AGENT_DIR/.venv/bin/python" -m pip install -r "$AGENT_DIR/requirements.txt"
else
  "$AGENT_DIR/.venv/bin/python" -m pip install pyyaml flask
fi

# 3. Dedicated system user (least privilege — can't log in interactively)
echo "[3/6] Creating service user '$SERVICE_USER'..."
id "$SERVICE_USER" &>/dev/null \
  || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"

# 4. Permissions — read alerts.json via ossec group
echo "[4/6] Setting permissions..."
usermod -aG ossec "$SERVICE_USER" 2>/dev/null || true
chown -R root:root "$AGENT_DIR"
find "$AGENT_DIR" -type d -exec chmod 755 {} \;
find "$AGENT_DIR" -type f -exec chmod 644 {} \;
chmod +x "$AGENT_DIR/.venv/bin/"* 2>/dev/null || true
chown -R "$SERVICE_USER:$SERVICE_USER" "$AGENT_DIR/reports" "$AGENT_DIR/logs"
chmod 700 "$AGENT_DIR/reports" "$AGENT_DIR/logs"

# 5. Copy config on first install only — don't overwrite an existing one
if [ ! -f "$AGENT_DIR/config.yaml" ]; then
    cp "$AGENT_DIR/config.yaml.example" "$AGENT_DIR/config.yaml"
    echo "  -> EDIT $AGENT_DIR/config.yaml before starting!"
fi
chown root:"$SERVICE_USER" "$AGENT_DIR/config.yaml"
chmod 640 "$AGENT_DIR/config.yaml"

# 6. Systemd service
echo "[5/6] Installing systemd service..."
cat > /etc/systemd/system/siem-ai-agent.service << EOF
[Unit]
Description=SIEM AI Agent — Wazuh + Ollama Alert Enrichment
Documentation=https://github.com/your-repo/siem-ai-agent
After=network.target wazuh-manager.service ollama.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${AGENT_DIR}
ExecStart=${AGENT_DIR}/.venv/bin/python ${AGENT_DIR}/main.py --config ${AGENT_DIR}/config.yaml
Environment=SIEM_AGENT_LOG=${AGENT_DIR}/logs/siem_agent.log
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=siem-ai-agent

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=${AGENT_DIR}/reports ${AGENT_DIR}/logs
ReadOnlyPaths=/var/ossec/logs/alerts

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo "[6/6] Done!"
echo ""
echo "  Next steps:"
echo "  1. Edit   : nano $AGENT_DIR/config.yaml"
echo "  2. Enable : systemctl enable siem-ai-agent"
echo "  3. Start  : systemctl start siem-ai-agent"
echo "  4. Logs   : journalctl -u siem-ai-agent -f"
echo "  5. Check  : python3 $AGENT_DIR/main.py --config $AGENT_DIR/config.yaml --demo-status"
echo "  6. UI     : python3 $AGENT_DIR/dashboard.py --reports $AGENT_DIR/reports"
echo ""
echo "  To use the custom Wazuh model:"
echo "    cd $AGENT_DIR && ollama create wazuh-soc -f Modelfile"
echo "    # then set model: wazuh-soc in config.yaml"
echo ""
echo "  To test with the training set:"
echo "    python3 $AGENT_DIR/main.py --config $AGENT_DIR/config.yaml --batch $AGENT_DIR/wazuh-training-set.jsonl"
