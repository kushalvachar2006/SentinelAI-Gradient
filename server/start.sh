#!/usr/bin/env bash
# ─── SentinelAI Backend Startup Script ───────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║         SentinelAI — Backend Startup         ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── 1. Node.js service ───────────────────────────────────────────────────────
echo "→ Checking Node.js dependencies..."
if [ ! -d node_modules ]; then
  echo "  Installing Node packages..."
  npm install
fi

echo "→ Starting Node.js service (port 3001)..."
node index.js &
NODE_PID=$!
echo "  Node PID: $NODE_PID"
sleep 2

# ── 2. Python service ────────────────────────────────────────────────────────
echo ""
echo "→ Checking Python AI service..."
cd app

if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
  echo "  ⚠️  Python not found — AI features will use Gemini via Node fallback"
else
  PY_CMD=$(command -v python3 || command -v python)
  echo "  Using: $PY_CMD"

  if [ ! -d venv ]; then
    echo "  Creating virtual environment..."
    $PY_CMD -m venv venv 2>/dev/null || true
  fi

  # Activate if possible
  [ -f venv/bin/activate ] && source venv/bin/activate 2>/dev/null || true

  # Install deps if requirements exist
  if [ -f requirements.txt ]; then
    echo "  Installing Python packages..."
    pip install -r requirements.txt -q 2>/dev/null || pip3 install -r requirements.txt -q 2>/dev/null || echo "  ⚠️  pip install failed — continuing without Python service"
  fi

  if python3 -c "import fastapi, uvicorn" &>/dev/null 2>&1; then
    echo "→ Starting Python AI service (port 8000)..."
    python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
    PYTHON_PID=$!
    echo "  Python PID: $PYTHON_PID"
  else
    echo "  ⚠️  FastAPI/uvicorn not available — chat will use Node-side Gemini fallback"
  fi
fi

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  ✅  SentinelAI Node API: http://localhost:3001  ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "Press Ctrl+C to stop all services."
echo ""

# Wait for Ctrl+C and kill children
trap 'echo ""; echo "Stopping services..."; kill $NODE_PID $PYTHON_PID 2>/dev/null; exit 0' INT TERM
wait