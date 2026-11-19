#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "=========================================================="
echo "🛡️  VAPTProX - Full Stack Security Scanner & Pentest Lab"
echo "=========================================================="

echo "[1/3] Setting up Python Backend..."
cd "$DIR/backend"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt -q
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
echo "Backend running on http://127.0.0.1:8000 (PID: $BACKEND_PID)"

echo "[2/3] Setting up React Vite Frontend..."
cd "$DIR/frontend"
npm install --silent
npm run dev -- --host &
FRONTEND_PID=$!
echo "Frontend running on http://localhost:5173 (PID: $FRONTEND_PID)"

echo "[3/3] Setting up VulnLab Practice Target..."
cd "$DIR/vulnlab"
python3 app.py &
VULNLAB_PID=$!
echo "VulnLab running on http://127.0.0.1:5000 (PID: $VULNLAB_PID)"

echo "=========================================================="
echo "🚀 Everything started successfully!"
echo "   - Web App UI:  http://localhost:5173"
echo "   - API Docs:    http://127.0.0.1:8000/docs"
echo "   - VulnLab:     http://127.0.0.1:5000"
echo "Press Ctrl+C to terminate all services."
echo "=========================================================="

trap "kill $BACKEND_PID $FRONTEND_PID $VULNLAB_PID" EXIT
wait

