#!/bin/bash
# Запуск StrikeNet Orchestrator
# Вызывайте: ./start.sh [--prod]

set -e
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
  echo "[start] Создаю виртуальное окружение..."
  python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r requirements.txt

# панель-HTML должна лежать в panel/
mkdir -p panel results logs

if [ "$1" = "--prod" ]; then
  echo "[start] Запуск в prod-режиме (127.0.0.1:9000)"
  exec uvicorn app.main:app \
    --host 127.0.0.1 \
    --port 9000 \
    --workers 1 \
    --log-level warning \
    --access-log
else
  echo "[start] Запуск в dev-режиме с автоперезагрузкой (127.0.0.1:9000)"
  exec uvicorn app.main:app \
    --host 127.0.0.1 \
    --port 9000 \
    --reload \
    --reload-dir app
fi
