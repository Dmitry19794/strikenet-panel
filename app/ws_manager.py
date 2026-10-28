"""
WebSocket менеджер — два канала:
  /ws/runs     → статусы всех прогонов (broadcast раз в 2 сек)
  /ws/logs/{id} → поток строк лога конкретного прогона
"""
import asyncio
import json
from collections import defaultdict
from fastapi import WebSocket


class WSManager:
    def __init__(self):
        # подключённые клиенты канала runs
        self._run_clients: list[WebSocket] = []
        # подключённые клиенты каналов логов: run_id → [ws, ...]
        self._log_clients: dict[int, list[WebSocket]] = defaultdict(list)
        # буфер логов: run_id → [строки]
        self._log_buffer: dict[int, list[dict]] = defaultdict(list)

    # ── RUNS CHANNEL ──
    async def connect_runs(self, ws: WebSocket):
        await ws.accept()
        self._run_clients.append(ws)

    def disconnect_runs(self, ws: WebSocket):
        self._run_clients = [c for c in self._run_clients if c is not ws]

    async def broadcast_runs(self, payload: dict):
        dead = []
        for ws in self._run_clients:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect_runs(ws)

    # ── LOGS CHANNEL ──
    async def connect_logs(self, ws: WebSocket, run_id: int):
        await ws.accept()
        self._log_clients[run_id].append(ws)
        # отдаём накопленный буфер новому подключению
        for line in self._log_buffer[run_id]:
            try:
                await ws.send_json(line)
            except Exception:
                break

    def disconnect_logs(self, ws: WebSocket, run_id: int):
        self._log_clients[run_id] = [
            c for c in self._log_clients[run_id] if c is not ws
        ]

    async def emit_log(self, run_id: int, line: dict):
        """Вызывается из pipeline.py при каждой новой строке лога."""
        self._log_buffer[run_id].append(line)
        dead = []
        for ws in self._log_clients.get(run_id, []):
            try:
                await ws.send_json(line)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect_logs(ws, run_id)

    def clear_buffer(self, run_id: int):
        self._log_buffer[run_id] = []


ws_manager = WSManager()
