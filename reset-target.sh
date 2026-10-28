#!/bin/bash
# Сброс состояния целевого приложения между мутирующими этапами.
# Вызывается автоматически из pipeline.py после Strix и перед Shannon.
# Адаптируйте под ваш стенд:

# Пример 1: Docker Compose стенд
# docker compose -f /opt/target-app/compose.yml down -v
# docker compose -f /opt/target-app/compose.yml up -d
# sleep 15

# Пример 2: VM-снапшот
# virsh snapshot-revert target-vm clean-state

# Пример 3: Kubernetes
# kubectl rollout restart deployment/target-app -n staging

echo "[reset-target] Сброс не настроен — переходим без сброса."
