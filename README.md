# Incident Prediction Module for RuSIEM

Прототип внутреннего модуля прогноза инцидентов ИБ для RuSIEM.

Основной режим работы - внутри RuSIEM: модуль получает уже нормализованные
события и контекст системы, обогащает их, анализирует последовательности и
возвращает объяснимый прогноз риска обратно в RuSIEM. REST/webhook/syslog в
этом прототипе оставлены как dev/test-режим для отладки и стендов.

## Быстрый запуск

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8088
```

Проверка REST ingestion:

```powershell
Invoke-RestMethod -Method Post http://localhost:8088/api/v1/events `
  -ContentType "application/json" `
  -Body '{"source":"rusiem","event_type":"auth_failed","src_ip":"203.0.113.10","dst_ip":"10.0.0.5","asset_id":"srv-ad-01","severity":"medium","raw":{"event.id":"4625"}}'
```

## Основные эндпоинты

- `POST /api/v1/rusiem/internal/events` - основной внутренний контракт RuSIEM.
- `POST /api/v1/events` - прием одного события.
- `POST /api/v1/events/normalized` - прием уже нормализованного события из SIEM.
- `POST /api/v1/webhook/rusiem` - webhook-совместимый прием пачки или одного события.
- `GET /api/v1/health` - состояние сервиса.
- `GET /api/v1/predictions/recent` - последние прогнозы из памяти прототипа.

Пример приема уже нормализованного события:

```powershell
Invoke-RestMethod -Method Post http://localhost:8088/api/v1/events/normalized `
  -ContentType "application/json" `
  -Body '{"event_id":"rusiem-evt-1","timestamp":"2026-06-11T10:00:00Z","vendor":"rusiem","event_type":"auth_failed","src_ip":"203.0.113.10","dst_ip":"10.0.0.5","username":"ivanov","asset_id":"srv-ad-01","severity":"high","message":"Failed login","raw":{"event.id":"4625"},"normalized_fields":{"event.category":"authentication","event.outcome":"failure"}}'
```

Пример внутреннего события RuSIEM:

```powershell
Invoke-RestMethod -Method Post http://localhost:8088/api/v1/rusiem/internal/events `
  -ContentType "application/json" `
  -Body '{"event_id":"rusiem-internal-1","event_time":"2026-06-11T10:00:00Z","event_type":"auth_failed","severity":"high","src_ip":"203.0.113.10","dst_ip":"10.0.0.5","username":"petrov","asset_id":"srv-dc-01","fields":{"event.category":"authentication","event.outcome":"failure"},"context":{"tenant_id":"tenant-1","node_id":"node-main","symptom_ids":["symptom-auth-failed"],"asset":{"criticality":"high"}}}'
```

## Документация

- [Техническое задание](docs/technical_requirements.md)
- [Архитектура](docs/architecture.md)
- [Интеграция с RuSIEM](docs/rusiem_integration.md)
