# Продолжение через адаптер Claude

Ветка обоих репозиториев: `codex/coordination-workflows`.

Актуальный переносимый контекст, решения, состояние Railway-доступа и порядок продолжения находятся в [handoff репозитория Cloud](https://github.com/Lockyard-dev/lockyard-cloud/blob/codex/coordination-workflows/docs/session-handoff-2026-11-07.md).

Проверенный CLI production code — `ebf347ad7d9048fd3b10b6feccd56e671d6673d8`; последующий handoff-коммит меняет только этот документ. Версия `0.0.1` сама по себе не отличает сборки. Новый source build требует собственных artifact hashes.

Пользователь разрешил server rollout Railway, затем проверку одного клиента и переход остальных с сохранением identity/state/keys/receipts. На момент передачи deployment не выполнен: нужен фактически подключённый `RAILWAY_TOKEN` для production environment. Токен вводится через безопасный механизм секретов адаптера, не в чат и не в Git; credential binding исходной среды не переносится автоматически.

Не повторять уже исполненные задания с новыми ID, не сбрасывать `.lockyard`/node state и не генерировать новый workspace key из-за обновления. Не объявлять enterprise readiness: открытые ограничения зафиксированы в Cloud handoff и приёмке. В исходной общей среде дополнительно прочитать `/workspace/LOCKYARD_MEMORY.md` и `/workspace/LOCKYARD_WORK_PLAN.md`; в новом checkout эти файлы могут отсутствовать.
