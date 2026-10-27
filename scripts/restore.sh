#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(dirname -- "$script_dir")"
log_dir="$script_dir/logs"
log_file="$log_dir/restore.log"

mkdir -p "$log_dir"

log() {
    printf '[%s] %s: %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" |
        tee -a "$log_file"
}

if [[ $# -ne 1 ]]; then
    log ERROR 'Использование: restore.sh ПУТЬ_К_ДАМПУ'
    exit 1
fi

backup_file="$1"
if [[ ! -s "$backup_file" ]]; then
    log ERROR "Дамп не найден или пуст: $backup_file"
    exit 1
fi

if [[ -z "${DATABASE_URL:-}" && -f "$project_dir/.env" ]]; then
    source "$project_dir/.env"
fi

if [[ -z "${DATABASE_URL:-}" ]]; then
    log ERROR 'DATABASE_URL не задан'
    exit 1
fi

case "$DATABASE_URL" in
    postgres://*|postgresql://*) ;;
    *)
        log ERROR 'DATABASE_URL должен быть PostgreSQL URL'
        exit 1
        ;;
esac

for tool in psql pg_restore; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        log ERROR "Команда $tool не найдена"
        exit 1
    fi
done

if ! pg_restore --list "$backup_file" \
    >/dev/null 2>>"$log_file"; then
    log ERROR "Файл не является читаемым архивом pg_dump: $backup_file"
    exit 1
fi

if ! table_count="$(psql "$DATABASE_URL" -X -A -t \
    -v ON_ERROR_STOP=1 \
    -c "SELECT count(*) FROM pg_catalog.pg_tables
        WHERE schemaname NOT IN ('pg_catalog', 'information_schema');" \
    2>>"$log_file")"; then
    log ERROR "Не удалось проверить целевую БД; подробности: $log_file"
    exit 1
fi

if [[ "$table_count" != '0' ]]; then
    log ERROR 'В целевой БД уже есть пользовательские таблицы'
    exit 1
fi

if pg_restore --exit-on-error --single-transaction \
    --no-owner --no-acl \
    --dbname="$DATABASE_URL" "$backup_file" 2>>"$log_file"; then
    log INFO "БД восстановлена из $backup_file"
else
    log ERROR "Восстановление не удалось; подробности: $log_file"
    exit 1
fi