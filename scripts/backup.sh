#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(dirname -- "$script_dir")"
dump_dir="$script_dir/dumps"
log_dir="$script_dir/logs"
log_file="$log_dir/backup.log"

mkdir -p "$dump_dir" "$log_dir"

log() {
    printf '[%s] %s: %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" |
        tee -a "$log_file"
}

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

for tool in psql pg_dump mktemp find; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        log ERROR "Команда $tool не найдена"
        exit 1
    fi
done

if ! psql "$DATABASE_URL" -X -qAt \
    -v ON_ERROR_STOP=1 -c 'SELECT 1' >/dev/null 2>>"$log_file"; then
    log ERROR "Не удалось подключиться к БД; подробности: $log_file"
    exit 1
fi

backup_file="$(mktemp \
    "$dump_dir/rumics-$(date '+%Y-%m-%d_%H-%M-%S').XXXXXX.dump")"

if pg_dump -Fc --dbname="$DATABASE_URL" \
    --file="$backup_file" 2>>"$log_file"; then
    log INFO "Дамп создан: $backup_file"
else
    rm -f -- "$backup_file"
    log ERROR "Создать дамп не удалось; подробности: $log_file"
    exit 1
fi

# Удалять только дампы этого скрипта старше семи суток.
find "$dump_dir" -maxdepth 1 -type f \
    -name 'rumics-*.dump' -mmin +10080 -delete