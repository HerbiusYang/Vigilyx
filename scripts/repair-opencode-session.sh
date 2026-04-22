#!/bin/sh

set -eu

DATA_DIR="${OPENCODE_DATA_DIR:-$HOME/.local/share/opencode}"
DB_PATH="${OPENCODE_DB_PATH:-$DATA_DIR/opencode.db}"
LOG_DIR="${OPENCODE_LOG_DIR:-$DATA_DIR/log}"
RUN_BACKUP_PATH=""

usage() {
  cat <<'EOF'
Usage:
  scripts/repair-opencode-session.sh
  scripts/repair-opencode-session.sh <session-id>
  scripts/repair-opencode-session.sh --latest-error
  scripts/repair-opencode-session.sh --all-errors
  scripts/repair-opencode-session.sh --project <session-id|project-id>
  scripts/repair-opencode-session.sh --list-errors
  scripts/repair-opencode-session.sh --dry-run <session-id>
  scripts/repair-opencode-session.sh --dry-run --all-errors
  scripts/repair-opencode-session.sh --dry-run --project <session-id|project-id>

Options:
  <no args>       Repair all sessions with non-text parts in every project that
                  has a logged tool replay error.
  <session-id>    Repair a single session by id.
  --latest-error  Repair only the most recent sessionID from logs that hit the
                  tool_use/tool_result replay error.
  --all-errors    Repair every distinct sessionID from logs that hit the replay
                  error.
  --project       Repair all sessions with non-text parts in the target project.
                  Accepts either a project id or a session id to resolve.
  --list-errors   Print recent corrupted-session candidates from logs.
  --dry-run       Show what would be changed, but do not modify the DB.
  -h, --help      Show this help.

Behavior:
  - Backs up the local opencode SQLite DB once per run
  - Can batch-repair all affected sessions in a project
  - Trims the trailing assistant messages of the latest corrupted turn
  - Removes all non-text parts from each repaired session
  - Deletes now-empty messages in repaired sessions
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

ensure_db() {
  if [ ! -f "$DB_PATH" ]; then
    echo "opencode DB not found: $DB_PATH" >&2
    exit 1
  fi
}

scan_error_sessions() {
  if [ ! -d "$LOG_DIR" ]; then
    echo "opencode log dir not found: $LOG_DIR" >&2
    exit 1
  fi

  awk '
    function extract_session_id(line,    token) {
      if (match(line, /sessionID=[^ ]+/)) {
        token = substr(line, RSTART + 10, RLENGTH - 10)
        return token
      }
      if (match(line, /session\.id=[^ ]+/)) {
        token = substr(line, RSTART + 11, RLENGTH - 11)
        return token
      }
      if (match(line, /session_id=[^ ]+/)) {
        token = substr(line, RSTART + 11, RLENGTH - 11)
        return token
      }
      return ""
    }
    {
      current_sid = extract_session_id($0)
      if (current_sid != "") {
        sid = current_sid
      }
    }
    /tool_use` ids were found without `tool_result` blocks immediately after/ {
      current_sid = extract_session_id($0)
      if (current_sid != "") {
        sid = current_sid
      }
      if (sid != "") {
        tool_id = ""
        if (match($0, /toolu_[A-Za-z0-9]+/)) {
          tool_id = substr($0, RSTART, RLENGTH)
        }
        printf "%s\t%s\t%s\n", FILENAME, sid, tool_id
      }
    }
  ' "$LOG_DIR"/*.log 2>/dev/null
}

list_error_sessions() {
  scan_error_sessions | tail -20
}

latest_error_session() {
  scan_error_sessions | tail -1 | cut -f2
}

all_error_sessions() {
  scan_error_sessions | cut -f2 | awk 'NF && !seen[$0]++'
}

all_error_projects() {
  all_error_sessions | while IFS= read -r session_id; do
    [ -n "$session_id" ] || continue
    project_for_session "$session_id"
  done | awk 'NF && !seen[$0]++'
}

validate_session_id() {
  case "$1" in
    ses_[A-Za-z0-9]*)
      ;;
    *)
      echo "Refusing unexpected session id: $1" >&2
      exit 1
      ;;
  esac
}

validate_project_id() {
  case "$1" in
    global|[A-Za-z0-9_-]*)
      ;;
    *)
      echo "Refusing unexpected project id: $1" >&2
      exit 1
      ;;
  esac
}

backup_db() {
  ts="$(date +%Y%m%d-%H%M%S)"
  backup_path="$DB_PATH.bak.$ts"
  cp "$DB_PATH" "$backup_path"
  echo "$backup_path"
}

ensure_backup() {
  if [ -z "$RUN_BACKUP_PATH" ]; then
    RUN_BACKUP_PATH="$(backup_db)"
  fi
}

session_exists() {
  sqlite3 "$DB_PATH" "select count(*) from session where id = '$1';"
}

project_exists() {
  sqlite3 "$DB_PATH" "select count(*) from session where project_id = '$1';"
}

project_for_session() {
  sqlite3 "$DB_PATH" "select project_id from session where id = '$1' limit 1;"
}

resolve_project_id() {
  target="$1"

  case "$target" in
    ses_*)
      validate_session_id "$target"
      project_id="$(project_for_session "$target")"
      if [ -z "$project_id" ]; then
        echo "No project found for session: $target" >&2
        exit 1
      fi
      ;;
    *)
      validate_project_id "$target"
      project_id="$target"
      ;;
  esac

  if [ "$(project_exists "$project_id")" = "0" ]; then
    echo "Project not found or has no sessions: $project_id" >&2
    exit 1
  fi

  printf "%s\n" "$project_id"
}

sessions_with_non_text_in_project() {
  project_id="$1"

  sqlite3 "$DB_PATH" "
    select id
    from session
    where project_id = '$project_id'
      and exists (
        select 1
        from part
        where part.session_id = session.id
          and json_extract(data, '$.type') <> 'text'
      )
    order by time_updated desc;
  "
}

sessions_from_error_projects() {
  all_error_projects | while IFS= read -r project_id; do
    [ -n "$project_id" ] || continue
    sessions_with_non_text_in_project "$project_id"
  done | awk 'NF && !seen[$0]++'
}

count_session_list() {
  printf "%s\n" "$1" | awk 'NF { count += 1 } END { print count + 0 }'
}

repair_session() {
  session_id="$1"
  dry_run="$2"

  validate_session_id "$session_id"

  if [ "$(session_exists "$session_id")" = "0" ]; then
    echo "Session not found: $session_id" >&2
    exit 1
  fi

  before_parts="$(sqlite3 "$DB_PATH" "select count(*) from part where session_id = '$session_id';")"
  before_non_text="$(sqlite3 "$DB_PATH" "select count(*) from part where session_id = '$session_id' and json_extract(data, '$.type') <> 'text';")"
  before_messages="$(sqlite3 "$DB_PATH" "select count(*) from message where session_id = '$session_id';")"
  last_non_text_time="$(sqlite3 "$DB_PATH" "select coalesce(max(m.time_created), 0) from message m join part p on p.message_id = m.id where m.session_id = '$session_id' and json_extract(p.data, '$.type') <> 'text';")"
  trim_user_time=0
  trim_user_id=""
  trailing_assistant_messages=0

  if [ "$last_non_text_time" != "0" ]; then
    trim_user_time="$(sqlite3 "$DB_PATH" "select coalesce(max(time_created), 0) from message where session_id = '$session_id' and json_extract(data, '$.role') = 'user' and time_created <= $last_non_text_time;")"
    if [ "$trim_user_time" != "0" ]; then
      trim_user_id="$(sqlite3 "$DB_PATH" "select id from message where session_id = '$session_id' and json_extract(data, '$.role') = 'user' and time_created = $trim_user_time order by id desc limit 1;")"
      trailing_assistant_messages="$(sqlite3 "$DB_PATH" "select count(*) from message where session_id = '$session_id' and json_extract(data, '$.role') = 'assistant' and time_created > $trim_user_time;")"
    fi
  fi

  if [ "$dry_run" = "1" ]; then
    cat <<EOF
Dry run: $session_id
DB: $DB_PATH

Current state:
  messages=$before_messages
  parts=$before_parts
  non_text_parts=$before_non_text
  trim_anchor_user_id=${trim_user_id:-none}
  trailing_assistant_messages=$trailing_assistant_messages
EOF
    return 0
  fi

  ensure_backup

  sqlite3 "$DB_PATH" >/dev/null <<SQL
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;
BEGIN IMMEDIATE;
DELETE FROM message
WHERE session_id = '$session_id'
  AND json_extract(data, '$.role') = 'assistant'
  AND $trim_user_time <> 0
  AND time_created > $trim_user_time;

DELETE FROM part
WHERE session_id = '$session_id'
  AND json_extract(data, '$.type') <> 'text';

DELETE FROM message
WHERE session_id = '$session_id'
  AND id NOT IN (
    SELECT DISTINCT message_id
    FROM part
    WHERE session_id = '$session_id'
  );
COMMIT;
PRAGMA wal_checkpoint(TRUNCATE);
SQL

  after_parts="$(sqlite3 "$DB_PATH" "select count(*) from part where session_id = '$session_id';")"
  after_non_text="$(sqlite3 "$DB_PATH" "select count(*) from part where session_id = '$session_id' and json_extract(data, '$.type') <> 'text';")"
  after_messages="$(sqlite3 "$DB_PATH" "select count(*) from message where session_id = '$session_id';")"

  cat <<EOF
Repaired session: $session_id
Backup: $RUN_BACKUP_PATH
DB: $DB_PATH

Before:
  messages=$before_messages
  parts=$before_parts
  non_text_parts=$before_non_text
  trim_anchor_user_id=${trim_user_id:-none}
  trailing_assistant_messages=$trailing_assistant_messages

After:
  messages=$after_messages
  parts=$after_parts
  non_text_parts=$after_non_text
EOF
}

repair_session_list() {
  session_ids="$1"
  dry_run="$2"
  label="$3"
  session_count="$(count_session_list "$session_ids")"

  if [ "$session_count" = "0" ]; then
    echo "Nothing to repair for $label"
    return 0
  fi

  echo "Target set: $label"
  echo "Sessions: $session_count"

  old_ifs="$IFS"
  IFS='
'
  set -f
  # shellcheck disable=SC2086
  set -- $session_ids
  set +f
  IFS="$old_ifs"

  for session_id in "$@"; do
    [ -n "$session_id" ] || continue
    repair_session "$session_id" "$dry_run"
  done

  if [ "$dry_run" = "0" ] && [ -n "$RUN_BACKUP_PATH" ]; then
    echo "Run backup: $RUN_BACKUP_PATH"
  fi
}

repair_default_target_set() {
  dry_run="$1"
  max_passes=5
  pass=1

  while [ "$pass" -le "$max_passes" ]; do
    session_ids="$(sessions_from_error_projects)"

    if [ -z "$session_ids" ]; then
      if [ "$pass" = "1" ]; then
        echo "Nothing to repair: no corrupted-session candidates found in $LOG_DIR"
      else
        echo "Target set clean after $((pass - 1)) pass(es)."
      fi
      return 0
    fi

    if [ "$dry_run" = "1" ]; then
      repair_session_list \
        "$session_ids" \
        "$dry_run" \
        "all projects implicated by corrupted sessions in $LOG_DIR"
      return 0
    fi

    repair_session_list \
      "$session_ids" \
      "$dry_run" \
      "all projects implicated by corrupted sessions in $LOG_DIR (pass $pass)"
    pass=$((pass + 1))
  done

  remaining_sessions="$(sessions_from_error_projects)"
  remaining_count="$(count_session_list "$remaining_sessions")"
  if [ "$remaining_count" = "0" ]; then
    echo "Target set clean after $max_passes pass(es)."
    return 0
  fi

  echo "Warning: $remaining_count session(s) still have non-text parts after $max_passes passes." >&2
  echo "They may still be active and re-appending tool parts. Run ocrepair again after the active session stops." >&2
  return 1
}

main() {
  require_cmd sqlite3
  require_cmd awk
  ensure_db

  dry_run=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run)
        dry_run=1
        shift
        ;;
      *)
        break
        ;;
    esac
  done

  case "${1:-}" in
    -h|--help)
      usage
      ;;
    "")
      repair_default_target_set "$dry_run"
      ;;
    --list-errors)
      list_error_sessions
      ;;
    --latest-error)
      session_id="$(latest_error_session)"
      if [ -z "$session_id" ]; then
        echo "No corrupted session candidate found in $LOG_DIR" >&2
        exit 1
      fi
      repair_session "$session_id" "$dry_run"
      ;;
    --all-errors)
      session_ids="$(all_error_sessions)"
      repair_session_list "$session_ids" "$dry_run" "all corrupted sessions from logs"
      ;;
    --project)
      if [ $# -lt 2 ]; then
        echo "--project requires a session id or project id" >&2
        exit 1
      fi
      project_id="$(resolve_project_id "$2")"
      session_ids="$(sessions_with_non_text_in_project "$project_id")"
      repair_session_list "$session_ids" "$dry_run" "project $project_id"
      ;;
    *)
      repair_session "$1" "$dry_run"
      ;;
  esac
}

main "$@"
