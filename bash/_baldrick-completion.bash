#!/usr/bin/env bash
# Advanced bash completion for baldrick with fzf
#
# Source this file after any completion installed by `baldrick --install-completion`:
#   source /path/to/bash/_baldrick-completion.bash
# The last sourced completion wins; this script intentionally extends and replaces
# Typer's standard completion for baldrick.
#
# Requirements: bash-completion, fzf, sqlite3

# ============================================================================
# Core infrastructure
# ============================================================================

_BALDRICK_COMPLETION_COMMANDS=(
    load load-types cast-mem load-process decode-backtrace decode-address
    analyse-memory analyse-deadlock report tag query schema version gdb-path
)

# Resolve DB path: --db from current line, else $BALDRICK_DB.
_baldrick_resolve_db() {
    local i
    for (( i=0; i<${#COMP_WORDS[@]}-1; i++ )); do
        if [[ "${COMP_WORDS[$i]}" == "--db" || "${COMP_WORDS[$i]}" == "-d" ]]; then
            echo "${COMP_WORDS[$i+1]}"
            return
        fi
    done
    echo "${BALDRICK_DB:-}"
}

# Run SQL against DB and pipe through fzf.
#
# Result (first tab-field) is written to _BALDRICK_FZF_RESULT.
# fzf runs in the CURRENT shell (not a subshell), so that:
#   - it can open /dev/tty directly
#   - the DSR readline-redraw trick works (bind/printf affect parent readline)
#
# In tmux sessions --tmux is added automatically (popup, cleaner UX).
# Outside tmux the DSR trick: bind \e[0n → redraw-current-line, then
# send \e[5n to elicit the response — same approach fzf --bash uses.
#
# Usage:
#   _baldrick_fzf_query <sql> [fzf-options...]
#   echo "$_BALDRICK_FZF_RESULT"
#
# IMPORTANT: call directly (not via $(...)) so bind/printf run in parent shell.
_BALDRICK_FZF_RESULT=""
_baldrick_fzf_query() {
    local sql="$1"; shift
    local db
    db="$(_baldrick_resolve_db)"
    _BALDRICK_FZF_RESULT=""
    [[ -n "$db" && -f "$db" ]] || return 1

    local tmp
    tmp="$(mktemp)" || return 1

    local fzf_extra=()
    [[ -n "${TMUX:-}" ]] && fzf_extra=(--tmux)

    sqlite3 -separator $'\t' "$db" "$sql" 2>/dev/null \
        | fzf --ansi --no-sort --height=40% --reverse \
              --prompt="baldrick> " "${fzf_extra[@]}" "$@" > "$tmp"

    _BALDRICK_FZF_RESULT="$(cut -f1 < "$tmp")"
    rm -f "$tmp"

    # Redraw readline line (DSR trick — works here because we're in parent shell,
    # not a subshell).  Skipped in tmux: --tmux popup handles its own redraw.
    if [[ -z "${TMUX:-}" ]]; then
        bind '"\e[0n": redraw-current-line' 2>/dev/null
        printf '\e[5n'
    fi
}

# Run SQL and store a plain newline-separated list in _BALDRICK_SQL_RESULT.
_BALDRICK_SQL_RESULT=""
_baldrick_sql_list() {
    local sql="$1"
    local db
    db="$(_baldrick_resolve_db)"
    _BALDRICK_SQL_RESULT=""
    [[ -n "$db" && -f "$db" ]] || return 1
    _BALDRICK_SQL_RESULT="$(sqlite3 "$db" "$sql" 2>/dev/null)"
}

# Return value of an already-typed option from COMP_WORDS.
# Usage: _baldrick_prev_opt --tag
_baldrick_prev_opt() {
    local opt="$1"
    local i
    for (( i=1; i<${#COMP_WORDS[@]}-1; i++ )); do
        if [[ "${COMP_WORDS[$i]}" == "$opt" ]]; then
            echo "${COMP_WORDS[$i+1]}"
            return
        fi
    done
}

# ============================================================================
# Reusable pickers
#
# All pickers call _baldrick_fzf_query directly (NOT via $(...)) and
# expose the result via $_BALDRICK_FZF_RESULT.
# Callers must also call them directly, then read $_BALDRICK_FZF_RESULT.
# ============================================================================

# fzf: pick snapshot id — shows id, pid, tag, created_at
_baldrick_pick_snapshot() {
    _baldrick_fzf_query \
        "SELECT id, pid, COALESCE(tag,'—'), created_at FROM processsnapshot ORDER BY id DESC" \
        --header=$'ID\tPID\tTag\tCreated'
}

# fzf: pick tag
_baldrick_pick_tag() {
    _baldrick_fzf_query \
        "SELECT DISTINCT tag FROM processsnapshot WHERE tag IS NOT NULL ORDER BY tag" \
        --header="Tag"
}

# fzf: pick binary name — shows name and md5
_baldrick_pick_binary() {
    _baldrick_fzf_query \
        "SELECT name, md5sum FROM binary ORDER BY name" \
        --header=$'Binary\tMD5'
}

# fzf: pick query name from baldrick query list output.
# Uses a tempfile — same parent-shell discipline as _baldrick_fzf_query.
_baldrick_pick_query_name() {
    local db
    db="$(_baldrick_resolve_db)"
    local cmd="baldrick"
    [[ -n "$db" ]] && cmd="baldrick --db $db"

    _BALDRICK_FZF_RESULT=""
    local tmp
    tmp="$(mktemp)" || return 1

    local fzf_extra=()
    [[ -n "${TMUX:-}" ]] && fzf_extra=(--tmux)

    $cmd query list 2>/dev/null \
        | grep -E "^│" \
        | awk -F'│' '{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}' \
        | grep -v '^$' \
        | fzf --height=40% --reverse --prompt="query> " \
              --header="Query name" "${fzf_extra[@]}" > "$tmp"

    _BALDRICK_FZF_RESULT="$(cat "$tmp")"
    rm -f "$tmp"

    if [[ -z "${TMUX:-}" ]]; then
        bind '"\e[0n": redraw-current-line' 2>/dev/null
        printf '\e[5n'
    fi
}

# ============================================================================
# Contextual pickers (use an already-typed --snapshot-id from COMP_WORDS)
# ============================================================================

# fzf: libraries in a snapshot.
# Reads snapshot id from argument, or from --snapshot-id already on the line.
_baldrick_libs_in_snapshot() {
    local snap_id="${1:-$(_baldrick_prev_opt --snapshot-id)}"
    [[ -z "$snap_id" ]] && return 1
    _baldrick_fzf_query \
        "SELECT DISTINCT pathname FROM memorymapping
         WHERE process_id=$snap_id AND pathname NOT LIKE '[%' AND pathname != '[anonymous]'
         ORDER BY pathname" \
        --header="Library (snapshot $snap_id)"
}

# fzf: binaries mapped in a snapshot.
_baldrick_binaries_in_snapshot() {
    local snap_id="${1:-$(_baldrick_prev_opt --snapshot-id)}"
    [[ -z "$snap_id" ]] && return 1
    _baldrick_fzf_query \
        "SELECT DISTINCT b.name, m.pathname
         FROM processbinary pb
         JOIN binary b ON b.id = pb.binary_id
         JOIN memorymapping m ON m.id = pb.mapping_id
         WHERE pb.process_id=$snap_id
         ORDER BY b.name" \
        --header=$'Binary\tPath (snapshot '"$snap_id"')'
}

# fzf: all symbols visible in a snapshot (across all its binaries).
_baldrick_symbols_in_snapshot() {
    local snap_id="${1:-$(_baldrick_prev_opt --snapshot-id)}"
    [[ -z "$snap_id" ]] && return 1
    _baldrick_fzf_query \
        "SELECT s.name, b.name, hex(s.address)
         FROM symbol s
         JOIN binary b ON b.id = s.binary_id
         JOIN processbinary pb ON pb.binary_id = b.id
         WHERE pb.process_id=$snap_id
         ORDER BY s.name" \
        --header=$'Symbol\tBinary\tAddress (snapshot '"$snap_id"')'
}

# fzf: symbols in a specific binary (by name).
_baldrick_symbols_in_binary() {
    local bin_name="${1:-$(_baldrick_prev_opt --binary)}"
    [[ -z "$bin_name" ]] && return 1
    _baldrick_fzf_query \
        "SELECT s.name, hex(s.address), s.section
         FROM symbol s JOIN binary b ON b.id = s.binary_id
         WHERE b.name='$bin_name'
         ORDER BY s.name" \
        --header=$'Symbol\tAddress\tSection ('"$bin_name"')'
}

# ============================================================================
# Per-subcommand completion functions
#
# All fzf pickers are called directly (not via $(...)).
# Result is read from $_BALDRICK_FZF_RESULT.
# ============================================================================

_baldrick_complete_load() {
    local cur="$1" prev="$2"
    case "$prev" in
        --rootfs|-R|--debugfs|-D|--dirs) _filedir -d; return ;;
        --files|-f|--maps|-m|--coredump|-C) _filedir; return ;;
        --pid|-p)
            COMPREPLY=( $(compgen -W "$(ls /proc 2>/dev/null | grep '^[0-9]')" -- "$cur") )
            return ;;
    esac
    COMPREPLY=( $(compgen -W \
        "--rootfs -R --debugfs -D --glob -g --perm -P --files -f --maps -m --pid -p --coredump -C --dirs --types -t --lines -l --maxbin --maxdepth --slow-threshold --slow-top --help -h" \
        -- "$cur") )
}

_baldrick_complete_load_types() {
    local cur="$1" prev="$2"
    case "$prev" in
        --binary|-b) _filedir; return ;;
    esac
    COMPREPLY=( $(compgen -W "--binary -b --help -h" -- "$cur") )
}

_baldrick_complete_cast_mem() {
    local cur="$1" prev="$2"
    case "$prev" in
        --binary|-b)
            _baldrick_sql_list "SELECT name FROM binary ORDER BY name"
            COMPREPLY=( $(compgen -W "$_BALDRICK_SQL_RESULT" -- "$cur") )
            return ;;
        --mem)       _filedir; return ;;
        --type)
            _baldrick_sql_list "SELECT DISTINCT name FROM canonical_dwarf_type WHERE tag IN ('structure_type','union_type','typedef') AND name IS NOT NULL ORDER BY name"
            COMPREPLY=( $(compgen -W "$_BALDRICK_SQL_RESULT" -- "$cur") )
            return ;;
    esac
    COMPREPLY=( $(compgen -W "--type --binary -b --mem --addr --help -h" -- "$cur") )
}

_baldrick_complete_load_process() {
    local cur="$1" prev="$2"
    case "$prev" in
        --maps|-m)                _filedir;    return ;;
        --coredump|-C)            _filedir;    return ;;
        --gdb-dump|-G)            _filedir;    return ;;
        --pid|-p)
            COMPREPLY=( $(compgen -W "$(ls /proc 2>/dev/null | grep '^[0-9]')" -- "$cur") )
            return ;;
        --rootfs|-R|--debugfs|-D) _filedir -d; return ;;
        --tag|-T)
            _baldrick_pick_tag
            [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("$_BALDRICK_FZF_RESULT")
            return ;;
        --snapshot-id|-s)
            _baldrick_pick_snapshot
            [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("$_BALDRICK_FZF_RESULT")
            return ;;
    esac
    COMPREPLY=( $(compgen -W \
        "--maps -m --pid -p --coredump -C --gdb-dump -G --rootfs -R --debugfs -D --tag -T --snapshot-id -s --update -u --force -f --help -h" \
        -- "$cur") )
}

_baldrick_complete_decode_backtrace() {
    local cur="$1" prev="$2"
    case "$prev" in
        --trace|-t) _filedir; return ;;
        --rootfs|-R|--debugfs|-D) _filedir -d; return ;;
        --snapshot-id|-s)
            _baldrick_pick_snapshot
            [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("$_BALDRICK_FZF_RESULT")
            return ;;
    esac
    COMPREPLY=( $(compgen -W \
        "--trace -t --snapshot-id -s --rootfs -R --debugfs -D --jobs -j --help -h" \
        -- "$cur") )
}

_baldrick_complete_decode_address() {
    local cur="$1" prev="$2"
    case "$prev" in
        --rootfs|-R|--debugfs|-D) _filedir -d; return ;;
        --snapshot-id|-s)
            _baldrick_pick_snapshot
            [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("$_BALDRICK_FZF_RESULT")
            return ;;
        --binary|-b) _filedir; return ;;
    esac
    COMPREPLY=( $(compgen -W \
        "--rootfs -R --debugfs -D --mapped -a --unmapped -A --snapshot-id -s --binary -b --name -n --type -t --section -j --full -F --help -h" \
        -- "$cur") )
}

_baldrick_complete_analyse_memory() {
    local cur="$1" prev="$2"
    case "$prev" in
        --maps|-m)                _filedir;    return ;;
        --coredump|-C)            _filedir;    return ;;
        --rootfs|-R|--debugfs|-D) _filedir -d; return ;;
        --pid|-p)
            COMPREPLY=( $(compgen -W "$(ls /proc 2>/dev/null | grep '^[0-9]')" -- "$cur") )
            return ;;
    esac
    COMPREPLY=( $(compgen -W \
        "--rootfs -R --debugfs -D --maps -m --pid -p --coredump -C --help -h" \
        -- "$cur") )
}

_baldrick_complete_tag() {
    local cur="$1" prev="$2"
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "--help -h" -- "$cur") )
        return
    fi

    # Count positional args already typed after 'tag' subcommand
    local pos=0
    local in_cmd=0
    local i
    for (( i=1; i<${#COMP_WORDS[@]}-1; i++ )); do
        local w="${COMP_WORDS[$i]}"
        [[ "$w" == "tag" ]]  && { in_cmd=1; continue; }
        [[ $in_cmd -eq 0 ]]  && continue
        [[ "$w" == --* ]]    && { (( i++ )); continue; }  # skip option+value
        (( pos++ ))
    done

    if (( pos == 0 )); then
        # First positional = snapshot id
        _baldrick_pick_snapshot
        [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("$_BALDRICK_FZF_RESULT")
    else
        # Second positional = new tag (offer existing tags as suggestions)
        _baldrick_pick_tag
        [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("$_BALDRICK_FZF_RESULT")
    fi
}

_baldrick_complete_analyse_deadlock() {
    local cur="$1" prev="$2"
    case "$prev" in
        --snapshot-id|-s)
            _baldrick_pick_snapshot
            [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("$_BALDRICK_FZF_RESULT")
            return ;;
        --lock-state|-L)
            _filedir
            return ;;
    esac
    COMPREPLY=( $(compgen -W "--snapshot-id -s --lock-state -L --json --help -h" -- "$cur") )
}

_baldrick_complete_report() {
    local cur="$1" prev="$2"
    case "$prev" in
        --snapshot-id|-s)
            _baldrick_pick_snapshot
            [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("$_BALDRICK_FZF_RESULT")
            return ;;
    esac
    COMPREPLY=( $(compgen -W "--snapshot-id -s --json --help -h" -- "$cur") )
}

_baldrick_complete_query() {
    local cur="$1" prev="$2"

    # Find query name already typed (first non-option positional after 'query')
    local query_name=""
    local in_cmd=0
    local i
    for (( i=1; i<${#COMP_WORDS[@]}-1; i++ )); do
        local w="${COMP_WORDS[$i]}"
        [[ "$w" == "query" ]] && { in_cmd=1; continue; }
        [[ $in_cmd -eq 0 ]]   && continue
        [[ "$w" == --* ]]     && { (( i++ )); continue; }
        query_name="$w"; break
    done

    if [[ -z "$query_name" && "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "--param -p --tag -T --format -f --help -h" -- "$cur") )
        return
    fi

    case "$prev" in
        --format|-f)
            COMPREPLY=( $(compgen -W "rich json csv" -- "$cur") )
            return ;;
        --tag|-T)
            _baldrick_pick_tag
            [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("$_BALDRICK_FZF_RESULT")
            return ;;
        --param|-p)
            # Context-aware: what param does this query expect?
            case "$query_name" in
                symbols|sections|symbol-cache|types)
                    # --param binary=<name>
                    # If --tag is already on the line, scope to that snapshot.
                    local snap_id
                    snap_id="$(_baldrick_prev_opt --tag)"
                    if [[ -n "$snap_id" ]]; then
                        # resolve tag → id
                        local db; db="$(_baldrick_resolve_db)"
                        snap_id="$(sqlite3 "$db" \
                            "SELECT id FROM processsnapshot WHERE tag='$snap_id' ORDER BY id DESC LIMIT 1" \
                            2>/dev/null)"
                    fi
                    if [[ -n "$snap_id" ]]; then
                        _baldrick_binaries_in_snapshot "$snap_id"
                    else
                        _baldrick_pick_binary
                    fi
                    [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("binary=$_BALDRICK_FZF_RESULT")
                    ;;
                mappings|libs|rwx|backtrace|process-binaries|threads|deadlock-threads)
                    # --param id=<snapshot_id>
                    _baldrick_pick_snapshot
                    [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("id=$_BALDRICK_FZF_RESULT")
                    ;;
                addr2line)
                    # --param binary=<name> addr=<offset in binary>
                    case "$cur" in
                        binary=*)
                            _baldrick_pick_binary
                            [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("binary=$_BALDRICK_FZF_RESULT")
                            ;;
                        *)
                            COMPREPLY=( $(compgen -W "binary= addr=" -- "$cur") )
                            ;;
                    esac
                    ;;
                addr2line-snap)
                    # --param id=<snapshot_id> addr=<virtual address>
                    case "$cur" in
                        id=*)
                            _baldrick_pick_snapshot
                            [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("id=$_BALDRICK_FZF_RESULT")
                            ;;
                        *)
                            COMPREPLY=( $(compgen -W "id= addr=" -- "$cur") )
                            ;;
                    esac
                    ;;
                struct|type-offset|line2addr)
                    # --param name=... binary=... (or file= line= for line2addr)
                    # First offer binary pick; raw fallback for name/file/line
                    case "$cur" in
                        binary=*)
                            _baldrick_pick_binary
                            [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("binary=$_BALDRICK_FZF_RESULT")
                            ;;
                        *)
                            if [[ "$query_name" == "line2addr" ]]; then
                                COMPREPLY=( $(compgen -W "binary= file= line=" -- "$cur") )
                            elif [[ "$query_name" == "type-offset" ]]; then
                                COMPREPLY=( $(compgen -W "name= offset= binary=" -- "$cur") )
                            else
                                COMPREPLY=( $(compgen -W "name= binary=" -- "$cur") )
                            fi
                            ;;
                    esac
                    ;;
                symbol-cache-stats)
                    # No params needed
                    COMPREPLY=()
                    ;;
                *)
                    COMPREPLY=( $(compgen -W "id= binary= tag=" -- "$cur") )
                    ;;
            esac
            return ;;
    esac

    # First positional after 'query' = query name (or special: list, sql=...).
    if [[ -z "$query_name" ]]; then
        # Offer built-in specials + fzf over named queries.
        case "$cur" in
            l*)  COMPREPLY=( $(compgen -W "list" -- "$cur") ); return ;;
            s*)  COMPREPLY=( $(compgen -W "sql=" -- "$cur") ); return ;;
        esac
        _baldrick_pick_query_name
        [[ -n "$_BALDRICK_FZF_RESULT" ]] && COMPREPLY=("$_BALDRICK_FZF_RESULT")
    else
        COMPREPLY=( $(compgen -W "--param -p --tag -T --format -f --help -h" -- "$cur") )
    fi
}

# ============================================================================
# Main dispatcher
# ============================================================================

# Use Typer's generated completion for commands without custom behaviour.
_baldrick_typer_complete() {
    local executable
    executable="$(type -P "${COMP_WORDS[0]}")"
    [[ -n "$executable" ]] || return 1

    local IFS=$'\n'
    COMPREPLY=( $(env COMP_WORDS="${COMP_WORDS[*]}" \
        COMP_CWORD="$COMP_CWORD" _BALDRICK_COMPLETE=complete_bash "$executable") )
}

_baldrick_complete() {
    local cur prev
    cur="${COMP_WORDS[$COMP_CWORD]}"
    prev="${COMP_WORDS[$COMP_CWORD-1]}"

    # Global options (before subcommand)
    local global_opts="--debug --log-level --log-file --db -d --install-completion --show-completion --help -h"

    # Handle global options
    case "$prev" in
        --db|-d)      _filedir; return ;;
        --log-file)   _filedir; return ;;
        --log-level)  COMPREPLY=( $(compgen -W "DEBUG INFO WARNING ERROR" -- "$cur") ); return ;;
        --install-completion|--show-completion) _baldrick_typer_complete; return ;;
    esac

    # Find the subcommand in COMP_WORDS
    local cmd="" known
    local i
    for (( i=1; i<${#COMP_WORDS[@]}; i++ )); do
        for known in "${_BALDRICK_COMPLETION_COMMANDS[@]}"; do
            if [[ "${COMP_WORDS[$i]}" == "$known" ]]; then
                cmd="${COMP_WORDS[$i]}"
                break 2
            fi
        done
    done

    if [[ -z "$cmd" ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=( $(compgen -W "$global_opts" -- "$cur") )
        else
            COMPREPLY=( $(compgen -W "${_BALDRICK_COMPLETION_COMMANDS[*]}" -- "$cur") )
        fi
        return
    fi

    # Dispatch to per-subcommand function
    case "$cmd" in
        load)               _baldrick_complete_load               "$cur" "$prev" ;;
        load-types)         _baldrick_complete_load_types         "$cur" "$prev" ;;
        cast-mem)           _baldrick_complete_cast_mem           "$cur" "$prev" ;;
        load-process)       _baldrick_complete_load_process       "$cur" "$prev" ;;
        decode-backtrace)   _baldrick_complete_decode_backtrace   "$cur" "$prev" ;;
        decode-address)     _baldrick_complete_decode_address     "$cur" "$prev" ;;
        analyse-memory)     _baldrick_complete_analyse_memory     "$cur" "$prev" ;;
        analyse-deadlock)   _baldrick_complete_analyse_deadlock   "$cur" "$prev" ;;
        report)             _baldrick_complete_report             "$cur" "$prev" ;;
        tag)                _baldrick_complete_tag                "$cur" "$prev" ;;
        query)              _baldrick_complete_query              "$cur" "$prev" ;;
        schema|version|gdb-path) _baldrick_typer_complete ;;
        *)                  _baldrick_typer_complete ;;
    esac
}

complete -F _baldrick_complete baldrick

# Compare the commands supported here with those advertised by the installed
# baldrick executable. Returns 0 when aligned, 1 for a mismatch, and 2 when the
# executable cannot be checked.
baldrick-check-completion() {
    local executable
    executable="$(type -P baldrick)"
    if [[ -z "$executable" ]]; then
        echo "baldrick-check-completion: baldrick is not available in PATH" >&2
        return 2
    fi

    local output
    if ! output="$(env COMP_WORDS="baldrick " COMP_CWORD=1 \
        _BALDRICK_COMPLETE=complete_bash "$executable" 2>/dev/null)"; then
        echo "baldrick-check-completion: cannot read commands from $executable" >&2
        return 2
    fi

    local current_commands=() command_name
    while IFS= read -r command_name; do
        [[ -n "$command_name" && "$command_name" != -* ]] && current_commands+=("$command_name")
    done <<< "$output"
    if (( ${#current_commands[@]} == 0 )); then
        echo "baldrick-check-completion: $executable returned no commands" >&2
        return 2
    fi

    local missing=() stale=() expected actual found
    for actual in "${current_commands[@]}"; do
        found=0
        for expected in "${_BALDRICK_COMPLETION_COMMANDS[@]}"; do
            [[ "$actual" == "$expected" ]] && { found=1; break; }
        done
        (( found )) || missing+=("$actual")
    done
    for expected in "${_BALDRICK_COMPLETION_COMMANDS[@]}"; do
        found=0
        for actual in "${current_commands[@]}"; do
            [[ "$expected" == "$actual" ]] && { found=1; break; }
        done
        (( found )) || stale+=("$expected")
    done

    if (( ${#missing[@]} || ${#stale[@]} )); then
        (( ${#missing[@]} )) && printf 'Missing completion commands: %s\n' "${missing[*]}" >&2
        (( ${#stale[@]} )) && printf 'Stale completion commands: %s\n' "${stale[*]}" >&2
        return 1
    fi

    printf 'Baldrick completion is up to date (%d commands).\n' "${#current_commands[@]}"
}

# ============================================================================
# Custom completion helper API — use in your own ~/.bashrc functions
#
#   _baldrick_fzf_query "<SQL>" [fzf-opts]    — fzf over any SQL
#                                               result in $_BALDRICK_FZF_RESULT
#                                               MUST call directly, not via $()
#   _baldrick_sql_list  "<SQL>"               — plain list (no fzf)
#   _baldrick_resolve_db                      — current DB path
#   _baldrick_prev_opt  --opt                 — value of option already typed
#   baldrick-check-completion                 — verify the installed command set
#
#   _baldrick_pick_snapshot                   — fzf: snapshot id
#   _baldrick_pick_tag                        — fzf: tag
#   _baldrick_pick_binary                     — fzf: binary name
#   _baldrick_pick_query_name                 — fzf: query name
#
#   _baldrick_libs_in_snapshot    [snap_id]   — fzf: libs in snapshot
#   _baldrick_binaries_in_snapshot [snap_id]  — fzf: binaries in snapshot
#   _baldrick_symbols_in_snapshot  [snap_id]  — fzf: all symbols in snapshot
#   _baldrick_symbols_in_binary    [bin_name] — fzf: symbols in binary
#
# All pickers write to $_BALDRICK_FZF_RESULT.  Call them directly (not via
# $(...)), otherwise the readline-redraw trick won't work outside tmux.
#
# Example — key binding that inserts a picked snapshot id at cursor:
#
#   _fzf_baldrick_snap() {
#       _baldrick_pick_snapshot
#       local sel="$_BALDRICK_FZF_RESULT"
#       READLINE_LINE="${READLINE_LINE::$READLINE_POINT}${sel}${READLINE_LINE:$READLINE_POINT}"
#       READLINE_POINT=$(( READLINE_POINT + ${#sel} ))
#   }
#   bind -x '"\C-x\C-s": _fzf_baldrick_snap'
#
# Example — interactive inspect: pick snapshot then binary then show symbols:
#
#   baldrick_inspect() {
#       local db="$BALDRICK_DB"
#       _baldrick_pick_snapshot
#       local snap_id="$_BALDRICK_FZF_RESULT"; [[ -n "$snap_id" ]] || return
#       _baldrick_binaries_in_snapshot "$snap_id"
#       local binary="$_BALDRICK_FZF_RESULT"; [[ -n "$binary" ]] || return
#       baldrick --db "$db" query symbols --param "binary=$binary"
#   }
# ============================================================================
