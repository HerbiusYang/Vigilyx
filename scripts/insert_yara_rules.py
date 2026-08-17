#!/usr/bin/env python3
"""Build governed YARA packs or import legacy JSON rules into PostgreSQL.

The pack builder is intentionally conservative: it pins provenance supplied by
the operator, preserves source rule text and attribution, rejects unsupported
modules/includes and duplicate identifiers, separates high-cost rules, and
emits an immutable SHA-256 manifest consumed by Vigilyx.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


RULE_START = re.compile(
    r"(?m)^[ \t]*(?:(private|global)[ \t]+)?rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)\b"
)
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
IMPORT = re.compile(r'(?m)^[ \t]*import[ \t]+"([A-Za-z0-9_.-]+)"[ \t]*$')
INCLUDE = re.compile(r'(?m)^[ \t]*include[ \t]+["<]')
QUOTED_LITERAL = re.compile(r'"((?:\\.|[^"\\]){4,})"')
HEX_RUN = re.compile(r"(?i)(?:\b[0-9a-f]{2}[ \t]+){3,}\b[0-9a-f]{2}\b")
COMMON_ATOMS = {
    "this",
    "that",
    "http",
    "https",
    "user",
    "windows",
    "microsoft",
    "program",
    "system",
    "error",
    "version",
    "content",
    "script",
    "function",
    "kernel32.dll",
    "get ",
    "post",
    "pe\x00\x00",
}
DEFAULT_UNSUPPORTED_MODULES = {"androguard", "cuckoo"}
QUALITY_TIERS = {"exact", "high", "medium", "hunting", "legacy"}
TARGETS = {
    "generic",
    "message",
    "office",
    "pdf",
    "archive",
    "executable",
    "script",
    "html",
    "shortcut",
    "disk_image",
}


@dataclass(frozen=True)
class SourceSpec:
    name: str
    root: Path
    license_id: str
    license_path: Path
    provenance: str
    version: str
    quality_tier: str
    target_override: str | None


@dataclass
class RuleUnit:
    name: str
    text: str
    target: str
    high_cost: bool
    source_name: str
    license_id: str
    provenance: str
    version: str
    quality_tier: str
    relative_path: str
    imports: tuple[str, ...]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_source_spec(value: str) -> SourceSpec:
    parts = [part.strip() for part in value.split("|")]
    if not 6 <= len(parts) <= 8:
        raise argparse.ArgumentTypeError(
            "source must be NAME|ROOT|LICENSE_ID|LICENSE_FILE|PROVENANCE|VERSION"
            "[|QUALITY_TIER[|TARGET]]"
        )
    name, root, license_id, license_file, provenance, version = parts[:6]
    quality_tier = parts[6] if len(parts) >= 7 and parts[6] else "legacy"
    target_override = parts[7] if len(parts) == 8 and parts[7] else None
    root_path = Path(root).resolve()
    license_path = Path(license_file).resolve()
    if not name or not license_id or not provenance or not version:
        raise argparse.ArgumentTypeError("source fields must not be empty")
    if not SAFE_TOKEN.fullmatch(name):
        raise argparse.ArgumentTypeError(
            "source name must contain only ASCII letters, digits, dot, underscore or dash"
        )
    if quality_tier not in QUALITY_TIERS:
        raise argparse.ArgumentTypeError(f"invalid quality tier: {quality_tier}")
    if target_override is not None and target_override not in TARGETS:
        raise argparse.ArgumentTypeError(f"invalid target override: {target_override}")
    if not root_path.is_dir():
        raise argparse.ArgumentTypeError(f"source root is not a directory: {root_path}")
    if not license_path.is_file():
        raise argparse.ArgumentTypeError(f"license file is missing: {license_path}")
    return SourceSpec(
        name,
        root_path,
        license_id,
        license_path,
        provenance,
        version,
        quality_tier,
        target_override,
    )


def mask_comments_and_strings(text: str) -> str:
    """Preserve positions while hiding tokens that can contain fake `rule`."""
    chars = list(text)
    index = 0
    state = "normal"
    while index < len(chars):
        current = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "normal":
            if current == "/" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if current == "/" and following == "*":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if current == '"':
                chars[index] = " "
                index += 1
                state = "string"
                continue
        elif state == "line_comment":
            if current == "\n":
                state = "normal"
            else:
                chars[index] = " "
        elif state == "block_comment":
            if current == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "normal"
                continue
            if current != "\n":
                chars[index] = " "
        elif state == "string":
            if current == "\\" and following:
                chars[index] = chars[index + 1] = " "
                index += 2
                continue
            if current == '"':
                chars[index] = " "
                state = "normal"
            elif current != "\n":
                chars[index] = " "
        index += 1
    return "".join(chars)


def extract_rules(text: str) -> list[tuple[str, str, str | None]]:
    masked = mask_comments_and_strings(text)
    results: list[tuple[str, str, str | None]] = []
    for match in RULE_START.finditer(masked):
        brace = masked.find("{", match.end())
        if brace < 0:
            continue
        depth = 0
        end = None
        for index in range(brace, len(masked)):
            if masked[index] == "{":
                depth += 1
            elif masked[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is not None:
            results.append(
                (match.group(2), text[match.start() : end].strip() + "\n", match.group(1))
            )
    return results


def mandatory_literal_present(rule_text: str) -> bool:
    """Conservative admission: only obvious selective literals count.

    This is a quality classification, not a semantic prefilter proof. The
    runtime therefore still evaluates high-cost rules in their own shard.
    """
    condition = rule_text.lower().split("condition:", 1)
    if len(condition) != 2:
        return False
    if re.search(r"\btrue\b", condition[1]) and "strings:" not in rule_text.lower():
        return False
    for match in QUOTED_LITERAL.finditer(rule_text):
        # Raw YARA string text is sufficient for admission scoring. Decoding
        # arbitrary escape sequences here both changes semantics and emits
        # warnings for valid YARA escapes that Python does not understand.
        literal = match.group(1).lower()
        if len(literal) >= 6 and literal not in COMMON_ATOMS and len(set(literal)) >= 3:
            return True
    for match in HEX_RUN.finditer(rule_text):
        tokens = re.findall(r"(?i)\b[0-9a-f]{2}\b", match.group(0))
        if len(tokens) >= 4 and len(set(tokens)) >= 3:
            return True
    return False


def classify_target(relative_path: str, text: str) -> str:
    value = f"{relative_path}\n{text[:8192]}".lower()
    if any(token in value for token in (".pdf", " pdf_", "pdf ", "%pdf")):
        return "pdf"
    if any(
        token in value
        for token in ("office", "maldoc", "docx", "docm", "xlsx", "xlsm", "vba", "macro", "rtf")
    ):
        return "office"
    if any(token in value for token in ("powershell", "javascript", "vbscript", "script_", ".ps1", ".vbs", ".js")):
        return "script"
    if any(token in value for token in ("html", "hta", "svg", "smuggl")):
        return "html"
    if any(token in value for token in ("lnk", "shortcut", "chm", "remoteapp", "rdp_", ".rdp")):
        return "shortcut"
    if any(token in value for token in ("iso_", "vhd", "disk_image", "cd001")):
        return "disk_image"
    if any(token in value for token in ("archive", " zip", "rar", "7zip", "packer")):
        return "archive"
    if any(token in value for token in ("pe32", "executable", "win32", "elf", "shellcode", "malware")):
        return "executable"
    if any(token in value for token in ("email", "phish", "eml", "smtp")):
        return "message"
    return "generic"


def compile_with_libyara(yara_module, source: str) -> tuple[bool, str | None, int]:
    """Compile one immutable unit and return its actual public-rule count."""
    try:
        compiled = yara_module.compile(source=source, error_on_warning=False)
        return True, None, sum(1 for _ in compiled)
    except yara_module.Error as error:
        return False, str(error)[:1000], 0


def standalone_source(imports: tuple[str, ...], rule_text: str) -> str:
    header = "\n".join(f'import "{module}"' for module in imports)
    return f"{header}\n\n{rule_text}" if header else rule_text


def unconditional_true(rule_text: str) -> bool:
    parts = re.split(r"(?i)\bcondition\s*:", rule_text, maxsplit=1)
    if len(parts) != 2:
        return False
    condition = parts[1].rsplit("}", 1)[0].strip().lower()
    return condition == "true"


def collect_units(
    specs: list[SourceSpec],
    unsupported_modules: set[str],
    exclude_globs: tuple[str, ...],
    yara_module,
) -> tuple[list[RuleUnit], list[dict], dict[str, bytes]]:
    units: list[RuleUnit] = []
    rejected: list[dict] = []
    licenses: dict[str, bytes] = {}
    seen_names: dict[str, str] = {}

    for spec in specs:
        licenses[spec.name] = spec.license_path.read_bytes()
        paths = sorted(
            path
            for path in spec.root.rglob("*")
            if path.is_file() and path.suffix.lower() in {".yar", ".yara"}
        )
        for path in paths:
            relative = path.relative_to(spec.root).as_posix()
            if any(fnmatch.fnmatchcase(relative, pattern) for pattern in exclude_globs):
                rejected.append({"source": spec.name, "path": relative, "reason": "excluded"})
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                rejected.append({"source": spec.name, "path": relative, "reason": "non_utf8"})
                continue
            imports = tuple(sorted(set(IMPORT.findall(text))))
            if INCLUDE.search(text):
                rejected.append({"source": spec.name, "path": relative, "reason": "include_directive"})
                continue
            extracted = extract_rules(text)
            if not extracted:
                rejected.append({"source": spec.name, "path": relative, "reason": "no_rules"})
                continue
            for name, rule_text, modifier in extracted:
                if modifier is not None:
                    rejected.append(
                        {
                            "source": spec.name,
                            "path": relative,
                            "rule": name,
                            "reason": f"{modifier}_rule_not_standalone",
                        }
                    )
                    continue
                used_modules = tuple(
                    module
                    for module in imports
                    if re.search(rf"(?<![A-Za-z0-9_]){re.escape(module)}\s*\.", rule_text)
                )
                unsupported = sorted(set(used_modules) & unsupported_modules)
                if unsupported:
                    rejected.append(
                        {
                            "source": spec.name,
                            "path": relative,
                            "rule": name,
                            "reason": "unsupported_modules",
                            "modules": unsupported,
                        }
                    )
                    continue
                if unconditional_true(rule_text):
                    rejected.append(
                        {
                            "source": spec.name,
                            "path": relative,
                            "rule": name,
                            "reason": "unconditional_true",
                        }
                    )
                    continue
                compiled, error, compiled_count = compile_with_libyara(
                    yara_module, standalone_source(used_modules, rule_text)
                )
                if not compiled or compiled_count != 1:
                    rejected.append(
                        {
                            "source": spec.name,
                            "path": relative,
                            "rule": name,
                            "reason": "compile_failed" if not compiled else "count_mismatch",
                            "error": error,
                            "compiled_count": compiled_count,
                        }
                    )
                    continue
                if name in seen_names:
                    rejected.append(
                        {
                            "source": spec.name,
                            "path": relative,
                            "reason": "duplicate_identifier",
                            "identifier": name,
                            "first_seen": seen_names[name],
                        }
                    )
                    continue
                seen_names[name] = f"{spec.name}:{relative}"
                # A filename or keyword heuristic cannot prove that a rule is
                # irrelevant to every other object type. Unproved rules remain
                # generic so target routing cannot create a false negative.
                # A target is accepted only as explicit governed source input.
                target = spec.target_override or "generic"
                units.append(
                    RuleUnit(
                        name=name,
                        text=rule_text,
                        target=target,
                        high_cost=not mandatory_literal_present(rule_text),
                        source_name=spec.name,
                        license_id=spec.license_id,
                        provenance=spec.provenance,
                        version=spec.version,
                        quality_tier=spec.quality_tier,
                        relative_path=relative,
                        imports=used_modules,
                    )
                )
    return units, rejected, licenses


def build_pack(args: argparse.Namespace) -> int:
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"output already exists; use a new immutable generation path: {output}")
    if args.mode != "shadow":
        raise SystemExit("governed libyara community packs are shadow-only")
    try:
        import yara
    except ImportError as error:
        raise SystemExit(
            "yara-python is required to compile-validate every governed rule"
        ) from error
    if yara.YARA_VERSION != args.expected_libyara_version:
        raise SystemExit(
            "libyara validator version mismatch: "
            f"found {yara.YARA_VERSION}, expected {args.expected_libyara_version}"
        )
    unsupported = set(args.unsupported_module or DEFAULT_UNSUPPORTED_MODULES)
    units, rejected, licenses = collect_units(
        args.source, unsupported, tuple(args.exclude_glob), yara
    )
    if len(units) < args.min_rules:
        raise SystemExit(
            f"quality gate failed: only {len(units)} unique compiled rules, need {args.min_rules}"
        )

    groups: dict[tuple[str, str, str, str, str, str, bool], list[RuleUnit]] = defaultdict(list)
    for unit in units:
        groups[
            (
                unit.source_name,
                unit.license_id,
                unit.provenance,
                unit.version,
                unit.quality_tier,
                unit.target,
                unit.high_cost,
            )
        ].append(unit)

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    manifest_sources: list[dict] = []
    try:
        license_metadata: dict[str, tuple[str, str]] = {}
        license_dir = staging / "licenses"
        license_dir.mkdir(parents=True)
        for source_name, license_bytes in licenses.items():
            license_name = f"{source_name}.txt"
            license_path = license_dir / license_name
            license_path.write_bytes(license_bytes)
            license_metadata[source_name] = (
                f"licenses/{license_name}",
                sha256_bytes(license_bytes),
            )

        shard_dir = staging / "shards"
        shard_dir.mkdir()
        for key in sorted(groups):
            source_name, license_id, provenance, version, quality_tier, target, high_cost = key
            group = sorted(groups[key], key=lambda unit: (unit.relative_path, unit.name))
            for part, start in enumerate(range(0, len(group), args.rules_per_shard)):
                chunk = group[start : start + args.rules_per_shard]
                shard_id = f"{source_name}-{target}{'-highcost' if high_cost else ''}-{part:04d}"
                imports = sorted({module for unit in chunk for module in unit.imports})
                header = [
                    f"// Vigilyx governed shard: {shard_id}",
                    f"// Provenance: {provenance}@{version}",
                    f"// License: {license_id}",
                    "",
                ]
                header.extend(f'import "{module}"' for module in imports)
                header.append("")
                body = "\n".join(header) + "\n\n".join(unit.text for unit in chunk)
                compiled, error, compiled_count = compile_with_libyara(yara, body)
                if not compiled or compiled_count != len(chunk):
                    raise SystemExit(
                        f"final shard quality gate failed for {shard_id}: "
                        f"compiled={compiled_count} expected={len(chunk)} error={error}"
                    )
                relative_path = f"shards/{shard_id}.yar"
                shard_bytes = body.encode("utf-8")
                (staging / relative_path).write_bytes(shard_bytes)
                license_path, license_digest = license_metadata[source_name]
                manifest_sources.append(
                    {
                        "shard_id": shard_id,
                        "path": relative_path,
                        "sha256": sha256_bytes(shard_bytes),
                        "target": target,
                        "backend": "libyara",
                        "license": license_id,
                        "license_path": license_path,
                        "license_sha256": license_digest,
                        "provenance": provenance,
                        "version": version,
                        "rule_count": len(chunk),
                        "quality_tier": "high_cost" if high_cost else quality_tier,
                        "mode": args.mode,
                    }
                )

        counts = Counter("high_cost" if unit.high_cost else "normal" for unit in units)
        manifest = {
            "schema_version": 1,
            "pack_id": args.pack_id,
            "generation": args.generation,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "min_engine_version": args.min_engine_version,
            "summary": {
                "candidate_rules": len(units),
                "compiled_rules": len(units),
                "normal_rules": counts["normal"],
                "high_cost_rules": counts["high_cost"],
                "rejected_units": len(rejected),
                "shards": len(manifest_sources),
                "mode": args.mode,
                "backend": "libyara",
                "compiler": f"yara-python/libyara {yara.YARA_VERSION}",
            },
            "sources": manifest_sources,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (staging / "rejections.json").write_text(
            json.dumps(rejected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    print(
        json.dumps(
            {
                "output": str(output),
                "rules": len(units),
                "normal": counts["normal"],
                "high_cost": counts["high_cost"],
                "shards": len(manifest_sources),
                "rejected_units": len(rejected),
                "mode": args.mode,
                "backend": "libyara",
                "compiler": yara.YARA_VERSION,
            },
            ensure_ascii=False,
        )
    )
    return 0


def import_db(args: argparse.Namespace) -> int:
    try:
        import psycopg2
    except ImportError as error:
        raise SystemExit("psycopg2 is required for db-import") from error
    password = os.environ.get("PGPASSWORD")
    if not password:
        raise SystemExit("PGPASSWORD environment variable is not set")
    rules = json.loads(args.rules_file.read_text(encoding="utf-8"))
    connection = psycopg2.connect(
        host=args.host,
        port=args.port,
        user=args.user,
        dbname=args.database,
        password=password,
    )
    connection.autocommit = True
    cursor = connection.cursor()
    success = failed = 0
    sql = (
        "INSERT INTO security_yara_rules "
        "(id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at) "
        "VALUES (%s, %s, %s, %s, 'custom', %s, %s, TRUE, 0, %s, %s) "
        "ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, "
        "category=EXCLUDED.category, severity=EXCLUDED.severity, "
        "description=EXCLUDED.description, updated_at=EXCLUDED.updated_at"
    )
    for rule in rules:
        now = datetime.now(timezone.utc).isoformat()
        try:
            cursor.execute(
                sql,
                (
                    str(uuid.uuid4()),
                    rule["rule_name"],
                    rule["category"],
                    rule["severity"],
                    rule["rule_source"],
                    rule.get("description", ""),
                    now,
                    now,
                ),
            )
            success += 1
        except Exception as error:  # administrative utility reports and continues
            print(f"FAILED {rule.get('rule_name', '<unknown>')}: {str(error)[:200]}")
            failed += 1
    cursor.close()
    connection.close()
    print(json.dumps({"success": success, "failed": failed, "total": len(rules)}))
    return 0 if failed == 0 else 1


def self_test() -> int:
    sample = r'''
// rule fake { condition: true }
import "math"
private rule helper { strings: $a = "selective-marker-123" condition: $a }
rule real_rule : test { strings: $h = { 4D 5A 90 00 } condition: helper and $h }
'''
    rules = extract_rules(sample)
    assert [name for name, _, _ in rules] == ["helper", "real_rule"]
    assert [modifier for _, _, modifier in rules] == ["private", None]
    assert mandatory_literal_present(rules[0][1])
    assert mandatory_literal_present(rules[1][1])
    assert classify_target("maldoc/test.yar", sample) == "office"
    print("self-test passed")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(dest="command", required=True)

    build = subcommands.add_parser("build-pack", help="build an immutable governed YARA pack")
    build.add_argument(
        "--source",
        action="append",
        type=parse_source_spec,
        required=True,
        help=(
            "NAME|ROOT|LICENSE_ID|LICENSE_FILE|PROVENANCE|VERSION"
            "[|QUALITY_TIER[|TARGET]]"
        ),
    )
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--pack-id", required=True)
    build.add_argument("--generation", required=True)
    build.add_argument("--min-engine-version", default="0.9.4")
    build.add_argument("--min-rules", type=int, default=10_000)
    build.add_argument("--rules-per-shard", type=int, default=1_000)
    build.add_argument("--mode", choices=("shadow", "enforce"), default="shadow")
    build.add_argument("--unsupported-module", action="append")
    build.add_argument("--exclude-glob", action="append", default=[])
    build.add_argument("--expected-libyara-version", default="4.5.5")
    build.set_defaults(function=build_pack)

    database = subcommands.add_parser("db-import", help="legacy JSON-to-PostgreSQL import")
    database.add_argument("--rules-file", type=Path, default=Path("/tmp/yara_rules_batch.json"))
    database.add_argument("--host", default="localhost")
    database.add_argument("--port", default="5433")
    database.add_argument("--user", default="vigilyx")
    database.add_argument("--database", default="vigilyx")
    database.set_defaults(function=import_db)

    check = subcommands.add_parser("self-test", help="test the conservative rule extractor")
    check.set_defaults(function=lambda _args: self_test())
    return result


def main() -> int:
    args = parser().parse_args()
    if getattr(args, "min_rules", 1) <= 0 or getattr(args, "rules_per_shard", 1) <= 0:
        raise SystemExit("rule limits must be positive")
    return args.function(args)


if __name__ == "__main__":
    raise SystemExit(main())
