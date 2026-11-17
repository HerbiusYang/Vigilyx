#!/usr/bin/env python3
"""Check the documentation actually present in a release Git tree."""

import argparse
import json
from pathlib import PurePosixPath
import posixpath
import re
import subprocess
from urllib.parse import unquote, urlsplit


MANIFEST = "release-docs.json"
DOCUMENT_SUFFIXES = {".md", ".markdown", ".mdx", ".rst", ".adoc", ".txt", ".pdf", ".docx", ".odt", ".ipynb"}
PRIVATE_PARTS = {".agents", ".claude", ".lotyra", ".audit", ".rollback"}
PRIVATE_NAMES = {"agents.md", "agents.local.md", "claude.md"}
MARKDOWN_LINK = re.compile(r'(?<!!)\[[^\]\n]*\]\(([^\s)]+)(?:\s+"[^"]*")?\)')
SSH_ADDRESS = re.compile(r"\bssh\s+(?:[\w.-]+@)?((?:\d{1,3}\.){3}\d{1,3})\b")


def is_document(path):
    return PurePosixPath(path).suffix.lower() in DOCUMENT_SUFFIXES


def is_private(path):
    parts = PurePosixPath(path.lower()).parts
    return (parts[0] == "docs" or bool(PRIVATE_PARTS.intersection(parts))
            or parts[-1] in PRIVATE_NAMES or parts[-1].startswith("evaluation"))


def validate_documents(paths, contents, approved):
    errors = []
    allowed = set(approved)
    if len(allowed) != len(approved):
        errors.append("duplicate entries in release-docs.json")
    for path in approved:
        if str(PurePosixPath(path)) != path or path.startswith("/") or ".." in PurePosixPath(path).parts:
            errors.append(f"invalid approved path: {path}")
        if not is_document(path) or path not in paths:
            errors.append(f"approved document is absent or invalid: {path}")
    for path in sorted(paths):
        if is_private(path):
            errors.append(f"private file in release tree: {path}")
        if not is_document(path):
            continue
        if path not in allowed:
            errors.append(f"unapproved document in release tree: {path}")
        if PurePosixPath(path).suffix.lower() not in {".md", ".markdown", ".mdx", ".rst", ".adoc", ".txt"}:
            continue
        text = contents[path]
        if re.search(r"/Users/[^/\s]+/", text) or SSH_ADDRESS.search(text):
            errors.append(f"local workstation path or hard-coded SSH address: {path}")
        if PurePosixPath(path).suffix.lower() not in {".md", ".markdown", ".mdx"}:
            continue
        for link in MARKDOWN_LINK.findall(text):
            url = urlsplit(link.strip("<>"))
            target_path = unquote(url.path)
            if url.scheme or url.netloc or not target_path:
                continue
            if PurePosixPath(target_path).suffix.lower() not in DOCUMENT_SUFFIXES:
                continue
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), target_path))
            if target not in allowed or target not in paths:
                errors.append(f"link to absent/unpublished document: {path} -> {target}")
    return errors


def git_output(*args):
    return subprocess.check_output(["git", *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="HEAD", help="Commit or tag to inspect (default: HEAD)")
    args = parser.parse_args()
    if args.ref.startswith("-"):
        parser.error("ref must be a commit or tag")
    commit = git_output("rev-parse", "--verify", f"{args.ref}^{{commit}}").decode().strip()
    manifest = json.loads(git_output("show", f"{commit}:{MANIFEST}"))
    if manifest.get("version") != 1 or not isinstance(manifest.get("files"), list):
        parser.error("unsupported release-docs.json format")
    approved = manifest["files"]
    if not all(isinstance(path, str) and path for path in approved):
        parser.error("approved paths must be non-empty strings")
    paths = {p.decode() for p in git_output("ls-tree", "-r", "-z", "--name-only", commit).split(b"\0") if p}
    contents = {path: git_output("show", f"{commit}:{path}").decode("utf-8", errors="replace")
                for path in paths if is_document(path)}
    errors = validate_documents(paths, contents, approved)
    if errors:
        print("Release documentation check failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"Release documentation check passed: {len(approved)} approved files at {commit}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
