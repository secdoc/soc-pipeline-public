#!/usr/bin/env python3
"""Build a collision-safe SOCFortress Wazuh rules bundle.

Vendor XML is never committed by this helper. It produces a temporary deployment
bundle plus a manifest containing source commit, hashes, dependencies, and any
rule-ID remaps.
"""

import argparse
import collections
import hashlib
import json
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

RULE_ID = re.compile(r'(<rule\s+[^>]*\bid=["\'])(\d+)(["\'])')
RULE_OPEN = re.compile(r'<rule\b[^>]*\bid=["\']\d+["\'][^>]*>')
RULE_BLOCK = re.compile(r'<rule\b[^>]*>.*?</rule>', re.DOTALL)
REFERENCE = re.compile(r'<(if_sid|if_matched_sid)>([^<]+)</\1>')
LIST_REF = re.compile(r'<list[^>]*>([^<]+)</list>')
GROUP_ALIASES = {"sysmon_event_7": "sysmon_event7"}
VENDOR_GROUP = "socfortress_vendor"


def _rule_ids(text):
    return [int(match.group(2)) for match in RULE_ID.finditer(text)]


def _safe_name(path, source, rule_ids):
    relative = str(path.relative_to(source).with_suffix(""))
    prefix = f"{min(rule_ids):06d}" if rule_ids else "decoder"
    return prefix + "_socfortress__" + re.sub(r"[^A-Za-z0-9._-]+", "_", relative) + ".xml"


def _rewrite(text, remap):
    def rule_open(match):
        tag = match.group()
        found = RULE_ID.search(tag)
        if found is None:
            raise ValueError("rule opening tag has no numeric ID")
        original = int(found.group(2))
        tag = RULE_ID.sub(
            lambda item: item.group(1) + str(remap.get(original, original)) + item.group(3),
            tag,
            count=1,
        )
        if original in remap:
            tag = re.sub(r"\s+overwrite=[\"'][^\"']+[\"']", "", tag)
        return tag

    def reference(match):
        value = re.sub(
            r"\d+",
            lambda found: str(remap.get(int(found.group()), int(found.group()))),
            match.group(2),
        )
        return f"<{match.group(1)}>{value}</{match.group(1)}>"

    rewritten = REFERENCE.sub(reference, RULE_OPEN.sub(rule_open, text))
    for old, new in GROUP_ALIASES.items():
        rewritten = rewritten.replace(f"<if_group>{old}</if_group>", f"<if_group>{new}</if_group>")
    def group_name(match):
        names = [name for name in match.group(2).split(",") if name]
        if VENDOR_GROUP not in names:
            names.append(VENDOR_GROUP)
        return match.group(1) + ",".join(names) + "," + match.group(3)
    rewritten = re.sub(r'(<group\s+name=["\'])([^"\']*)(["\'])', group_name, rewritten)
    return rewritten


def _exclude_unresolved(texts, upstream_ids, existing_ids):
    dependencies = {}
    blocks = {}
    for path, text in texts.items():
        for match in RULE_BLOCK.finditer(text):
            block = match.group()
            ids = _rule_ids(block)
            if len(ids) != 1:
                continue
            rule_id = ids[0]
            refs = {
                int(value)
                for _kind, content in REFERENCE.findall(block)
                for value in re.findall(r"\d+", content)
            }
            dependencies[rule_id] = refs
            blocks[rule_id] = (path, block)
    available = set(existing_ids) | set(upstream_ids)
    excluded = {}
    changed = True
    while changed:
        changed = False
        for rule_id, refs in dependencies.items():
            if rule_id in excluded:
                continue
            missing = sorted(ref for ref in refs if ref not in available)
            if missing:
                excluded[rule_id] = missing
                available.discard(rule_id)
                changed = True
    result = dict(texts)
    for rule_id in excluded:
        path, block = blocks[rule_id]
        result[path] = result[path].replace(block, "")
    return result, excluded


def build_bundle(source, output, existing_ids, allow_unlicensed=False, commit=None):
    source = Path(source)
    output = Path(output)
    license_files = [
        path for path in source.iterdir()
        if path.is_file() and path.name.lower().startswith(("license", "copying"))
    ]
    if not license_files and not allow_unlicensed:
        raise ValueError("upstream source has no license file; explicit acknowledgment required")
    if output.exists():
        raise ValueError("output directory already exists")

    xml_files = sorted(path for path in source.rglob("*.xml") if ".git" not in path.parts)
    definitions = collections.defaultdict(list)
    texts = {}
    for path in xml_files:
        text = path.read_text(errors="strict")
        texts[path] = text
        for rule_id in _rule_ids(text):
            definitions[rule_id].append(str(path.relative_to(source)))
    duplicates = {rule_id: paths for rule_id, paths in definitions.items() if len(paths) > 1}
    if duplicates:
        raise ValueError(f"upstream contains duplicate rule IDs: {duplicates}")

    upstream_ids = set(definitions)
    texts, excluded = _exclude_unresolved(texts, upstream_ids, set(existing_ids))
    collisions = sorted(upstream_ids & set(existing_ids))
    occupied = set(existing_ids) | upstream_ids
    remap = {}
    candidate = 910000
    for original in collisions:
        while candidate in occupied or candidate in remap.values():
            candidate += 1
        if candidate > 999999:
            raise ValueError("no collision-free Wazuh rule IDs remain")
        remap[original] = candidate
        candidate += 1

    (output / "rules").mkdir(parents=True)
    (output / "decoders").mkdir()
    (output / "lists").mkdir()
    file_records = []
    list_dependencies = set()
    for path, original in texts.items():
        rewritten = _rewrite(original, remap)
        try:
            ET.fromstring("<wazuh_bundle>" + rewritten + "</wazuh_bundle>")
        except ET.ParseError as error:
            raise ValueError(
                f"invalid Wazuh XML in {path.relative_to(source)}: {error}"
            ) from error
        rewritten_ids = _rule_ids(rewritten)
        has_rule = bool(rewritten_ids)
        has_decoder = "<decoder" in rewritten
        if not has_rule and not has_decoder:
            continue
        if has_rule and has_decoder:
            raise ValueError(f"mixed rule and decoder XML is unsupported: {path}")
        destination_root = output / ("rules" if has_rule else "decoders")
        destination = destination_root / _safe_name(path, source, _rule_ids(original))
        destination.write_text(rewritten)
        file_records.append({
            "source": str(path.relative_to(source)),
            "destination": str(destination.relative_to(output)),
            "sha256": hashlib.sha256(rewritten.encode()).hexdigest(),
        })
        list_dependencies.update(value.strip() for value in LIST_REF.findall(rewritten))

    list_records = []
    all_source_files = [path for path in source.rglob("*") if path.is_file() and ".git" not in path.parts]
    for reference in sorted(list_dependencies):
        name = Path(reference).name
        candidates = [path for path in all_source_files if path.name == name and path.suffix != ".xml"]
        if len(candidates) != 1:
            raise ValueError(f"list dependency {reference!r} resolved to {len(candidates)} files")
        destination = output / "lists" / name
        shutil.copyfile(candidates[0], destination)
        list_records.append({
            "reference": reference,
            "source": str(candidates[0].relative_to(source)),
            "destination": str(destination.relative_to(output)),
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        })

    manifest = {
        "source_repository": "https://github.com/socfortress/Wazuh-Rules",
        "source_commit": commit,
        "license_file_present": bool(license_files),
        "unlicensed_source_acknowledged": bool(allow_unlicensed and not license_files),
        "xml_files": len(xml_files),
        "rule_files": sum(1 for record in file_records if record["destination"].startswith("rules/")),
        "decoder_files": sum(1 for record in file_records if record["destination"].startswith("decoders/")),
        "rule_ids": len(upstream_ids) - len(excluded),
        "remapped_rule_ids": {str(key): value for key, value in sorted(remap.items())},
        "excluded_unresolved_rules": {str(key): value for key, value in sorted(excluded.items())},
        "normalized_group_aliases": GROUP_ALIASES,
        "vendor_group": VENDOR_GROUP,
        "files": file_records,
        "lists": list_records,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--existing-ids", required=True, help="JSON array of live rule IDs")
    parser.add_argument("--commit")
    parser.add_argument("--acknowledge-unlicensed-source", action="store_true")
    args = parser.parse_args()
    existing = {int(value) for value in json.loads(Path(args.existing_ids).read_text())}
    manifest = build_bundle(
        Path(args.source),
        Path(args.output),
        existing,
        allow_unlicensed=args.acknowledge_unlicensed_source,
        commit=args.commit,
    )
    print(json.dumps({
        "output": args.output,
        "rule_files": manifest["rule_files"],
        "decoder_files": manifest["decoder_files"],
        "rule_ids": manifest["rule_ids"],
        "remapped": len(manifest["remapped_rule_ids"]),
        "lists": len(manifest["lists"]),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
