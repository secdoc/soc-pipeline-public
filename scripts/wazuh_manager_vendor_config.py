#!/usr/bin/env python3
"""Pure manager-config transformation for vendor lists and hook rotation."""

LISTS = (
    "etc/lists/bash_profile",
    "etc/lists/common-ports",
    "etc/lists/malicious-powershell",
)


def add_list_entries(text):
    missing = [entry for entry in LISTS if f"<list>{entry}</list>" not in text]
    if missing:
        marker = "<ruleset>"
        if marker not in text:
            raise ValueError("manager configuration has no ruleset section")
        insertion = "\n" + "\n".join(
            f"    <list>{entry}</list>" for entry in missing
        )
        text = text.replace(marker, marker + insertion, 1)
    return text


def patch_config(text, old_hook_id, new_hook_id):
    if not old_hook_id or not new_hook_id or old_hook_id == new_hook_id:
        raise ValueError("hook identifiers must be distinct and non-empty")
    if text.count(old_hook_id) != 1:
        raise ValueError("manager configuration must contain exactly one old hook identifier")
    if new_hook_id in text:
        raise ValueError("new hook identifier already exists in manager configuration")
    return add_list_entries(text.replace(old_hook_id, new_hook_id))
