#!/usr/bin/env python3
"""Normalize renderer SVG output to a 2x audit typography floor."""

from __future__ import annotations

import argparse
from pathlib import Path
from xml.etree import ElementTree as ET


SVG_NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", SVG_NS)


def number(value: str) -> float:
    return float(value.removesuffix("px"))


def scale_svg(path: Path, factor: float) -> None:
    tree = ET.parse(path)
    root = tree.getroot()
    for attribute in ("width", "height"):
        root.set(attribute, f"{number(root.attrib[attribute]) * factor:g}")
    root.set("viewBox", " ".join(f"{float(part) * factor:g}" for part in root.attrib["viewBox"].split()))

    for text in root.iter(f"{{{SVG_NS}}}text"):
        size = text.get("font-size")
        x = text.get("x")
        y = text.get("y")
        if size and x and y:
            text.set("font-size", f"{number(size) * factor:g}")
            text.set(
                "transform",
                f"translate({x} {y}) scale({1 / factor:g}) translate(-{x} -{y})",
            )

    metadata_tags = {
        f"{{{SVG_NS}}}title",
        f"{{{SVG_NS}}}desc",
        f"{{{SVG_NS}}}defs",
    }
    visual = [child for child in list(root) if child.tag not in metadata_tags]
    group = ET.Element(f"{{{SVG_NS}}}g", {"transform": f"scale({factor:g})"})
    for child in visual:
        root.remove(child)
        group.append(child)
    root.append(group)
    tree.write(path, encoding="unicode", xml_declaration=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--factor", type=float, default=2.0)
    args = parser.parse_args()
    if args.factor <= 0:
        raise SystemExit("factor must be positive")
    scale_svg(args.path, args.factor)


if __name__ == "__main__":
    main()
