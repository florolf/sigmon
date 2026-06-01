from dataclasses import dataclass
from pathlib import Path

import ckdl

from .utils import sha256

DEFAULT_TEMPLATE = ''

@dataclass
class Hook:
    kind: str # "match" or "leaf_info"
    name: str
    params: dict[str, str]


@dataclass
class KeyEntry:
    keyhash: bytes
    key: bytes | None
    name: str
    attrs: dict[str, str]
    hooks: list[Hook]


def _parse_hook(node) -> Hook:
    params = {}

    for child in node.children:
        params[child.name] = child.args[0]

    return Hook(kind=node.name, name=node.args[0], params=params)


Template = tuple[list[Hook], dict[str, str]]


def _parse_node(node, templates: dict[str, Template], strict: bool = False) -> Template:
    hooks = []
    attrs = {}

    for child in node.children:
        match child.name:
            case 'match' | 'leaf_info':
                hooks.append(_parse_hook(child))

            case 'inherit':
                name = child.args[0]
                if name not in templates:
                    raise ValueError(f"unknown template '{name}'")

                t_hooks, t_attrs = templates[name]
                hooks.extend(t_hooks)
                attrs.update(t_attrs)

            case 'attr':
                attrs[child.args[0]] = child.args[1]

            case _:
                if strict:
                    raise ValueError(f"unexpected node '{child.name}' in {node.name}")

    return hooks, attrs


def load_config(path: Path) -> dict[bytes, KeyEntry]:
    doc = ckdl.parse(path.read_text())

    templates: dict[str, tuple[list[Hook], dict[str, str]]] = {}
    entries: dict[bytes, KeyEntry] = {}

    for node in doc.nodes:
        match node.name:
            case 'template':
                name = node.args[0] if node.args else DEFAULT_TEMPLATE
                if name in templates:
                    raise ValueError(f"duplicate template '{name}'")

                templates[name] = _parse_node(node, templates, strict=True)

            case 'key' | 'keyhash':
                name = node.args[0]
                inherit_default = True

                for child in node.children:
                    match child.name:
                        case 'alias':
                            name = child.args[0]
                        case 'no-inherit' | 'inherit':
                            inherit_default = False
                        case 'match' | 'leaf_info' | 'attr':
                            pass  # handled below
                        case _:
                            raise ValueError(f"unexpected node '{child.name}' in {node.name} '{node.args[0]}'")

                hooks, attrs = _parse_node(node, templates)

                if inherit_default and DEFAULT_TEMPLATE in templates:
                    t_hooks, t_attrs = templates[DEFAULT_TEMPLATE]
                    hooks.extend(t_hooks)
                    attrs.update(t_attrs)


                raw = bytes.fromhex(node.args[0])
                if len(raw) != 32:
                    raise ValueError(f"{node.name} '{node.args[0]}' has wrong length, expected 32, got {len(node.args[0])}")

                if node.name == 'keyhash':
                    keyhash, key = raw, None
                else:
                    keyhash, key = sha256(raw), raw

                if keyhash in entries:
                    raise ValueError(f"duplicate key hash {keyhash.hex()}")

                entries[keyhash] = KeyEntry(keyhash=keyhash, key=key, name=name, attrs=attrs, hooks=hooks)

            case _:
                raise ValueError(f"unexpected top-level node '{node.name}'")

    return entries
