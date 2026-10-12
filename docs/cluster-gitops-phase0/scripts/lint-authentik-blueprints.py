#!/usr/bin/env python3
"""Lint Authentik blueprints so a re-apply can never revert identity data.

Authentik's blueprint importer re-saves `state: present` entries on every apply
(hourly, and on every file change), and many-to-many attrs (users, groups,
parents, roles) are REPLACED, not merged. A present user or group entry, or a
member list, therefore silently undoes edits made in the Authentik UI or in QQQ
(qbit-authentik DESIGN.md sections 2.2, 4.2 and 4.5; contract test (d)).

Rules (each violation is printed as file:entry: message):
  R1  authentik_core.user / authentik_core.group entries must be
      `state: created`, `must_created` or `absent` (no state means present).
  R2  no member lists: a group entry must not carry `users`.
  R3  an `authentik_rbac.role` entry may be `present` only if its attrs are
      limited to `permissions` (and `name`): the qbit role pattern, whose
      global permissions are re-asserted additively.
  R4  no literal secrets: password, password_hash, key, token, client_secret
      must be a YAML tag (e.g. !Env) or absent; authentik_core.token entries are
      not allowed at all.

Input: Kubernetes ConfigMap manifests (every data value that looks like a
blueprint is checked) and plain blueprint files. Usage:

  lint-authentik-blueprints.py FILE_OR_DIR...   # exit 1 on violations
  lint-authentik-blueprints.py --self-test      # run the built-in cases
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

import yaml

IDENTITY_MODELS = {"authentik_core.user", "authentik_core.group"}
SAFE_IDENTITY_STATES = {"created", "must_created", "absent"}
SECRET_KEYS = {"password", "password_hash", "key", "token", "client_secret"}
ROLE_PRESENT_ALLOWED_ATTRS = {"permissions", "name"}


class Tag:
    """Placeholder for an Authentik YAML tag such as !KeyOf, !Find or !Env."""

    def __init__(self, tag: str, value):
        self.tag = tag
        self.value = value

    def __repr__(self):
        return f"{self.tag} {self.value!r}"


class BlueprintLoader(yaml.SafeLoader):
    """SafeLoader that accepts Authentik's custom tags."""


def _construct_tag(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return Tag("!" + tag_suffix, value)


BlueprintLoader.add_multi_constructor("!", _construct_tag)


@dataclass
class Violation:
    source: str
    entry: str
    message: str

    def __str__(self):
        return f"{self.source}: {self.entry}: {self.message}"


def entry_label(index: int, entry: dict) -> str:
    identifiers = entry.get("identifiers") or {}
    ident = ", ".join(f"{k}={v}" for k, v in identifiers.items()) if isinstance(identifiers, dict) else str(identifiers)
    return f"entry {index} ({entry.get('model')} {ident})"


def lint_blueprint(source: str, document) -> list[Violation]:
    violations: list[Violation] = []
    if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
        return violations

    for index, entry in enumerate(document["entries"]):
        if not isinstance(entry, dict):
            continue
        model = entry.get("model")
        if isinstance(model, Tag):
            violations.append(Violation(source, entry_label(index, entry), "model must be a literal so it can be linted"))
            continue
        state = entry.get("state", "present")
        if isinstance(state, Tag):
            violations.append(Violation(source, entry_label(index, entry), "state must be a literal so it can be linted"))
            continue
        attrs = entry.get("attrs") or {}
        label = entry_label(index, entry)

        if model in IDENTITY_MODELS and state not in SAFE_IDENTITY_STATES:
            violations.append(Violation(source, label, f"R1 {model} must be `state: created` (got `{state}`); present entries revert UI/QQQ edits on every apply"))

        if model == "authentik_core.group" and state != "absent" and "users" in attrs:
            violations.append(Violation(source, label, "R2 member list (`users:`) on a group; memberships are data, manage them in the Authentik UI or QQQ"))

        if model == "authentik_rbac.role" and state not in SAFE_IDENTITY_STATES:
            extra = set(attrs) - ROLE_PRESENT_ALLOWED_ATTRS
            if extra:
                violations.append(Violation(source, label, f"R3 present role may only declare `permissions` (found {sorted(extra)})"))

        if model == "authentik_core.token":
            violations.append(Violation(source, label, "R4 tokens must never be declared in blueprints"))

        for key in SECRET_KEYS:
            if key in attrs and attrs[key] is not None and not isinstance(attrs[key], Tag):
                violations.append(Violation(source, label, f"R4 literal `{key}`; use !Env or set it outside git"))
    return violations


def blueprints_in_manifest(source: str, text: str):
    """Yield (source, parsed blueprint) for a file: a ConfigMap or a blueprint."""
    for document in yaml.load_all(text, Loader=BlueprintLoader):
        if not isinstance(document, dict):
            continue
        if document.get("kind") == "ConfigMap" and isinstance(document.get("data"), dict):
            for key, value in document["data"].items():
                if isinstance(value, str) and "entries:" in value and "version:" in value:
                    yield f"{source}#{key}", yaml.load(value, Loader=BlueprintLoader)
        elif "entries" in document:
            yield source, document


def lint_paths(paths: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    for path in paths:
        files = []
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                files.extend(os.path.join(root, n) for n in names if n.endswith((".yaml", ".yml")))
        else:
            files.append(path)
        for file in sorted(files):
            with open(file, encoding="utf-8") as handle:
                text = handle.read()
            if "entries:" not in text:
                continue
            try:
                for source, blueprint in blueprints_in_manifest(file, text):
                    violations.extend(lint_blueprint(source, blueprint))
            except yaml.YAMLError as error:
                violations.append(Violation(file, "-", f"YAML error: {error}"))
    return violations


SELF_TEST_GOOD = """
version: 1
entries:
  - model: authentik_rbac.role
    state: present
    identifiers: {name: qqq-x}
    attrs: {permissions: [authentik_core.view_user]}
  - model: authentik_core.user
    state: created
    identifiers: {username: sa}
    attrs: {type: service_account, roles: [!KeyOf r], groups: [!Find [authentik_core.group, [name, x]]]}
  - model: authentik_core.group
    state: created
    identifiers: {name: g}
    attrs: {attributes: {qqq.io/permissions: [a]}}
  - model: authentik_providers_oauth2.oauth2provider
    state: present
    identifiers: {name: p}
    attrs: {client_secret: !Env SECRET}
"""

SELF_TEST_BAD = {
    "present group": ("model: authentik_core.group\n    identifiers: {name: g}", "R1"),
    "present user": ("model: authentik_core.user\n    state: present\n    identifiers: {username: u}\n    attrs: {groups: [!KeyOf g]}", "R1"),
    "member list": ("model: authentik_core.group\n    state: created\n    identifiers: {name: g}\n    attrs: {users: [1]}", "R2"),
    "role with users": ("model: authentik_rbac.role\n    identifiers: {name: r}\n    attrs: {permissions: [a], users: [1]}", "R3"),
    "token": ("model: authentik_core.token\n    state: created\n    identifiers: {identifier: t}", "R4"),
    "literal secret": ("model: authentik_providers_oauth2.oauth2provider\n    identifiers: {name: p}\n    attrs: {client_secret: hunter2}", "R4"),
    "literal password": ("model: authentik_core.user\n    state: created\n    identifiers: {username: u}\n    attrs: {password: hunter2}", "R4"),
}


def self_test() -> int:
    failures = 0
    good = lint_blueprint("good", yaml.load(SELF_TEST_GOOD, Loader=BlueprintLoader))
    if good:
        failures += 1
        print("FAIL good blueprint flagged:", *good, sep="\n  ")
    for name, (entry, rule) in SELF_TEST_BAD.items():
        found = lint_blueprint(name, yaml.load(f"version: 1\nentries:\n  - {entry}\n", Loader=BlueprintLoader))
        if not any(v.message.startswith(rule) for v in found):
            failures += 1
            print(f"FAIL {name}: expected {rule}, got {[str(v) for v in found]}")
    configmap = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\ndata:\n  bad.yaml: |\n    version: 1\n    entries:\n      - model: authentik_core.group\n        identifiers: {name: g}\n"
    if not any("#bad.yaml" in v.source for v in [v for s, b in blueprints_in_manifest("cm.yaml", configmap) for v in lint_blueprint(s, b)]):
        failures += 1
        print("FAIL ConfigMap data values are not linted")
    print("self-test:", "OK" if failures == 0 else f"{failures} failure(s)")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if not argv:
        print(__doc__)
        return 2
    violations = lint_paths(argv)
    for violation in violations:
        print(violation)
    print(f"{len(violations)} violation(s)")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
