"""Minimal CloudFormation intrinsic-function evaluator for tests.

Supports what the Idlefy templates use: Ref, Sub (both forms), Join, Select,
Split, If, Equals, GetAtt (as a placeholder string) and AWS::NoValue removal.
Not a general CloudFormation engine.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


class _Tag:
    def __init__(self, name: str, value: Any):
        self.name = name
        self.value = value


def _construct(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> _Tag:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return _Tag(tag_suffix, value)


# Subclass of SafeLoader: only the CloudFormation "!Fn" tags below are constructed, no python objects.
class _Loader(yaml.SafeLoader):
    pass


_Loader.add_multi_constructor("!", _construct)


def load_template(name: str) -> dict:
    return yaml.load((TEMPLATES / name).read_text(), Loader=_Loader)


class Renderer:
    def __init__(self, template: dict, params: dict[str, Any]):
        self.template = template
        self.params = dict(params)
        for pname, pdef in template.get("Parameters", {}).items():
            if pname not in self.params and "Default" in pdef:
                self.params[pname] = pdef["Default"]
        for pname, pdef in template.get("Parameters", {}).items():
            if pdef.get("Type") == "CommaDelimitedList" and isinstance(self.params.get(pname), str):
                self.params[pname] = [p.strip() for p in self.params[pname].split(",")]
        self.conditions = {
            cname: self.evaluate(cdef) for cname, cdef in template.get("Conditions", {}).items()
        }

    # -- pseudo / refs -----------------------------------------------------
    def ref(self, name: str) -> Any:
        if name == "AWS::AccountId":
            return ACCOUNT_ID
        if name == "AWS::Region":
            return REGION
        if name == "AWS::NoValue":
            return _NOVALUE
        if name in self.params:
            return self.params[name]
        if name in self.template.get("Resources", {}):
            return f"<ref:{name}>"
        raise KeyError(name)

    # -- evaluator ---------------------------------------------------------
    def evaluate(self, node: Any) -> Any:
        if isinstance(node, _Tag):
            return self._intrinsic(node.name, node.value)
        if isinstance(node, dict):
            if len(node) == 1:
                (k, v), = node.items()
                if k == "Ref":
                    return self.ref(v)
                if k.startswith("Fn::"):
                    return self._intrinsic(k[4:], v)
            out = {}
            for k, v in node.items():
                ev = self.evaluate(v)
                if ev is not _NOVALUE:
                    out[k] = ev
            return out
        if isinstance(node, list):
            return [ev for ev in (self.evaluate(v) for v in node) if ev is not _NOVALUE]
        return node

    def _intrinsic(self, name: str, raw: Any) -> Any:
        if name == "Ref":
            return self.ref(raw)
        if name == "Sub":
            if isinstance(raw, list):
                text, variables = raw[0], {k: self.evaluate(v) for k, v in raw[1].items()}
            else:
                text, variables = raw, {}
            return re.sub(
                r"\$\{([^}]+)\}",
                lambda m: str(variables[m.group(1)]) if m.group(1) in variables else str(self.ref(m.group(1))),
                text,
            )
        if name == "Join":
            sep, items = raw
            return sep.join(str(x) for x in self.evaluate(items))
        if name == "Select":
            idx, items = raw
            return self.evaluate(items)[int(idx)]
        if name == "Split":
            sep, value = raw
            return str(self.evaluate(value)).split(sep)
        if name == "Equals":
            a, b = (self.evaluate(x) for x in raw)
            return a == b
        if name == "If":
            cond, yes, no = raw
            return self.evaluate(yes) if self.conditions[cond] else self.evaluate(no)
        if name == "GetAtt":
            res, attr = raw if isinstance(raw, list) else raw.split(".")
            return f"<getatt:{res}.{attr}>"
        raise NotImplementedError(name)

    def resources(self) -> dict[str, dict]:
        out = {}
        for rname, rdef in self.template["Resources"].items():
            cond = rdef.get("Condition")
            if cond and not self.conditions[cond]:
                continue
            out[rname] = self.evaluate(rdef)
        return out


_NOVALUE = object()


def policy_documents(resources: dict[str, dict]) -> dict[str, dict]:
    """Return every policy document in the rendered resources, keyed by a stable path."""
    docs: dict[str, dict] = {}
    for rname, res in resources.items():
        props = res["Properties"]
        if "AssumeRolePolicyDocument" in props:
            doc = props["AssumeRolePolicyDocument"]
            docs[f"{rname}.AssumeRolePolicyDocument"] = json.loads(doc) if isinstance(doc, str) else doc
        for pol in props.get("Policies", []):
            docs[f"{rname}.Policies.{pol['PolicyName']}"] = pol["PolicyDocument"]
        if "PolicyDocument" in props:
            docs[f"{rname}.PolicyDocument"] = props["PolicyDocument"]
    return docs
