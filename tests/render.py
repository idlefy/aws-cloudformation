"""Minimal CloudFormation intrinsic-function evaluator for tests.

Supports what the Idlefy templates use: Ref, Sub (both forms), Join, Select,
Split, If, Equals, And, Not, Condition, GetAtt (as a placeholder string) and
AWS::NoValue removal; resources and outputs whose Condition is false are
dropped; Rules (RuleCondition + Assertions) are checked by rule_violations().
A parameter the template does not declare is an error (a misspelt name would
otherwise render the default). Not a general CloudFormation engine.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

import yaml

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
ACCOUNT_ID = "123456789012"
REGION = "us-east-1"
STACK_NAME = "Idlefy-Provision"


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


def parse_template(text: str) -> dict:
    return yaml.load(text, Loader=_Loader)


def load_template(name: str) -> dict:
    return parse_template((TEMPLATES / name).read_text())


class Renderer:
    def __init__(self, template: dict, params: Mapping[str, Any]):
        self.template = template
        unknown = sorted(set(params) - set(template.get("Parameters", {})))
        if unknown:
            raise ValueError(f"parameters the template does not declare: {', '.join(unknown)}")
        self.params = dict(params)
        for pname, pdef in template.get("Parameters", {}).items():
            if pname not in self.params and "Default" in pdef:
                self.params[pname] = pdef["Default"]
        for pname, pdef in template.get("Parameters", {}).items():
            if pdef.get("Type") == "CommaDelimitedList" and isinstance(self.params.get(pname), str):
                self.params[pname] = [p.strip() for p in self.params[pname].split(",")]
        self.conditions: dict[str, bool] = {}
        self._resolving: set[str] = set()
        for cname in template.get("Conditions", {}):
            self.condition(cname)

    def condition(self, name: str) -> bool:
        """A named condition, resolved on first use (a condition may refer to one declared later)."""
        if name not in self.conditions:
            if name in self._resolving:
                raise ValueError(f"condition {name} refers to itself")
            self._resolving.add(name)
            self.conditions[name] = bool(self.evaluate(self.template["Conditions"][name]))
            self._resolving.discard(name)
        return self.conditions[name]

    # -- pseudo / refs -----------------------------------------------------
    def ref(self, name: str) -> Any:
        if name == "AWS::AccountId":
            return ACCOUNT_ID
        if name == "AWS::Region":
            return REGION
        if name == "AWS::StackName":
            return STACK_NAME
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
        if name == "And":
            return all(bool(self.evaluate(x)) for x in raw)
        if name == "Not":
            (value,) = raw
            return not self.evaluate(value)
        if name == "Condition":
            return self.condition(raw)
        if name == "If":
            cond, yes, no = raw
            return self.evaluate(yes) if self.condition(cond) else self.evaluate(no)
        if name == "GetAtt":
            res, attr = raw if isinstance(raw, list) else raw.split(".")
            return f"<getatt:{res}.{attr}>"
        raise NotImplementedError(name)

    def resources(self) -> dict[str, dict]:
        out = {}
        for rname, rdef in self.template["Resources"].items():
            cond = rdef.get("Condition")
            if cond and not self.condition(cond):
                continue
            out[rname] = self.evaluate(rdef)
        return out

    def outputs(self) -> dict[str, Any]:
        """Output name -> evaluated Value; outputs whose Condition is false are dropped."""
        out = {}
        for oname, odef in self.template.get("Outputs", {}).items():
            cond = odef.get("Condition")
            if cond and not self.condition(cond):
                continue
            out[oname] = self.evaluate(odef["Value"])
        return out

    def rule_violations(self) -> list[str]:
        """Names of the Rules whose RuleCondition holds (or is absent) and an Assertion fails."""
        out = []
        for rname, rdef in self.template.get("Rules", {}).items():
            if "RuleCondition" in rdef and not self.evaluate(rdef["RuleCondition"]):
                continue
            if not all(self.evaluate(a["Assert"]) for a in rdef["Assertions"]):
                out.append(rname)
        return out


_NOVALUE = object()


def render(template: str, params: Mapping[str, str]) -> dict:
    """The resources of templates/<template> as CloudFormation would create them for params."""
    return Renderer(load_template(template), params).resources()


def outputs(template: str, params: Mapping[str, str]) -> dict[str, Any]:
    return Renderer(load_template(template), params).outputs()


def rule_violations(template: str, params: Mapping[str, str]) -> list[str]:
    return Renderer(load_template(template), params).rule_violations()


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
