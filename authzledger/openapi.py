"""Offline OpenAPI operation discovery and explicit, reviewable contract compilation.

An API description is not an authorization policy. No expected permissions,
credentials, target origin, or object identifiers are inferred from it.
"""
from __future__ import annotations

import copy
import json
import re
from urllib.parse import quote, urlencode

from .model import ContractError, _fields, _json_value, _path, _string, load_contract

METHODS = {"get", "head", "post", "put", "patch", "delete", "options"}


def _resolve(document: dict, value: object) -> dict:
    visited = set()
    for _ in range(24):
        if not isinstance(value, dict):
            raise ContractError("OpenAPI objects must be JSON objects.")
        if "$ref" not in value:
            return value
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or "%" in ref:
            raise ContractError("Only local, unescaped OpenAPI references are supported.")
        if ref in visited:
            raise ContractError("OpenAPI reference cycle detected.")
        if set(value) - {"$ref", "summary", "description"}:
            raise ContractError("OpenAPI reference siblings cannot be merged unambiguously.")
        visited.add(ref)
        value = document
        for part in ref[2:].split("/"):
            if re.search(r"~(?![01])", part):
                raise ContractError("OpenAPI reference has an invalid pointer escape.")
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(value, dict) or part not in value:
                raise ContractError("OpenAPI reference does not resolve to an object.")
            value = value[part]
    raise ContractError("OpenAPI reference depth exceeds the supported limit.")


def _parameters(document: dict, source: object) -> dict:
    if not isinstance(source, list) or len(source) > 100:
        raise ContractError("OpenAPI parameters must be a list of at most 100 entries.")
    result = {}
    for raw in source:
        p = _resolve(document, raw)
        name = _string(p.get("name"), "OpenAPI parameter name", 128)
        location = p.get("in")
        if location not in {"path", "query", "header", "cookie"}:
            raise ContractError("OpenAPI parameter location is unsupported.")
        key = (location, name)
        if key in result:
            raise ContractError("OpenAPI parameter list contains duplicates.")
        required = p.get("required", False)
        if type(required) is not bool or (location == "path" and not required):
            raise ContractError("OpenAPI path parameters must explicitly be required.")
        schema = _resolve(document, p.get("schema", {}))
        style = p.get("style", "simple" if location in {"path", "header"} else "form")
        kind = schema.get("type")
        supported = (location in {"path", "query"} and kind in {"string", "integer", "number", "boolean"}
                     and style == ("simple" if location == "path" else "form")
                     and not p.get("allowReserved", False) and "content" not in p)
        result[key] = {"name": name, "in": location, "required": required,
                       "type": kind if isinstance(kind, str) else "complex",
                       "supported": supported}
    return result


def catalog(document: dict) -> dict:
    """Index operations without making requests or following remote references."""
    _json_value(document, "OpenAPI document")
    if not isinstance(document, dict) or not re.fullmatch(r"3\.(?:0|1)\.[0-9]+", str(document.get("openapi", ""))):
        raise ContractError("Import requires an OpenAPI 3.0 or 3.1 JSON document.")
    if len(json.dumps(document, ensure_ascii=True).encode()) > 4 * 1048576:
        raise ContractError("OpenAPI document exceeds 4 MiB.")
    paths = document.get("paths", {})
    if not isinstance(paths, dict) or len(paths) > 1000:
        raise ContractError("OpenAPI paths must be an object with at most 1000 entries.")
    operations = []
    for path, raw_item in paths.items():
        if path.startswith("x-"):
            continue
        _path(path)
        if "?" in path:
            raise ContractError("OpenAPI path templates must not include query strings.")
        slots = re.findall(r"\{([^{}]+)\}", path)
        if "{" in re.sub(r"\{[^{}]+\}", "", path) or "}" in re.sub(r"\{[^{}]+\}", "", path):
            raise ContractError("OpenAPI path template has unmatched braces.")
        item = _resolve(document, raw_item)
        inherited = _parameters(document, item.get("parameters", []))
        for method, operation in item.items():
            if method not in METHODS:
                continue
            if not isinstance(operation, dict):
                raise ContractError("OpenAPI operation must be an object.")
            parameters = dict(inherited)
            parameters.update(_parameters(document, operation.get("parameters", [])))
            if set(slots) != {name for location, name in parameters if location == "path"}:
                raise ContractError("OpenAPI path parameters do not match the template.")
            security = operation.get("security", document.get("security", []))
            if (not isinstance(security, list) or len(security) > 100
                    or any(not isinstance(rule, dict) or any(not isinstance(scopes, list)
                        or any(not isinstance(scope, str) for scope in scopes) for scopes in rule.values()) for rule in security)):
                raise ContractError("OpenAPI security requirements are malformed.")
            body = _resolve(document, operation.get("requestBody", {}))
            body_required = body.get("required", False)
            if type(body_required) is not bool:
                raise ContractError("OpenAPI requestBody.required must be boolean.")
            operations.append({
                "key": method.upper() + " " + path, "method": method.upper(), "path": path,
                "operation_id": _string(operation.get("operationId", method + " " + path), "operationId", 8192),
                "summary": _string(operation.get("summary") or "No summary supplied", "operation summary", 2000),
                "parameters": list(parameters.values()), "security": copy.deepcopy(security),
                "body_required": body_required,
                "json_body_supported": "application/json" in body.get("content", {}) if isinstance(body.get("content", {}), dict) else False,
                "mutating": method not in {"get", "head", "options"},
            })
            if len(operations) > 1000:
                raise ContractError("OpenAPI operation count exceeds 1000.")
    info = document.get("info", {})
    return {"openapi": document["openapi"], "title": _string(info.get("title", "API") if isinstance(info, dict) else "API", "API title"),
            "operations": operations, "operation_count": len(operations),
            "notice": "Permissions must be supplied by the operator. Server URLs, remote references, callbacks and webhooks are never executed."}


def compile_contract(document: dict, config: dict, *, allow_mutations: bool = False) -> dict:
    """Turn selected operations, fixture values and explicit policy into a contract."""
    _json_value(config, "import configuration")
    _fields(config, {"name", "target", "base_path", "identities", "selections", "limits"}, "import configuration",
            {"name", "target", "identities", "selections"})
    indexed = {op["key"]: op for op in catalog(document)["operations"]}
    prefix = config.get("base_path", "")
    if not isinstance(prefix, str) or (prefix and (not prefix.startswith("/") or prefix.endswith("/") or any(c in prefix for c in "?{}"))):
        raise ContractError("base_path must be empty or an absolute path without a trailing slash.")
    if prefix:
        _path(prefix)
    selections = config["selections"]
    if not isinstance(selections, list) or not 1 <= len(selections) <= 1000:
        raise ContractError("Select between 1 and 1000 explicit authorization cases.")
    cases = []
    for selection in selections:
        _fields(selection, {"operation", "id", "identity", "parameters", "expect", "requires", "body", "headers"},
                "operation selection", {"operation", "id", "identity", "expect"})
        if not isinstance(selection["operation"], str) or selection["operation"] not in indexed:
            raise ContractError("Selected operation is not present in the OpenAPI catalog.")
        op = indexed[selection["operation"]]
        supplied = selection.get("parameters", {})
        _fields(supplied, {"path", "query"}, "parameter values")
        declared = {(p["in"], p["name"]): p for p in op["parameters"]}
        for location, values in supplied.items():
            if not isinstance(values, dict) or any((location, name) not in declared for name in values):
                raise ContractError("Parameter values contain unknown names.")
        path_values, query = {}, []
        for p in op["parameters"]:
            values = supplied.get(p["in"], {})
            if p["name"] not in values:
                if p["required"]:
                    raise ContractError("A required operation parameter needs an explicit supported fixture value.")
                continue
            if not p["supported"]:
                raise ContractError("Complex, header and cookie parameters require a hand-reviewed contract.")
            value = values[p["name"]]
            valid = {"string": isinstance(value, str), "integer": type(value) is int,
                     "number": type(value) in {int, float}, "boolean": type(value) is bool}.get(p["type"], False)
            if not valid:
                raise ContractError("Parameter value does not match its declared primitive type.")
            encoded = str(value).lower() if type(value) is bool else str(value)
            if len(encoded) > 4096:
                raise ContractError("Parameter fixture value is too long.")
            if p["in"] == "path":
                if not encoded:
                    raise ContractError("Path parameter values must not be empty.")
                path_values[p["name"]] = quote(encoded, safe="")
            else:
                query.append((p["name"], encoded))
        path = prefix + re.sub(r"\{([^{}]+)\}", lambda match: path_values[match[1]], op["path"])
        if query:
            path += "?" + urlencode(query, quote_via=quote)
        if op["body_required"] and "body" not in selection:
            raise ContractError("Selected operation requires an explicit request body.")
        if "body" in selection and not op["json_body_supported"]:
            raise ContractError("Only explicitly declared application/json request bodies can be compiled.")
        case = {key: copy.deepcopy(selection[key]) for key in ("id", "identity", "expect", "requires", "body", "headers") if key in selection}
        case.update(method=op["method"], path=path)
        cases.append(case)
    contract = {key: copy.deepcopy(config[key]) for key in ("name", "target", "identities", "limits") if key in config}
    contract.update(version=1, cases=cases)
    return load_contract(contract, allow_mutations=allow_mutations)
