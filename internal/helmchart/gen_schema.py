#!/usr/bin/env python3
"""Regenerates the shape charts' values.schema.json from their values.yaml.

Every key of values.yaml appears in the schema and unknown keys fail at
render time (additionalProperties: false at every sealed level). Maps whose
keys belong to the consumer (resources, digest maps, selectors, annotations)
stay open. Run after editing a chart's values.yaml; chart tests assert the
checked-in schema matches regeneration.
"""
import json
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).parent
CHARTS = ["pod", "node-cloud", "node-metal", "node-image"]

OPEN_MAPS = {
    "operator.resources", "operator.podAnnotations", "cds.resources",
    "cds.node.selector", "ratlsMesh.resources", "ratlsMesh.nodeSelector",
    "ratlsMesh.iptablesSync.resources", "ratlsMesh.iptablesCleanup.resources",
    "tlsLb.allowlist.resources", "tlsLb.attest.resources",
    "tlsLb.nginx.resources", "tlsLb.strategy", "tlsLb.service.annotations",
    "nriImagePolicy.resources", "nriImagePolicy.bootstrapAllowlist.digests",
    "nriImagePolicy.bootstrapAllowlist.workloads", "volumed.resources",
    "volumed.nodeSelector", "attestationApi.resources",
    "attestationApi.proxy.resources", "kata.resources", "kata.nodeSelector",
    "kata.snpNodeSelector", "kata.tdxNodeSelector", "kata.guestImage.resources",
    "kata.gpu.guestImage.resources", "kata.gpu.sandboxDevicePlugin.resources",
    "webhook.annotations", "hostNamespacePolicy.exemptNamespaces",
}
ENUMS = {
    "distro": ["k8s", "rke2"],
    "nriImagePolicy.policy.mode": ["fail-closed", "audit"],
    "ratlsMesh.certMode": ["self-signed", "cds"],
}
# platform is per-chart: only node-cloud accepts the Azure vTPM platforms.
PLATFORM_ENUMS = {
    "pod": ["snp", "tdx"],
    "node-cloud": ["snp", "tdx", "az-snp", "az-tdx"],
    "node-metal": ["snp", "tdx"],
    "node-image": ["snp", "tdx"],
}

COMMENT = (
    "Sealed: every key of values.yaml appears here and unknown keys fail at "
    "render time. Leaf types stay unconstrained except where noted; maps whose "
    "keys belong to the consumer (resources, digests, workloads, annotations, "
    "selectors) are left open. Regenerate with internal/helmchart/gen_schema.py."
)


def gen_props(values: dict, path: str = "", chart: str = "") -> dict:
    props = {}
    for key, val in values.items():
        full = f"{path}.{key}" if path else key
        if isinstance(val, dict) and full not in OPEN_MAPS:
            props[key] = {
                "type": ["object", "null"],
                "additionalProperties": False,
                "properties": gen_props(val, full, chart),
            }
        else:
            leaf = {}
            if full == "platform":
                leaf["enum"] = PLATFORM_ENUMS[chart]
            elif full in ENUMS:
                leaf["enum"] = ENUMS[full]
            props[key] = leaf
    return props


def main() -> int:
    rc = 0
    for chart in CHARTS:
        values = yaml.safe_load((HERE / chart / "values.yaml").read_text())
        schema = {
            "$schema": "https://json-schema.org/draft-07/schema#",
            "$comment": COMMENT,
            "type": "object",
            "additionalProperties": False,
            "properties": {**gen_props(values, chart=chart), "c8s-lib": {}, "global": {}},
        }
        out = HERE / chart / "values.schema.json"
        rendered = json.dumps(schema, indent=2) + "\n"
        if "--check" in sys.argv:
            if out.read_text() != rendered:
                print(f"{out}: stale, rerun gen_schema.py", file=sys.stderr)
                rc = 1
        else:
            out.write_text(rendered)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
