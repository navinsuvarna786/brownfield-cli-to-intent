class Rule:
    id = "118"
    description = "Verify VRF names referenced by routed interfaces are defined in the VRF configuration"
    severity = "HIGH"

    # Well-known implicit VRFs that do not require an explicit definition
    _IMPLICIT_VRFS = {"default", "global", ""}

    @classmethod
    def _defined_vrf_names(cls, data):
        """Collect all VRF names that are explicitly defined in the intent model."""
        names = set()
        # Primary key: single-VRF dict (management VRF from normalizer)
        vrf_cfg = data.get("vrf_config")
        if isinstance(vrf_cfg, dict) and vrf_cfg.get("name"):
            names.add(vrf_cfg["name"])
        # Secondary key: list of VRF objects (LLM or Arista multi-VRF output)
        for v in data.get("vrfs", []):
            if isinstance(v, dict) and v.get("name"):
                names.add(v["name"])
            elif isinstance(v, str) and v.strip():
                names.add(v.strip())
        return names

    @classmethod
    def match(cls, data):
        results = []
        try:
            defined = cls._defined_vrf_names(data)
            if not defined:
                # No VRF definitions present — referential checks would be vacuous
                return results

            for intf in data.get("routed_interfaces", []):
                if not isinstance(intf, dict):
                    continue
                vrf_ref = (intf.get("vrf") or "").strip()
                if not vrf_ref or vrf_ref.lower() in cls._IMPLICIT_VRFS:
                    continue
                if vrf_ref not in defined:
                    results.append(
                        f"routed_interfaces: {intf.get('name', 'unknown')} references "
                        f"VRF '{vrf_ref}' which is not defined in vrf_config or vrfs"
                    )
        except KeyError as e:
            print(f"KeyError: {e}")
        return results
