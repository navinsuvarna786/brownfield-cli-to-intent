class Rule:
    id = "117"
    description = "Verify VLAN IDs referenced in uplink allowed-VLAN lists and access interfaces are defined in the VLAN table"
    severity = "HIGH"

    # VLANs that are always implicitly valid and need not be declared
    _RESERVED = {1, 1002, 1003, 1004, 1005}

    @classmethod
    def _defined_vlan_ids(cls, data):
        ids = set()
        for v in data.get("vlans", []):
            if isinstance(v, dict):
                try:
                    ids.add(int(v["id"]))
                except (KeyError, ValueError, TypeError):
                    pass
            elif isinstance(v, str) and "|" in v:
                try:
                    ids.add(int(v.split("|")[0]))
                except (ValueError, IndexError):
                    pass
        return ids

    @classmethod
    def match(cls, data):
        results = []
        try:
            defined = cls._defined_vlan_ids(data)
            if not defined:
                # No VLAN table present — skip referential checks
                return results

            # Check uplink allowed-VLAN lists
            for uplink in data.get("uplinks", []):
                if not isinstance(uplink, dict):
                    continue
                ul_name = uplink.get("name", "unknown")
                allowed = uplink.get("allowed_vlans", [])
                if isinstance(allowed, str):
                    # Could be comma-separated, e.g. "10,20,30"
                    allowed = [a.strip() for a in allowed.split(",") if a.strip()]
                for vid in allowed:
                    try:
                        vid_int = int(vid)
                    except (ValueError, TypeError):
                        continue
                    if vid_int in cls._RESERVED:
                        continue
                    if vid_int not in defined:
                        results.append(
                            f"uplinks: {ul_name} allowed_vlans references VLAN {vid_int} "
                            f"which is not defined in the VLAN table"
                        )

            # Check access-interface VLAN and voice VLAN references
            for item in data.get("access_interfaces", []):
                if isinstance(item, dict):
                    name = item.get("name") or "unknown"
                    cfg = item.get("config") or item
                    candidates = {
                        "access_vlan": cfg.get("access_vlan"),
                        "voice_vlan":  cfg.get("voice_vlan"),
                    }
                elif isinstance(item, str) and "|" in item:
                    parts = item.split("|")
                    name = parts[0].strip() if parts else "unknown"
                    candidates = {}
                    for label, idx in [("access_vlan", 2), ("voice_vlan", 3)]:
                        try:
                            val = int(parts[idx]) if len(parts) > idx and parts[idx].strip() else None
                        except (ValueError, IndexError):
                            val = None
                        candidates[label] = val
                else:
                    continue

                for label, vid in candidates.items():
                    if vid is None:
                        continue
                    try:
                        vid_int = int(vid)
                    except (ValueError, TypeError):
                        continue
                    if vid_int in cls._RESERVED:
                        continue
                    if vid_int not in defined:
                        results.append(
                            f"access_interfaces: {name} {label} {vid_int} "
                            f"is not defined in the VLAN table"
                        )
        except KeyError as e:
            print(f"KeyError: {e}")
        return results
