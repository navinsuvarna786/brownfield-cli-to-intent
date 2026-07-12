class Rule:
    id = "120"
    description = "Verify spanning-tree portfast is not enabled on uplink/trunk interfaces"
    severity = "MEDIUM"

    @classmethod
    def _uplink_names(cls, data):
        """Return a set of interface names that are classified as uplinks."""
        names = set()
        for ul in data.get("uplinks", []):
            if not isinstance(ul, dict):
                continue
            # Primary uplink name (Port-channel or physical trunk)
            if ul.get("name"):
                names.add(ul["name"].strip())
            # Member interfaces (physical ports bonded into a port-channel)
            for member in ul.get("member_interfaces", []):
                if isinstance(member, dict) and member.get("name"):
                    names.add(member["name"].strip())
                elif isinstance(member, str) and member.strip():
                    names.add(member.strip())
        return names

    @classmethod
    def match(cls, data):
        results = []
        try:
            uplink_names = cls._uplink_names(data)
            if not uplink_names:
                return results

            for item in data.get("access_interfaces", []):
                name = ""
                portfast = False

                if isinstance(item, dict):
                    name = (item.get("name") or "").strip()
                    cfg = item.get("config") or item
                    portfast = bool(cfg.get("portfast", False))
                elif isinstance(item, str) and "|" in item:
                    parts = item.split("|")
                    name = parts[0].strip() if parts else ""
                    # Pipe format: name|desc|access_vlan|voice_vlan|port_sec|sec_max|sec_viol|portfast|...
                    # portfast is at index 7
                    try:
                        portfast_val = parts[7].strip().lower() if len(parts) > 7 else "true"
                        portfast = portfast_val not in ("false", "0", "")
                    except IndexError:
                        portfast = True  # template default is portfast=true

                if not name:
                    continue

                if name in uplink_names and portfast:
                    results.append(
                        f"access_interfaces: {name} has spanning-tree portfast enabled "
                        f"but is also classified as an uplink/trunk interface - "
                        f"portfast must not be configured on uplink ports"
                    )
        except KeyError as e:
            print(f"KeyError: {e}")
        return results
