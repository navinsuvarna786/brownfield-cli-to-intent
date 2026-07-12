class Rule:
    id = "115"
    description = "Verify routed interfaces are not also classified as access interfaces (role conflict)"
    severity = "HIGH"

    @classmethod
    def _access_interface_names(cls, data):
        """Return a set of interface names from access_interfaces (handles dict or pipe-string items)."""
        names = set()
        for item in data.get("access_interfaces", []):
            if isinstance(item, dict):
                name = item.get("name") or ""
                if name:
                    names.add(name.strip())
            elif isinstance(item, str) and "|" in item:
                # Pipe-delimited: first field is interface name
                names.add(item.split("|")[0].strip())
        return names

    @classmethod
    def match(cls, data):
        results = []
        try:
            routed = data.get("routed_interfaces", [])
            access_names = cls._access_interface_names(data)

            for intf in routed:
                if not isinstance(intf, dict):
                    continue
                name = (intf.get("name") or "").strip()
                if not name:
                    continue
                if name in access_names:
                    results.append(
                        f"Interface {name} is present in both routed_interfaces and "
                        f"access_interfaces - conflicting role assignment"
                    )
        except KeyError as e:
            print(f"KeyError: {e}")
        return results
