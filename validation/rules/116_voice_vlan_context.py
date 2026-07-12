class Rule:
    id = "116"
    description = "Verify voice VLAN is only configured in access port context with a corresponding access VLAN"
    severity = "HIGH"

    @classmethod
    def _iter_access_entries(cls, data):
        """Yield (name, access_vlan, voice_vlan) tuples from access_interfaces."""
        for item in data.get("access_interfaces", []):
            if isinstance(item, dict):
                name = item.get("name") or ""
                cfg = item.get("config") or item  # config may be nested or flat
                access_vlan = cfg.get("access_vlan")
                voice_vlan = cfg.get("voice_vlan")
                yield name, access_vlan, voice_vlan
            elif isinstance(item, str) and "|" in item:
                # Pipe-delimited format: name|desc|access_vlan|voice_vlan|...
                parts = item.split("|")
                name = parts[0].strip() if len(parts) > 0 else ""
                try:
                    access_vlan = int(parts[2]) if len(parts) > 2 and parts[2].strip() else None
                except (ValueError, IndexError):
                    access_vlan = None
                try:
                    voice_vlan = int(parts[3]) if len(parts) > 3 and parts[3].strip() else None
                except (ValueError, IndexError):
                    voice_vlan = None
                yield name, access_vlan, voice_vlan

    @classmethod
    def match(cls, data):
        results = []
        try:
            for name, access_vlan, voice_vlan in cls._iter_access_entries(data):
                if voice_vlan is None:
                    continue
                # Voice VLAN without a corresponding access VLAN is invalid
                if access_vlan is None:
                    results.append(
                        f"access_interfaces: {name} has voice_vlan {voice_vlan} "
                        f"but no access_vlan - voice VLAN requires an access port context"
                    )
                # Voice VLAN and access VLAN must differ
                elif voice_vlan == access_vlan:
                    results.append(
                        f"access_interfaces: {name} voice_vlan {voice_vlan} equals "
                        f"access_vlan {access_vlan} - they must be distinct VLANs"
                    )

            # Voice VLAN must not appear on uplink interfaces
            for uplink in data.get("uplinks", []):
                if not isinstance(uplink, dict):
                    continue
                if uplink.get("voice_vlan") is not None:
                    results.append(
                        f"uplinks: {uplink.get('name', 'unknown')} has voice_vlan set - "
                        f"voice VLAN is not valid on trunk/uplink interfaces"
                    )
        except KeyError as e:
            print(f"KeyError: {e}")
        return results
