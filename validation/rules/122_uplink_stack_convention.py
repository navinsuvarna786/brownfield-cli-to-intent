import re as _re


class Rule:
    id = "122"
    description = (
        "Uplink stack convention: for stacked devices each port-channel uplink must contain "
        "only the first uplink port (port index 1) on the first switch and the first uplink port "
        "on the last switch in the stack. Extra member interfaces must be removed."
    )
    severity = "HIGH"

    _INTF_RE = _re.compile(
        r'(?:TenGigabitEthernet|Te)(\d+)/(\d+)/(\d+)', _re.IGNORECASE
    )

    @classmethod
    def _switch_numbers(cls, stack_info):
        """Return sorted list of switch numbers from stack_info."""
        switches_raw = stack_info.get("switches", [])
        if switches_raw:
            first = switches_raw[0]
            if isinstance(first, (list, tuple)):
                return sorted(int(s[0]) for s in switches_raw)
            if isinstance(first, (int, float)):
                return sorted(int(s) for s in switches_raw)
        member_count = stack_info.get("member_count", 1)
        return list(range(1, member_count + 1))

    @classmethod
    def match(cls, data):
        results = []

        stack_info = data.get("stack_info") or {}
        if not isinstance(stack_info, dict):
            return results
        if not stack_info.get("is_stack"):
            return results
        member_count = stack_info.get("member_count", 1)
        if member_count < 2:
            return results

        switch_numbers = cls._switch_numbers(stack_info)
        first_sw = switch_numbers[0]
        last_sw = switch_numbers[-1]

        for ul in data.get("uplinks", []):
            if not isinstance(ul, dict):
                continue
            if ul.get("type") != "port-channel":
                continue

            pc_id = ul.get("port_channel_id") or ul.get("name") or "?"
            pc_label = f"Port-channel{pc_id}" if str(pc_id).isdigit() else str(pc_id)
            members = ul.get("member_interfaces", [])
            if not members:
                continue

            extra = []
            for m in members:
                name = m.get("name", "") if isinstance(m, dict) else str(m)
                match = cls._INTF_RE.search(name)
                if not match:
                    continue
                sw, _mod, port = int(match.group(1)), int(match.group(2)), int(match.group(3))
                # Valid: switch must be first or last, and port index must be 1
                if not (sw in (first_sw, last_sw) and port == 1):
                    extra.append(name)

            if extra:
                expected = [
                    f"TenGigabitEthernet{first_sw}/1/1",
                    f"TenGigabitEthernet{last_sw}/1/1",
                ]
                results.append(
                    f"uplinks: {pc_label} has extra member_interfaces {extra} for a "
                    f"{member_count}-switch stack - member_interfaces must contain only "
                    f"the first uplink port on the first and last switch: {expected}. "
                    f"Remove {extra} from member_interfaces."
                )

        return results
