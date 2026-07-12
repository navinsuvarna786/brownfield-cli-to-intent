"""
Deterministic Arista EOS Config Parser.

Extracts structured data from an Arista EOS running-config (show running-config)
and produces the same intermediate format as the Cisco legacy parser, so the
downstream normalizer/generator pipeline works identically.
"""
import re
from typing import Dict, Any, List, Optional


class AristaEOSParser:
    """Regex-based parser for Arista EOS running-configs."""

    def __init__(self, config_text: str):
        self.config = config_text
        self.lines = config_text.splitlines()

    # ── helpers ──────────────────────────────────────────────────────
    def _get_section(self, start_re: str) -> List[str]:
        """Return lines from *start_re* until the next un-indented non-! line."""
        out: List[str] = []
        inside = False
        for line in self.lines:
            stripped = line.rstrip()
            if not inside:
                if re.match(start_re, stripped):
                    inside = True
                    # Don't include the header itself; caller adds it if needed
            else:
                if stripped == '!' or stripped == '':
                    break
                if not stripped.startswith(' ') and not stripped.startswith('\t'):
                    break  # new top-level command
                out.append(stripped.strip())
        return out

    def _get_all_sections(self, start_re: str) -> List[tuple]:
        """Return list of (header, [body_lines]) for every match of start_re."""
        results: List[tuple] = []
        inside = False
        header = ""
        body: List[str] = []
        for line in self.lines:
            stripped = line.rstrip()
            if re.match(start_re, stripped):
                if inside:
                    results.append((header, body))
                header = stripped
                body = []
                inside = True
            elif inside:
                if stripped == '!' or stripped == '':
                    results.append((header, body))
                    inside = False
                elif not stripped.startswith(' ') and not stripped.startswith('\t'):
                    results.append((header, body))
                    inside = False
                    # Re-check if this line starts a new matching section
                    if re.match(start_re, stripped):
                        header = stripped
                        body = []
                        inside = True
                else:
                    body.append(stripped.strip())
        if inside:
            results.append((header, body))
        return results

    # ── extractors ──────────────────────────────────────────────────

    def extract_hostname(self) -> str:
        m = re.search(r'^hostname\s+(\S+)', self.config, re.M)
        return m.group(1) if m else ""

    def extract_domain_name(self) -> str:
        m = re.search(r'^dns domain\s+(\S+)', self.config, re.M)
        if not m:
            m = re.search(r'^ip domain.name\s+(\S+)', self.config, re.M)
        return m.group(1) if m else ""

    def extract_timezone_config(self) -> Dict[str, Any]:
        m = re.search(r'^clock timezone\s+(.+)', self.config, re.M)
        return {"timezone": m.group(1).strip(), "timezone_offset": None} if m else {}

    def extract_spanning_tree_mode(self) -> str:
        m = re.search(r'^spanning-tree mode\s+(\S+)', self.config, re.M)
        return m.group(1) if m else "rapid-pvst"

    def extract_dns_servers(self) -> List[str]:
        servers = []
        for m in re.finditer(r'^ip name-server\s+(?:vrf\s+\S+\s+)?(\S+)', self.config, re.M):
            servers.append(m.group(1))
        return list(dict.fromkeys(servers))

    def extract_ntp_servers(self) -> List[str]:
        servers = []
        for m in re.finditer(r'^ntp server\s+(?:vrf\s+\S+\s+)?(\S+)(.*)$', self.config, re.M):
            entry = m.group(1)
            if 'prefer' in m.group(2):
                entry += "|prefer"
            servers.append(entry)
        return servers

    def extract_logging_hosts(self) -> List[str]:
        hosts = []
        for m in re.finditer(r'^logging\s+(?:vrf\s+\S+\s+)?host\s+(\S+)', self.config, re.M):
            hosts.append(m.group(1))
        return list(dict.fromkeys(hosts))

    def extract_snmp_config(self) -> Dict[str, Any]:
        config: Dict[str, Any] = {}
        m = re.search(r'^snmp-server location\s+(.+)', self.config, re.M)
        if m:
            config["location"] = m.group(1).strip()
        m = re.search(r'^snmp-server contact\s+(.+)', self.config, re.M)
        if m:
            config["contact"] = m.group(1).strip()
        # Community strings (v2c)
        for m in re.finditer(r'^snmp-server community\s+(\S+)\s+(RO|RW)', self.config, re.M | re.I):
            if m.group(2).upper() == 'RO':
                config["community_ro"] = m.group(1)
            else:
                config["community_rw"] = m.group(1)
        # Trap hosts
        trap_hosts = []
        for m in re.finditer(r'^snmp-server host\s+(\S+)', self.config, re.M):
            trap_hosts.append(m.group(1))
        if trap_hosts:
            config["trap_hosts"] = trap_hosts
        config["enable_traps"] = bool(re.search(r'^snmp-server enable traps$', self.config, re.M))
        # ACL
        m = re.search(r'^snmp-server\s+ipv4\s+access-list\s+(\S+)', self.config, re.M)
        if m:
            config["acl_ro"] = m.group(1)
        return config

    def extract_aaa_config(self) -> Dict[str, Any]:
        config: Dict[str, Any] = {"aaa_enabled": False, "tacacs_servers": []}
        # TACACS servers
        for m in re.finditer(
            r'^tacacs-server host\s+(\S+)\s+(?:vrf\s+\S+\s+)?key\s+\S+\s+(\S+)',
            self.config, re.M
        ):
            config["tacacs_servers"].append({
                "name": m.group(1),
                "ip": m.group(1),
                "key": m.group(2),
            })
        # Group name
        m = re.search(r'^aaa group server tacacs\+\s+(\S+)', self.config, re.M)
        if m:
            config["tacacs_group_name"] = m.group(1)
            config["aaa_enabled"] = True
        elif config["tacacs_servers"]:
            config["aaa_enabled"] = True
        return config

    def extract_local_users(self) -> List[Dict[str, str]]:
        users = []
        for m in re.finditer(r'^username\s+(\S+).*?secret\s+\S+\s+(\S+)', self.config, re.M):
            users.append({"name": m.group(1), "password": m.group(2)})
        return users

    def extract_enable_secret(self) -> str:
        m = re.search(r'^enable\s+(?:secret|password)\s+\S+\s+(\S+)', self.config, re.M)
        return m.group(1) if m else ""

    def extract_errdisable_config(self) -> Dict[str, Any]:
        m = re.search(r'^errdisable recovery interval\s+(\d+)', self.config, re.M)
        return {"recovery_interval": int(m.group(1))} if m else {}

    def extract_all_vlans(self) -> List[Dict[str, Any]]:
        vlans = []
        sections = self._get_all_sections(r'^vlan\s+(\d+)$')
        for header, body in sections:
            m = re.match(r'^vlan\s+(\d+)', header)
            if not m:
                continue
            vid = int(m.group(1))
            name = ""
            for line in body:
                nm = re.match(r'name\s+(.+)', line)
                if nm:
                    name = nm.group(1).strip()
            vlans.append({"id": vid, "name": name})
        return vlans

    def extract_vrfs(self) -> List[Dict[str, str]]:
        vrfs = []
        sections = self._get_all_sections(r'^vrf instance\s+(\S+)')
        for header, body in sections:
            m = re.match(r'^vrf instance\s+(\S+)', header)
            if not m:
                continue
            name = m.group(1)
            desc = ""
            for line in body:
                dm = re.match(r'description\s+(.+)', line)
                if dm:
                    desc = dm.group(1).strip()
            vrfs.append({"name": name, "description": desc})
        return vrfs

    def extract_acls(self) -> List[Dict[str, Any]]:
        acls = []
        sections = self._get_all_sections(r'^ip access-list\s+(standard|extended)\s+(.+)')
        for header, body in sections:
            m = re.match(r'^ip access-list\s+(standard|extended)\s+(.+)', header)
            if not m:
                continue
            acl_type = m.group(1)
            acl_name = m.group(2).strip()
            entries = []
            for line in body:
                entry = self._parse_acl_entry(line, acl_type)
                if entry:
                    entries.append(entry)
            acls.append({"name": acl_name, "type": acl_type, "entries": entries})
        return acls

    def _parse_acl_entry(self, line: str, acl_type: str) -> Optional[Dict[str, Any]]:
        """Parse a single ACL entry."""
        parts = line.split()
        if not parts:
            return None
        idx = 0
        seq = ""
        # Check if first token is a sequence number
        if parts[0].isdigit():
            seq = parts[0]
            idx = 1
        if idx >= len(parts):
            return None
        action = parts[idx]
        if action == 'remark':
            return {"sequence": seq, "action": "remark", "remark": ' '.join(parts[idx+1:])}
        if action not in ('permit', 'deny'):
            return None
        idx += 1
        rest = ' '.join(parts[idx:]) if idx < len(parts) else "any"
        log = 'log' in rest.lower()
        rest = re.sub(r'\s+log\b', '', rest, flags=re.I).strip()
        return {
            "sequence": seq,
            "action": action,
            "source": rest if rest else "any",
            "wildcard": None,
            "log": log,
        }

    def extract_interfaces(self) -> List[Dict[str, Any]]:
        """Extract ALL interface definitions."""
        interfaces = []
        sections = self._get_all_sections(r'^interface\s+\S+')
        for header, body in sections:
            m = re.match(r'^interface\s+(.+)', header)
            if not m:
                continue
            name = m.group(1).strip()
            if name == 'defaults':
                continue
            intf = self._parse_interface(name, body)
            interfaces.append(intf)
        return interfaces

    def _parse_interface(self, name: str, body: List[str]) -> Dict[str, Any]:
        intf: Dict[str, Any] = {"name": name, "config": {}}
        cfg = intf["config"]
        for line in body:
            m = re.match(r'description\s+(.+)', line)
            if m:
                cfg["description"] = m.group(1)
            elif line == 'shutdown':
                cfg["shutdown"] = True
            elif line == 'no shutdown':
                cfg["shutdown"] = False
            elif (m := re.match(r'switchport access vlan\s+(\d+)', line)):
                cfg["access_vlan"] = int(m.group(1))
                cfg["mode"] = "access"
            elif line == 'switchport mode access':
                cfg["mode"] = "access"
            elif line == 'switchport mode trunk':
                cfg["mode"] = "trunk"
            elif (m := re.match(r'switchport trunk allowed vlan\s+(.+)', line)):
                cfg["allowed_vlans"] = m.group(1)
            elif (m := re.match(r'switchport trunk native vlan\s+(\d+)', line)):
                cfg["native_vlan"] = int(m.group(1))
            elif (m := re.match(r'channel-group\s+(\d+)\s+mode\s+(\S+)', line)):
                cfg["port_channel_id"] = int(m.group(1))
                cfg["lacp_mode"] = m.group(2)
            elif (m := re.match(r'ip address\s+(.+)', line)):
                cfg["ip_address"] = m.group(1)
            elif (m := re.match(r'vrf\s+(\S+)', line)):
                cfg["vrf"] = m.group(1)
            elif (m := re.match(r'mtu\s+(\d+)', line)):
                cfg["mtu"] = int(m.group(1))
            elif (m := re.match(r'mlag\s+(\d+)', line)):
                cfg["mlag"] = int(m.group(1))
            elif line.startswith('spanning-tree portfast'):
                cfg["portfast"] = True
            elif line.startswith('spanning-tree bpduguard'):
                cfg["bpduguard"] = True
            elif (m := re.match(r'encapsulation dot1q vlan\s+(\d+)', line)):
                cfg["dot1q_vlan"] = int(m.group(1))
            elif line.startswith('pim '):
                cfg["pim_sparse"] = True
            elif (m := re.match(r'ip virtual-router address\s+(.+)', line)):
                cfg["virtual_router_address"] = m.group(1)
        return intf

    def extract_management(self) -> Dict[str, Any]:
        """Extract management interfaces and settings."""
        mgmt: Dict[str, Any] = {}
        # Management VRF — look for management interface in MGMT vrf
        # or explicit 'management vrf' statement
        # OOB interface = Management1 or Management0
        for intf_section in self._get_all_sections(r'^interface Management\d+'):
            header = intf_section[0] if isinstance(intf_section, tuple) else ""
            body = intf_section[1] if isinstance(intf_section, tuple) else []
            m = re.match(r'^interface (Management\d+)', header)
            if m:
                oob: Dict[str, Any] = {"name": m.group(1)}
                for line in body:
                    m_vrf = re.match(r'vrf\s+(\S+)', line)
                    if m_vrf:
                        oob["vrf"] = m_vrf.group(1)
                        mgmt["management_vrf"] = oob["vrf"]
                    m_ip = re.match(r'ip address\s+(.+)', line)
                    if m_ip:
                        oob["ip_address"] = m_ip.group(1)
                mgmt.setdefault("interfaces", {})["oob"] = [oob]

        # HTTP/HTTPS — management api http-commands section
        api_body = self._get_section(r'^management api http-commands')
        if api_body:
            https_cfg: Dict[str, Any] = {"enabled": True}
            for line in api_body:
                if line.startswith('protocol https'):
                    https_cfg["https_enabled"] = True
                if re.match(r'no shutdown', line):
                    https_cfg["shutdown"] = False
            mgmt["http_https"] = https_cfg

        # SSH
        ssh_body = self._get_section(r'^management ssh')
        if ssh_body:
            ssh_cfg: Dict[str, Any] = {"enabled": True}
            for line in ssh_body:
                m_idle = re.match(r'idle-timeout\s+(\d+)', line)
                if m_idle:
                    ssh_cfg["idle_timeout"] = int(m_idle.group(1))
            mgmt["ssh"] = ssh_cfg

        return mgmt

    def extract_banners(self) -> Dict[str, str]:
        banners: Dict[str, str] = {}
        for btype in ('login', 'motd'):
            lines_out = []
            inside = False
            for line in self.lines:
                stripped = line.rstrip()
                if not inside:
                    if re.match(rf'^banner {btype}$', stripped):
                        inside = True
                elif stripped == 'EOF':
                    break
                else:
                    lines_out.append(stripped)
            if lines_out:
                banners[btype] = '\n'.join(lines_out)
        return banners

    def extract_uplinks(self) -> List[Dict[str, Any]]:
        """Extract Port-Channel (uplink) interfaces."""
        uplinks = []
        for intf in self.extract_interfaces():
            name = intf["name"]
            cfg = intf.get("config", {})
            if name.startswith("Port-Channel") or cfg.get("mode") == "trunk":
                if name.startswith("Port-Channel"):
                    uplinks.append({
                        "name": name,
                        "type": "trunk",
                        "description": cfg.get("description", ""),
                        "allowed_vlans": cfg.get("allowed_vlans", ""),
                        "native_vlan": cfg.get("native_vlan", ""),
                    })
        return uplinks

    def extract_access_interfaces(self) -> List[Dict[str, Any]]:
        """Extract access-mode interfaces in the legacy pipeline format."""
        access = []
        target_re = re.compile(r'^(Ethernet\d+)$')
        for intf in self.extract_interfaces():
            name = intf["name"]
            cfg = intf.get("config", {})
            if cfg.get("mode") == "access" or (
                target_re.match(name) and not cfg.get("ip_address") and not cfg.get("mode") == "trunk"
            ):
                # Map Arista name -> Catalyst 9300 name
                catalyst_name = self._map_interface_name(name)
                access.append({
                    "name": catalyst_name,
                    "config": {
                        "description": cfg.get("description", "Access Port"),
                        "access_vlan": cfg.get("access_vlan", 1),
                        "voice_vlan": cfg.get("voice_vlan"),
                        "shutdown": cfg.get("shutdown", True),
                        "portfast": cfg.get("portfast", True),
                        "bpduguard": cfg.get("bpduguard", True),
                    },
                    "nac": {},
                })
        return access

    def extract_routed_interfaces(self) -> List[Dict[str, Any]]:
        """Extract routed interfaces (SVIs, loopbacks, sub-interfaces with IPs)."""
        routed = []
        for intf in self.extract_interfaces():
            name = intf["name"]
            cfg = intf.get("config", {})
            if cfg.get("ip_address") and (
                name.startswith("Vlan") or name.startswith("Loopback") or '.' in name
            ):
                catalyst_name = self._map_interface_name(name)
                ip_str = cfg["ip_address"]
                addr, mask = "", ""
                if '/' in ip_str:
                    parts = ip_str.split('/')
                    addr = parts[0]
                    try:
                        prefix = int(parts[1])
                        mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                        mask = f"{(mask_int >> 24) & 0xFF}.{(mask_int >> 16) & 0xFF}.{(mask_int >> 8) & 0xFF}.{mask_int & 0xFF}"
                    except (ValueError, IndexError):
                        mask = "255.255.255.0"
                routed.append({
                    "name": catalyst_name,
                    "description": cfg.get("description", ""),
                    "vrf": cfg.get("vrf", ""),
                    "ipv4": {"address": addr, "netmask": mask},
                    "mtu": cfg.get("mtu"),
                    "shutdown": cfg.get("shutdown", False),
                    "pim_sparse": cfg.get("pim_sparse", False),
                    "dot1q_vlan": cfg.get("dot1q_vlan"),
                })
        return routed

    @staticmethod
    def _map_interface_name(arista_name: str) -> str:
        """Map Arista interface name to Catalyst 9300 naming."""
        # Ethernet1 -> GigabitEthernet1/0/1
        m = re.match(r'^Ethernet(\d+)$', arista_name)
        if m:
            return f"GigabitEthernet1/0/{m.group(1)}"
        # Ethernet23.11 -> GigabitEthernet1/0/23.11 (sub-interface)
        m = re.match(r'^Ethernet(\d+)\.(\d+)$', arista_name)
        if m:
            return f"GigabitEthernet1/0/{m.group(1)}.{m.group(2)}"
        # Port-Channel, Vlan, Loopback, Management stay as-is
        # Management1 -> GigabitEthernet0/0
        if arista_name.startswith("Management"):
            return "GigabitEthernet0/0"
        return arista_name

    def parse_all(self) -> Dict[str, Any]:
        """Extract everything into the intermediate format expected by the pipeline."""
        return {
            "hostname": self.extract_hostname(),
            "domain_name": self.extract_domain_name(),
            "timezone_config": self.extract_timezone_config(),
            "stp_mode": self.extract_spanning_tree_mode(),
            "dns_servers": self.extract_dns_servers(),
            "ntp_servers": self.extract_ntp_servers(),
            "logging_hosts": self.extract_logging_hosts(),
            "snmp_config": self.extract_snmp_config(),
            "aaa_config": self.extract_aaa_config(),
            "local_users": self.extract_local_users(),
            "enable_secret": self.extract_enable_secret(),
            "errdisable_config": self.extract_errdisable_config(),
            "vlans": self.extract_all_vlans(),
            "vrfs": self.extract_vrfs(),
            "acls": self.extract_acls(),
            "management": self.extract_management(),
            "banners": self.extract_banners(),
            "uplinks": self.extract_uplinks(),
            "access_interfaces": self.extract_access_interfaces(),
            "routed_interfaces": self.extract_routed_interfaces(),
            "stack_info": {"is_stack": False, "member_count": 1},
            "pnp_config": {},
            "vrf_config": {},
        }
