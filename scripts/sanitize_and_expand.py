#!/usr/bin/env python3
"""
Sanitize existing configs and generate expanded variants for the paper dataset.

Removes all customer-identifying information and generates new configs by varying:
  - Hostnames / device roles
  - VLAN assignments
  - Interface counts and role mixes
  - 802.1X presence
  - Uplink type (port-channel vs plain trunk)
  - Stack size (single vs 2-/3-member)
  - STP mode (rapid-pvst vs pvst)
  - NAC/dot1x presence
  - License level

Output directory layout:
  input/sanitized/
    cisco/    <- sanitized originals + Cisco variants
    arista/   <- sanitized original + Arista variants
"""

import os
import re
import copy
import random
from pathlib import Path
from typing import Dict, List

random.seed(42)

REPO_ROOT = Path(__file__).resolve().parent.parent
INPUT_DIR  = REPO_ROOT / "input"
OUT_CISCO  = INPUT_DIR / "sanitized" / "cisco"
OUT_ARISTA = INPUT_DIR / "sanitized" / "arista"
OUT_CISCO.mkdir(parents=True, exist_ok=True)
OUT_ARISTA.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Replacement tables — map real production values to generic stand-ins.
#
# NOTE FOR PUBLIC RELEASE: the production source values (real IPs, hostnames,
# domain, organization name, server names, street address, phone) have been
# REDACTED. The entries below are representative placeholders illustrating each
# transform category; the full site-specific map is withheld. The sanitized
# corpus in input/sanitized/ was produced with the original map and is
# unaffected by this redaction.
# ---------------------------------------------------------------------------

IP_MAP = {
    # <real production IP> : <RFC 5737 stand-in>   (production keys redacted)
    "203.0.113.10":  "192.0.2.11",     # example: TACACS/RADIUS/NTP/mgmt host
    "203.0.113.20":  "192.0.2.21",     # example: syslog
    "203.0.113.30":  "198.51.100.11",  # example: Arista management
}

STRING_MAP = {
    # <real production string> : <generic stand-in>   (production keys redacted)
    "example.internal":  "campus.example.edu",         # domain
    "EXAMPLE-ORG":       "Campus Network Operations",  # org / banner name
    "SRC-DIST-DR01":     "CAMPUS-DIST-SW01",           # hostname
    # server names, street address, phone, and SNMPv3 hashes redacted
    "sch-smart-licensing@cisco.com": "sch-smart-licensing@cisco.com",  # Cisco default; kept
}

SNMP_AUTH_HASH_RE = re.compile(
    r'(snmp-server user \S+ \S+ v3 localized \S+ auth \S+) \S+ (priv \S+) \S+',
)

def _replace_ips(text: str) -> str:
    """Replace IP addresses by longest-match first."""
    for real, fake in sorted(IP_MAP.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(real, fake)
    return text

def _replace_strings(text: str) -> str:
    for real, fake in STRING_MAP.items():
        text = text.replace(real, fake)
    return text

def _scrub_snmp_hashes(text: str) -> str:
    return SNMP_AUTH_HASH_RE.sub(r'\1 REDACTED \2 REDACTED', text)

def _sanitize_hostname(text: str, new_hostname: str) -> str:
    """Replace the 'hostname X' line."""
    return re.sub(r'^hostname\s+\S+', f'hostname {new_hostname}', text, flags=re.MULTILINE)

def _sanitize_snmp_location(text: str, new_location: str) -> str:
    return re.sub(r'^snmp-server location\s+.*', f'snmp-server location {new_location}', text, flags=re.MULTILINE)

def _sanitize_snmp_chassis(text: str, new_chassis: str) -> str:
    return re.sub(r'^snmp-server chassis-id\s+.*', f'snmp-server chassis-id {new_chassis}', text, flags=re.MULTILINE)

_INTERNAL_IP_RE = re.compile(
    r'\b(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'      # RFC 1918 10.x.x.x
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'  # RFC 1918 172.16-31.x.x
    r')\b'
    # site-specific public ranges (2 entries) redacted for public release
)

_IP_COUNTER = [0]

def _replace_residual_ips(text: str) -> str:
    """Replace any remaining real IPs not covered by the explicit IP_MAP.

    Each unique real IP is assigned a stable RFC 5737 / RFC 3849 placeholder.
    Already-replaced placeholder IPs are left alone.
    """
    seen: Dict[str, str] = {}
    def _sub(m: re.Match) -> str:
        ip = m.group(0)
        # Don't re-replace addresses we already mapped to
        if ip.startswith("192.0.2.") or ip.startswith("198.51.100.") or ip.startswith("198.51.1"):
            return ip
        if ip not in seen:
            _IP_COUNTER[0] += 1
            seen[ip] = f"192.0.2.{(_IP_COUNTER[0] % 254) + 1}"
        return seen[ip]
    return _INTERNAL_IP_RE.sub(_sub, text)

def sanitize(text: str) -> str:
    text = _replace_ips(text)
    text = _replace_strings(text)
    text = _scrub_snmp_hashes(text)
    text = _replace_residual_ips(text)
    return text

# ---------------------------------------------------------------------------
# Template snippets for generating new Cisco IOS-XE configs
# ---------------------------------------------------------------------------

CISCO_HEADER = """\
no service pad
service timestamps debug uptime
service timestamps log datetime localtime
service password-encryption
service compress-config
no platform punt-keepalive disable-kernel-core
!
hostname {hostname}
!
vrf definition Mgmt-vrf
 !
 address-family ipv4
 exit-address-family
!
enable secret 5 xxxxxxxx
!"""

CISCO_AAA_NAC = """
aaa new-model
!
aaa group server radius RADIUS_GROUP
 server name radius-svr-01
 server name radius-svr-02
 deadtime 1
!
aaa group server tacacs+ Tacacs_Group
 server name tacacs-svr-01
 server name tacacs-svr-02
!
aaa authentication login default local group Tacacs_Group enable
aaa authentication dot1x default group RADIUS_GROUP
aaa authorization exec default group Tacacs_Group local
aaa authorization commands 15 default group Tacacs_Group if-authenticated
aaa authorization network default group RADIUS_GROUP
aaa accounting dot1x default start-stop group RADIUS_GROUP
aaa accounting exec default start-stop group Tacacs_Group
!
aaa server radius dynamic-author
 client 192.0.2.31 server-key 7 xxxxxxxx
 port 3799
 auth-type all
!
aaa session-id common
dot1x system-auth-control"""

CISCO_AAA_NOTACACS = """
aaa new-model
!
aaa authentication login default local enable
aaa session-id common"""

CISCO_SYS_RAPID = """
errdisable recovery cause security-violation
errdisable recovery cause gbic-invalid
errdisable recovery cause psecure-violation
errdisable recovery interval 100
{license}
diagnostic bootup level minimal
spanning-tree mode rapid-pvst
spanning-tree extend system-id"""

CISCO_SYS_PVST = """
errdisable recovery cause security-violation
errdisable recovery cause gbic-invalid
errdisable recovery cause psecure-violation
errdisable recovery interval 100
{license}
diagnostic bootup level minimal
spanning-tree mode pvst
spanning-tree extend system-id"""

CISCO_STACK = """
switch 1 provision ws-c3850-48p
switch 2 provision ws-c3850-48p"""

CISCO_SINGLE = """
switch 1 provision ws-c3850-48p"""

CISCO_COMMON = """
redundancy
 mode sso
!
username xxxxxxxx privilege 15 password 7 xxxxxxxx
!
lldp run
!"""

def _vlan_block(vlans: List[Dict]) -> str:
    lines = []
    for v in vlans:
        lines.append(f"vlan {v['id']}")
        lines.append(f" name {v['name']}")
        lines.append("!")
    return "\n".join(lines)

def _access_port(n: int, vlan: int, voice: int = 0, nac: bool = False,
                 storm: bool = True, switch: int = 1) -> str:
    lines = [
        f"interface GigabitEthernet{switch}/0/{n}",
        f" switchport access vlan {vlan}",
        " switchport mode access",
    ]
    if voice:
        lines.append(f" switchport voice vlan {voice}")
    if nac:
        lines += [
            " authentication host-mode multi-auth",
            " authentication order dot1x mab",
            " authentication priority dot1x mab",
            " authentication port-control auto",
            " authentication periodic",
            " authentication timer reauthenticate server",
            " mab",
            " dot1x pae authenticator",
        ]
    lines.append(" no logging event link-status")
    if storm:
        lines += [
            " storm-control broadcast level 2.00 1.00",
            " storm-control multicast level 2.00 1.00",
        ]
    lines += [
        " spanning-tree portfast",
        " spanning-tree bpduguard enable",
        "!",
    ]
    return "\n".join(lines)

def _uplink_pc(pc_id: int, members: List[str], allowed_vlans: str, native: int) -> str:
    lines = [f"interface Port-channel{pc_id}",
             f" description UPLINK-PC{pc_id}",
             f" switchport trunk native vlan {native}",
             f" switchport trunk allowed vlan {allowed_vlans}",
             " switchport mode trunk",
             "!"]
    for m in members:
        lines += [f"interface {m}",
                  f" description MEMBER-PC{pc_id}",
                  f" channel-group {pc_id} mode active",
                  "!"]
    return "\n".join(lines)

def _uplink_trunk(name: str, allowed_vlans: str, native: int) -> str:
    return "\n".join([
        f"interface {name}",
        " description UPLINK-TRUNK",
        f" switchport trunk native vlan {native}",
        f" switchport trunk allowed vlan {allowed_vlans}",
        " switchport mode trunk",
        " spanning-tree guard root",
        "!",
    ])

def _mgmt_svi(vlan: int, ip: str, gw: str) -> str:
    return "\n".join([
        "interface GigabitEthernet0/0",
        " vrf forwarding Mgmt-vrf",
        " no ip address",
        " negotiation auto",
        "!",
        f"interface Vlan{vlan}",
        f" ip address {ip} 255.255.255.0",
        " no ip redirects",
        "!",
        f"ip default-gateway {gw}",
    ])

def _mgmt_plain(ip: str, gw: str) -> str:
    return "\n".join([
        "interface GigabitEthernet0/0",
        " vrf forwarding Mgmt-vrf",
        f" ip address {ip} 255.255.255.0",
        " negotiation auto",
        "!",
        f"ip default-gateway {gw}",
    ])

def _snmp(location: str, chassis: str, acl: int = 13) -> str:
    return "\n".join([
        f"snmp-server community xxxxxxxx RO {acl}",
        f"snmp-server location {location}",
        "snmp-server contact NOC",
        f"snmp-server chassis-id {chassis}",
        "snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart",
        "snmp-server enable traps config",
        f"snmp-server host 192.0.2.24 version 2c xxxxxxxx",
    ])

def _tacacs_servers() -> str:
    return "\n".join([
        "tacacs server tacacs-svr-01",
        " address ipv4 192.0.2.11",
        " key 7 xxxxxxxx",
        " timeout 3",
        "tacacs server tacacs-svr-02",
        " address ipv4 192.0.2.12",
        " key 7 xxxxxxxx",
        " timeout 3",
    ])

def _radius_servers() -> str:
    return "\n".join([
        "radius server radius-svr-01",
        " address ipv4 192.0.2.31 auth-port 1645 acct-port 1646",
        " key 7 xxxxxxxx",
        "radius server radius-svr-02",
        " address ipv4 192.0.2.32 auth-port 1645 acct-port 1646",
        " key 7 xxxxxxxx",
    ])

CISCO_LOGGING = """
logging host 192.0.2.21
logging host 192.0.2.22
logging host 192.0.2.23"""

CISCO_BANNER = """
banner motd ^C
*************************************************************
* Authorized access only.                                   *
* Unauthorized use is prohibited and may be prosecuted.     *
*************************************************************
^C"""

CISCO_LINES = """
ip ssh version 2
no ip http server
ip http authentication aaa
no ip http secure-server
!
line con 0
 exec-timeout 5 0
 stopbits 1
line vty 0 4
 access-class 13 in
 exec-timeout 20 0
 privilege level 15
 transport preferred none
 transport input ssh
line vty 5 15
 access-class 13 in
 exec-timeout 20 0
 privilege level 15
 transport preferred none
 transport input ssh
!
ntp server 192.0.2.11 prefer
ntp server 192.0.2.12
!
ip domain name campus.example.edu
ip name-server 192.0.2.50 192.0.2.60
!
vtp domain CAMPUS
vtp mode transparent
!"""

CISCO_VTP_BLOCK = """
vtp domain CAMPUS
vtp mode transparent
!"""

CISCO_FOOTER = """
control-plane
 service-policy input system-cpp-policy
!
end"""

# ---------------------------------------------------------------------------
# Config builder
# ---------------------------------------------------------------------------

def build_cisco_config(spec: Dict) -> str:
    """Assemble a Cisco IOS-XE config from spec dict."""
    parts = []

    # Header
    parts.append(CISCO_HEADER.format(hostname=spec["hostname"]))

    # AAA
    if spec.get("nac"):
        parts.append(CISCO_AAA_NAC)
    else:
        parts.append(CISCO_AAA_NOTACACS)

    # Clock
    parts.append("clock timezone CST -6 0\nclock summer-time CDT recurring")

    # Stack
    if spec.get("stack", 1) > 1:
        st = "\n".join(f"switch {i} provision ws-c3850-48p" for i in range(1, spec["stack"] + 1))
        parts.append(st)
    else:
        parts.append("switch 1 provision ws-c3850-48p")

    # DNS / domain
    parts.append(f"ip domain name campus.example.edu\nip name-server 192.0.2.50 192.0.2.60")

    # VTP
    parts.append(CISCO_VTP_BLOCK)

    # Sys / STP
    lic = f"license boot level {spec.get('license', 'network-advantage')}"
    if spec.get("stp", "rapid-pvst") == "rapid-pvst":
        parts.append(CISCO_SYS_RAPID.format(license=lic))
    else:
        parts.append(CISCO_SYS_PVST.format(license=lic))

    parts.append(CISCO_COMMON)

    # VLANs
    parts.append(_vlan_block(spec["vlans"]))

    # GigabitEthernet0/0 management
    mgmt = spec.get("mgmt")
    if mgmt:
        if mgmt.get("vlan"):
            parts.append(_mgmt_svi(mgmt["vlan"], mgmt["ip"], mgmt["gw"]))
        else:
            parts.append(_mgmt_plain(mgmt["ip"], mgmt["gw"]))

    # Uplinks
    uplink = spec.get("uplink", {})
    vlan_ids = ",".join(str(v["id"]) for v in spec["vlans"])
    native = spec.get("native_vlan", spec["vlans"][0]["id"])
    if uplink.get("type") == "port-channel":
        parts.append(_uplink_pc(
            uplink["pc_id"],
            uplink.get("members", ["TenGigabitEthernet1/1/1", "TenGigabitEthernet2/1/1"]),
            vlan_ids, native
        ))
    else:
        ul_name = uplink.get("name", "TenGigabitEthernet1/1/1")
        parts.append(_uplink_trunk(ul_name, vlan_ids, native))

    # Access ports
    vlans = spec["vlans"]
    data_vlan = vlans[0]["id"]
    voice_vlan = vlans[1]["id"] if len(vlans) > 1 and "voice" in vlans[1]["name"].lower() else 0
    nac = spec.get("nac", False)
    count = spec.get("access_count", 24)
    for sw_num in range(1, spec.get("stack", 1) + 1):
        for port in range(1, count + 1):
            # Sprinkle variation: some ports get voice VLAN, some don't
            v = voice_vlan if voice_vlan and (port % 3 == 0) else 0
            parts.append(_access_port(port, data_vlan, v, nac=nac, switch=sw_num))

    # SNMP
    parts.append(_snmp(spec.get("snmp_location", spec["hostname"]), spec["hostname"]))

    # TACACS / RADIUS servers
    parts.append(_tacacs_servers())
    if nac:
        parts.append(_radius_servers())

    # ACLs
    acl_src = spec.get("acl_src", "192.0.2.0 0.0.0.255")
    parts.append(f"ip access-list standard 13\n 10 permit 192.0.2.11\n 20 permit 192.0.2.12\n 30 permit {acl_src}")
    if nac:
        parts.append("ip access-list extended 109\n 10 permit ip 192.0.2.0 0.0.0.255 any\n 20 permit ip host 192.0.2.31 any")

    # Logging / banner / lines / footer
    parts.append(CISCO_LOGGING)
    parts.append(CISCO_BANNER)
    parts.append(CISCO_LINES)
    parts.append(CISCO_FOOTER)

    return "\n!\n".join(parts)


# ---------------------------------------------------------------------------
# Dataset specifications — 16 Cisco configs (13 sanitized originals + 3 new)
# plus 4 Arista configs derived from the 1 original
# ---------------------------------------------------------------------------

CISCO_SPECS: List[Dict] = [
    # --- Group A: Access-edge, 3-stack, full NAC/802.1X ---
    {
        "id": "BLDG-A-FLOOR1-SW01", "hostname": "BLDG-A-FLOOR1-SW01",
        "vlans": [{"id": 10, "name": "DATA"}, {"id": 20, "name": "VOICE"}, {"id": 30, "name": "GUEST"}, {"id": 900, "name": "MGMT"}],
        "native_vlan": 900, "stack": 3, "nac": True, "stp": "rapid-pvst",
        "license": "network-advantage", "access_count": 48,
        "uplink": {"type": "port-channel", "pc_id": 10, "members": ["TenGigabitEthernet1/1/1", "TenGigabitEthernet2/1/1", "TenGigabitEthernet3/1/1"]},
        "mgmt": {"vlan": 900, "ip": "192.0.2.101", "gw": "192.0.2.254"},
        "snmp_location": "Building-A Floor-1 IDF",
    },
    {
        "id": "BLDG-A-FLOOR2-SW01", "hostname": "BLDG-A-FLOOR2-SW01",
        "vlans": [{"id": 10, "name": "DATA"}, {"id": 20, "name": "VOICE"}, {"id": 40, "name": "IOT"}, {"id": 900, "name": "MGMT"}],
        "native_vlan": 900, "stack": 2, "nac": True, "stp": "rapid-pvst",
        "license": "network-advantage", "access_count": 48,
        "uplink": {"type": "port-channel", "pc_id": 10, "members": ["TenGigabitEthernet1/1/1", "TenGigabitEthernet2/1/1"]},
        "mgmt": {"vlan": 900, "ip": "192.0.2.102", "gw": "192.0.2.254"},
        "snmp_location": "Building-A Floor-2 IDF",
    },
    {
        "id": "BLDG-A-FLOOR3-SW01", "hostname": "BLDG-A-FLOOR3-SW01",
        "vlans": [{"id": 10, "name": "DATA"}, {"id": 20, "name": "VOICE"}, {"id": 900, "name": "MGMT"}],
        "native_vlan": 900, "stack": 2, "nac": True, "stp": "rapid-pvst",
        "license": "network-advantage", "access_count": 24,
        "uplink": {"type": "trunk", "name": "TenGigabitEthernet1/1/1"},
        "mgmt": {"vlan": 900, "ip": "192.0.2.103", "gw": "192.0.2.254"},
        "snmp_location": "Building-A Floor-3 IDF",
    },
    # --- Group B: OOB server-room switches, no NAC, many VLANs ---
    {
        "id": "DATACTR-OOBSW-01", "hostname": "DATACTR-OOBSW-01",
        "vlans": [{"id": 230, "name": "OOB-PDU"}, {"id": 236, "name": "OOB-MGMT"},
                  {"id": 712, "name": "SERVER-VLAN-712"}, {"id": 713, "name": "SERVER-VLAN-713"},
                  {"id": 714, "name": "SERVER-VLAN-714"}, {"id": 715, "name": "SERVER-VLAN-715"},
                  {"id": 716, "name": "SERVER-VLAN-716"}, {"id": 3069, "name": "Native"}],
        "native_vlan": 3069, "stack": 1, "nac": False, "stp": "rapid-pvst",
        "license": "ipservicesk9", "access_count": 48,
        "uplink": {"type": "trunk", "name": "TenGigabitEthernet1/1/1"},
        "mgmt": {"vlan": 236, "ip": "192.0.2.136", "gw": "192.0.2.254"},
        "snmp_location": "Data-Center-01 OOB-Switch",
    },
    {
        "id": "DATACTR-OOBSW-02", "hostname": "DATACTR-OOBSW-02",
        "vlans": [{"id": 230, "name": "OOB-PDU"}, {"id": 236, "name": "OOB-MGMT"},
                  {"id": 720, "name": "SERVER-VLAN-720"}, {"id": 721, "name": "SERVER-VLAN-721"},
                  {"id": 722, "name": "SERVER-VLAN-722"}, {"id": 3069, "name": "Native"}],
        "native_vlan": 3069, "stack": 1, "nac": False, "stp": "rapid-pvst",
        "license": "ipservicesk9", "access_count": 48,
        "uplink": {"type": "trunk", "name": "TenGigabitEthernet1/1/1"},
        "mgmt": {"vlan": 236, "ip": "192.0.2.137", "gw": "192.0.2.254"},
        "snmp_location": "Data-Center-01 OOB-Switch",
    },
    {
        "id": "DATACTR-OOBSW-03", "hostname": "DATACTR-OOBSW-03",
        "vlans": [{"id": 230, "name": "OOB-PDU"}, {"id": 236, "name": "OOB-MGMT"},
                  {"id": 730, "name": "SERVER-VLAN-730"}, {"id": 731, "name": "SERVER-VLAN-731"},
                  {"id": 732, "name": "SERVER-VLAN-732"}, {"id": 3069, "name": "Native"}],
        "native_vlan": 3069, "stack": 1, "nac": False, "stp": "rapid-pvst",
        "license": "ipservicesk9", "access_count": 48,
        "uplink": {"type": "trunk", "name": "TenGigabitEthernet1/1/1"},
        "mgmt": {"vlan": 236, "ip": "192.0.2.138", "gw": "192.0.2.254"},
        "snmp_location": "Data-Center-02 OOB-Switch",
    },
    {
        "id": "DATACTR-OOBSW-04", "hostname": "DATACTR-OOBSW-04",
        "vlans": [{"id": 230, "name": "OOB-PDU"}, {"id": 236, "name": "OOB-MGMT"},
                  {"id": 740, "name": "SERVER-VLAN-740"}, {"id": 741, "name": "SERVER-VLAN-741"},
                  {"id": 742, "name": "SERVER-VLAN-742"}, {"id": 3069, "name": "Native"}],
        "native_vlan": 3069, "stack": 1, "nac": False, "stp": "rapid-pvst",
        "license": "ipservicesk9", "access_count": 48,
        "uplink": {"type": "port-channel", "pc_id": 1, "members": ["GigabitEthernet1/1/1", "GigabitEthernet1/1/2"]},
        "mgmt": {"vlan": 236, "ip": "192.0.2.139", "gw": "192.0.2.254"},
        "snmp_location": "Data-Center-02 OOB-Switch",
    },
    {
        "id": "DATACTR-OOBSW-05", "hostname": "DATACTR-OOBSW-05",
        "vlans": [{"id": 230, "name": "OOB-PDU"}, {"id": 236, "name": "OOB-MGMT"},
                  {"id": 750, "name": "SERVER-VLAN-750"}, {"id": 751, "name": "SERVER-VLAN-751"},
                  {"id": 3069, "name": "Native"}],
        "native_vlan": 3069, "stack": 1, "nac": False, "stp": "rapid-pvst",
        "license": "ipservicesk9", "access_count": 48,
        "uplink": {"type": "trunk", "name": "TenGigabitEthernet1/1/1"},
        "mgmt": {"vlan": 236, "ip": "192.0.2.140", "gw": "192.0.2.254"},
        "snmp_location": "Data-Center-03 OOB-Switch",
    },
    # --- Group C: Building access, no NAC, simple VLAN ---
    {
        "id": "BLDG-B-FLOOR1-SW01", "hostname": "BLDG-B-FLOOR1-SW01",
        "vlans": [{"id": 61, "name": "USER-NET"}, {"id": 900, "name": "MGMT"}, {"id": 919, "name": "MGMT2"}],
        "native_vlan": 900, "stack": 1, "nac": False, "stp": "pvst",
        "license": "lanbasek9", "access_count": 48,
        "uplink": {"type": "trunk", "name": "TenGigabitEthernet1/1/1"},
        "mgmt": {"vlan": 919, "ip": "192.0.2.119", "gw": "192.0.2.254"},
        "snmp_location": "Building-B Floor-1",
    },
    {
        "id": "BLDG-B-FLOOR2-SW01", "hostname": "BLDG-B-FLOOR2-SW01",
        "vlans": [{"id": 61, "name": "USER-NET"}, {"id": 62, "name": "CONF-ROOM"}, {"id": 900, "name": "MGMT"}],
        "native_vlan": 900, "stack": 1, "nac": False, "stp": "pvst",
        "license": "lanbasek9", "access_count": 48,
        "uplink": {"type": "port-channel", "pc_id": 1, "members": ["TenGigabitEthernet1/1/1"]},
        "mgmt": {"vlan": 900, "ip": "192.0.2.120", "gw": "192.0.2.254"},
        "snmp_location": "Building-B Floor-2",
    },
    {
        "id": "BLDG-C-FLOOR1-SW01", "hostname": "BLDG-C-FLOOR1-SW01",
        "vlans": [{"id": 100, "name": "DATA"}, {"id": 200, "name": "VOICE"}, {"id": 300, "name": "GUEST"}, {"id": 900, "name": "MGMT"}],
        "native_vlan": 900, "stack": 2, "nac": True, "stp": "rapid-pvst",
        "license": "network-advantage", "access_count": 48,
        "uplink": {"type": "port-channel", "pc_id": 10, "members": ["TenGigabitEthernet1/1/1", "TenGigabitEthernet2/1/1"]},
        "mgmt": {"vlan": 900, "ip": "192.0.2.150", "gw": "192.0.2.254"},
        "snmp_location": "Building-C Floor-1 IDF",
    },
    {
        "id": "BLDG-C-FLOOR2-SW01", "hostname": "BLDG-C-FLOOR2-SW01",
        "vlans": [{"id": 100, "name": "DATA"}, {"id": 200, "name": "VOICE"}, {"id": 900, "name": "MGMT"}],
        "native_vlan": 900, "stack": 1, "nac": True, "stp": "rapid-pvst",
        "license": "network-advantage", "access_count": 24,
        "uplink": {"type": "trunk", "name": "TenGigabitEthernet1/1/1"},
        "mgmt": {"vlan": 900, "ip": "192.0.2.151", "gw": "192.0.2.254"},
        "snmp_location": "Building-C Floor-2 IDF",
    },
    # --- Group D: Mixed-role, routed interface (SVI), more complex ---
    {
        "id": "DIST-SW-BLDGA-01", "hostname": "DIST-SW-BLDGA-01",
        "vlans": [{"id": 10, "name": "DATA"}, {"id": 20, "name": "VOICE"},
                  {"id": 30, "name": "GUEST"}, {"id": 40, "name": "IOT"},
                  {"id": 900, "name": "MGMT"}],
        "native_vlan": 900, "stack": 2, "nac": True, "stp": "rapid-pvst",
        "license": "network-advantage", "access_count": 24,
        "uplink": {"type": "port-channel", "pc_id": 10, "members": ["TenGigabitEthernet1/1/1", "TenGigabitEthernet2/1/1"]},
        "mgmt": {"vlan": 900, "ip": "192.0.2.200", "gw": "192.0.2.254"},
        "snmp_location": "Distribution Building-A",
    },
    {
        "id": "DIST-SW-BLDGB-01", "hostname": "DIST-SW-BLDGB-01",
        "vlans": [{"id": 50, "name": "RESEARCH"}, {"id": 60, "name": "LAB"},
                  {"id": 70, "name": "VOICE"}, {"id": 900, "name": "MGMT"}],
        "native_vlan": 900, "stack": 1, "nac": False, "stp": "rapid-pvst",
        "license": "network-advantage", "access_count": 24,
        "uplink": {"type": "port-channel", "pc_id": 10, "members": ["TenGigabitEthernet1/1/1"]},
        "mgmt": {"vlan": 900, "ip": "192.0.2.201", "gw": "192.0.2.254"},
        "snmp_location": "Distribution Building-B",
    },
    {
        "id": "EDGE-SW-REMOTE-01", "hostname": "EDGE-SW-REMOTE-01",
        "vlans": [{"id": 10, "name": "DATA"}, {"id": 900, "name": "MGMT"}],
        "native_vlan": 900, "stack": 1, "nac": False, "stp": "rapid-pvst",
        "license": "lanbasek9", "access_count": 24,
        "uplink": {"type": "trunk", "name": "GigabitEthernet1/1/1"},
        "mgmt": {"vlan": 900, "ip": "192.0.2.210", "gw": "192.0.2.254"},
        "snmp_location": "Remote-Site-01",
    },
    {
        "id": "EDGE-SW-REMOTE-02", "hostname": "EDGE-SW-REMOTE-02",
        "vlans": [{"id": 10, "name": "DATA"}, {"id": 20, "name": "VOICE"}, {"id": 900, "name": "MGMT"}],
        "native_vlan": 900, "stack": 1, "nac": True, "stp": "rapid-pvst",
        "license": "network-advantage", "access_count": 24,
        "uplink": {"type": "port-channel", "pc_id": 1, "members": ["GigabitEthernet1/1/1", "GigabitEthernet1/1/2"]},
        "mgmt": {"vlan": 900, "ip": "192.0.2.211", "gw": "192.0.2.254"},
        "snmp_location": "Remote-Site-02",
    },
]


# ---------------------------------------------------------------------------
# Arista variant generator
# ---------------------------------------------------------------------------

ARISTA_VLAN_BLOCK = """\
vlan {vlan_id}
   name {vlan_name}"""

ARISTA_ACCESS_PORT = """\
interface {name}
   description {desc}
   switchport access vlan {vlan}
   switchport"""

ARISTA_TRUNK_PORT = """\
interface {name}
   description UPLINK-TRUNK
   switchport mode trunk
   switchport trunk allowed vlan {allowed}
   switchport"""

ARISTA_SVI = """\
interface Vlan{vlan}
   description {desc}
   vrf {vrf}
   ip address {ip}/24"""

ARISTA_MGMT_BLOCK = """\
management api http-commands
   no protocol http
   protocol https
   no shutdown
   !
   vrf MDMZ
      no shutdown
!
management ssh
   idle-timeout 20
   authentication mode keyboard-interactive
   vrf MDMZ
      no shutdown"""

def build_arista_config(spec: Dict) -> str:
    lines = []
    lines.append(f"! Command: show running-config")
    lines.append(f"! device: {spec['hostname']} (CCS-720XP-24ZY4, EOS-4.31.3M)")
    lines.append("!")
    lines.append("no aaa root")
    lines.append("!")
    lines.append(f"hostname {spec['hostname']}")
    lines.append("!")
    lines.append("switchport default mode routed")
    lines.append("!")
    # VLANs
    lines.append("vlan internal order ascending range 3500 3750")
    lines.append("!")
    for v in spec["vlans"]:
        lines.append(f"vlan {v['id']}")
        lines.append(f"   name {v['name']}")
        lines.append("!")
    lines.append(f"dns domain campus.example.org")
    lines.append("!")
    # SNMPv3 — placeholder only, no real hashes
    lines.append(f"snmp-server ipv4 access-list SNMP-ALLOWED vrf MDMZ")
    lines.append(f"snmp-server contact NOC-555-0100")
    lines.append(f"snmp-server location {spec.get('snmp_location', spec['hostname'])}")
    lines.append(f"snmp-server vrf MDMZ local-interface Vlan{spec.get('mgmt_vlan', 4060)}")
    lines.append("!")
    # Interfaces — uplink
    allowed = ",".join(str(v["id"]) for v in spec["vlans"])
    uplink = spec.get("uplink", {})
    if uplink.get("type") == "port-channel":
        pc_id = uplink["pc_id"]
        lines.append(f"interface Port-Channel{pc_id}")
        lines.append(f"   description UPLINK-PC{pc_id}")
        lines.append(f"   switchport mode trunk")
        lines.append(f"   switchport trunk allowed vlan {allowed}")
        lines.append("!")
        for m in uplink.get("members", []):
            lines.append(f"interface {m}")
            lines.append(f"   description UPLINK-MEMBER")
            lines.append(f"   channel-group {pc_id} mode active")
            lines.append("!")
    else:
        ul = uplink.get("name", "Ethernet25")
        lines.append(f"interface {ul}")
        lines.append(f"   description UPLINK")
        lines.append(f"   switchport mode trunk")
        lines.append(f"   switchport trunk allowed vlan {allowed}")
        lines.append("!")

    # Access ports
    data_vlan = spec["vlans"][0]["id"]
    voice_vlan = next((v["id"] for v in spec["vlans"] if "voice" in v["name"].lower()), 0)
    for i in range(1, spec.get("access_count", 24) + 1):
        lines.append(f"interface Ethernet{i}")
        desc = "USER" if i % 4 != 0 else "IP-PHONE"
        lines.append(f"   description {desc}")
        lines.append(f"   switchport access vlan {data_vlan}")
        if voice_vlan and i % 3 == 0:
            lines.append(f"   switchport trunk native vlan {data_vlan}")
            lines.append(f"   switchport trunk allowed vlan {data_vlan},{voice_vlan}")
            lines.append(f"   switchport mode trunk")
        lines.append("   switchport")
        lines.append("!")

    # SVIs
    for v in spec["vlans"]:
        if v.get("ip"):
            vrf = v.get("vrf", "MDMZ")
            lines.append(f"interface Vlan{v['id']}")
            lines.append(f"   description {v['name']}")
            lines.append(f"   vrf {vrf}")
            lines.append(f"   ip address {v['ip']}/24")
            lines.append("!")

    # Management
    lines.append(ARISTA_MGMT_BLOCK)

    # NTP
    lines.append("ntp server 192.0.2.11 prefer")
    lines.append("ntp server 192.0.2.12")
    lines.append("!")

    # AAA / TACACS
    if spec.get("nac"):
        lines.append("aaa group server tacacs+ TACACS_GROUP")
        lines.append(f"   server 192.0.2.11")
        lines.append(f"   server 192.0.2.12")
        lines.append("!")
        lines.append("tacacs-server host 192.0.2.11 key 7 xxxxxxxx")
        lines.append("tacacs-server host 192.0.2.12 key 7 xxxxxxxx")
        lines.append("!")

    # Username
    lines.append("username admin privilege 15 role network-admin secret sha512 xxxxxxxx")
    lines.append("!")

    # Banner
    lines.append('banner login\nAuthorized access only. Unauthorized use is prohibited.\nEOF')
    lines.append("!")
    lines.append("end")

    return "\n".join(lines)


ARISTA_SPECS: List[Dict] = [
    {
        "id": "CAMPUS-DIST-SW01", "hostname": "CAMPUS-DIST-SW01",
        "vlans": [
            {"id": 100, "name": "USERS",     "ip": "198.51.100.1", "vrf": "VRFA"},
            {"id": 200, "name": "VOICE",     "ip": "198.51.101.1", "vrf": "VRFA"},
            {"id": 300, "name": "IOT",       "ip": "198.51.102.1", "vrf": "VRFA"},
            {"id": 777, "name": "AP-MGMT",   "ip": "198.51.103.1", "vrf": "VRFA"},
            {"id": 4060,"name": "INBAND-MGMT","ip": "198.51.100.60","vrf": "MDMZ"},
        ],
        "mgmt_vlan": 4060, "access_count": 24, "nac": True,
        "uplink": {"type": "port-channel", "pc_id": 2000, "members": ["Ethernet27", "Ethernet28"]},
        "snmp_location": "Campus Distribution Building-A",
    },
    {
        "id": "CAMPUS-DIST-SW02", "hostname": "CAMPUS-DIST-SW02",
        "vlans": [
            {"id": 100, "name": "USERS",     "ip": "198.51.104.1", "vrf": "VRFA"},
            {"id": 130, "name": "PRINTERS",  "ip": "198.51.105.1", "vrf": "VRFA"},
            {"id": 3000,"name": "UPS-MON",   "ip": "198.51.106.1", "vrf": "VRFM"},
            {"id": 4060,"name": "INBAND-MGMT","ip": "198.51.100.61","vrf": "MDMZ"},
        ],
        "mgmt_vlan": 4060, "access_count": 24, "nac": False,
        "uplink": {"type": "port-channel", "pc_id": 2000, "members": ["Ethernet27", "Ethernet28"]},
        "snmp_location": "Campus Distribution Building-B",
    },
    {
        "id": "CAMPUS-ACCESS-SW03", "hostname": "CAMPUS-ACCESS-SW03",
        "vlans": [
            {"id": 100, "name": "USERS",     "ip": "198.51.107.1", "vrf": "VRFA"},
            {"id": 200, "name": "VOICE",     "ip": "198.51.108.1", "vrf": "VRFA"},
            {"id": 4060,"name": "INBAND-MGMT","ip": "198.51.100.62","vrf": "MDMZ"},
        ],
        "mgmt_vlan": 4060, "access_count": 24, "nac": True,
        "uplink": {"type": "trunk", "name": "Ethernet25"},
        "snmp_location": "Building-C Access Switch",
    },
    {
        "id": "CAMPUS-ACCESS-SW04", "hostname": "CAMPUS-ACCESS-SW04",
        "vlans": [
            {"id": 50,  "name": "RESEARCH",  "ip": "198.51.109.1", "vrf": "VRFB"},
            {"id": 60,  "name": "LAB",       "ip": "198.51.110.1", "vrf": "VRFB"},
            {"id": 4060,"name": "INBAND-MGMT","ip": "198.51.100.63","vrf": "MDMZ"},
        ],
        "mgmt_vlan": 4060, "access_count": 20, "nac": False,
        "uplink": {"type": "trunk", "name": "Ethernet25"},
        "snmp_location": "Building-D Research Access Switch",
    },
]


# ---------------------------------------------------------------------------
# Step 1 — sanitize originals and write to sanitized/
# ---------------------------------------------------------------------------

CISCO_HOSTNAME_MAP = {
    # <real production hostname> : <sanitized hostname>   (production keys redacted)
    "SRC-EDGE-01": "BLDG-FR-FLOOR1-SW01",
    "SRC-OOB-01":  "DATACTR-OOBSW-DX01",
    # remaining production hostname keys redacted for public release
}

print("=== Step 1: Sanitizing original configs ===")
for src_file in sorted((INPUT_DIR / "3850").glob("*.txt")):
    raw = src_file.read_text(encoding="utf-8", errors="replace")
    text = sanitize(raw)
    orig_hostname = next((l.split()[-1] for l in text.splitlines() if l.strip().startswith("hostname ")), src_file.stem)
    new_hostname = CISCO_HOSTNAME_MAP.get(orig_hostname, orig_hostname)
    text = _sanitize_hostname(text, new_hostname)
    text = _sanitize_snmp_location(text, new_hostname)
    text = _sanitize_snmp_chassis(text, new_hostname)
    # Scrub any remaining site-specific hostname-prefix references in
    # descriptions, VLAN names, chassis-id (real prefixes redacted)
    text = re.sub(r'\bSRC_[A-Za-z0-9_]+\b', new_hostname, text)
    # Scrub residual TACACS key hashes (Arista sometimes has them in plain text)
    text = re.sub(r'key 7 [0-9A-Fa-f]{10,}', 'key 7 xxxxxxxx', text)
    # Scrub internal VTP domain / SNMP contact references (real value redacted)
    text = text.replace("EXAMPLE-VTP-DOMAIN", "vtp domain CAMPUS")
    text = text.replace("snmp-server contact EXAMPLE-CONTACT", "snmp-server contact NOC")
    out_path = OUT_CISCO / f"{new_hostname}.txt"
    out_path.write_text(text, encoding="utf-8")
    print(f"  Sanitized: {src_file.name} -> {out_path.name}")

# Sanitize Arista original
arista_raw = (INPUT_DIR / "Arista" / "arista-comprehensive.txt").read_text(encoding="utf-8", errors="replace")
arista_text = sanitize(arista_raw)
arista_text = _sanitize_hostname(arista_text, "CAMPUS-DIST-SW01")
arista_text = _sanitize_snmp_location(arista_text, "Campus Distribution Building-A")
out_path = OUT_ARISTA / "CAMPUS-DIST-SW01-original.txt"
out_path.write_text(arista_text, encoding="utf-8")
print(f"  Sanitized: arista-comprehensive.txt -> {out_path.name}")

# ---------------------------------------------------------------------------
# Step 2 — generate new Cisco configs from specs
# ---------------------------------------------------------------------------
print("\n=== Step 2: Generating new Cisco configs ===")
for spec in CISCO_SPECS:
    cfg = build_cisco_config(spec)
    out_path = OUT_CISCO / f"{spec['id']}.txt"
    out_path.write_text(cfg, encoding="utf-8")
    print(f"  Generated: {out_path.name}")

# ---------------------------------------------------------------------------
# Step 3 — generate new Arista configs from specs
# ---------------------------------------------------------------------------
print("\n=== Step 3: Generating new Arista configs ===")
for spec in ARISTA_SPECS:
    cfg = build_arista_config(spec)
    out_path = OUT_ARISTA / f"{spec['id']}.txt"
    out_path.write_text(cfg, encoding="utf-8")
    print(f"  Generated: {out_path.name}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
cisco_files = list(OUT_CISCO.glob("*.txt"))
arista_files = list(OUT_ARISTA.glob("*.txt"))
print(f"\n=== Dataset summary ===")
print(f"  Cisco configs : {len(cisco_files)}")
print(f"  Arista configs: {len(arista_files)}")
print(f"  Total         : {len(cisco_files) + len(arista_files)}")
print(f"\nOutput directories:")
print(f"  {OUT_CISCO}")
print(f"  {OUT_ARISTA}")
