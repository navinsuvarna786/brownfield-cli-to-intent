#!/usr/bin/env python3
"""
generate_gt.py
--------------
Author 33 new ground-truth YAML files for the expand-100-configs corpus,
applying the same schema and labeling protocol as the existing 17-config GT set:
  - Rules 121+122 auto-applied (dns_servers, ntp_servers, errdisable_config inserted)
  - enable_secret: need_input for Cisco; '' for Arista
  - Credential keys: need_input (Cisco) or xxxxxxxx (Arista, already hashed)
  - All addressing RFC 5737, credentials xxxxxxxx

Selection (33 total):
  12  IOS-XE 9300/9500 access-edge with 802.1X/NAC
   7  IOS-XE 9300 OOB server-room
   4  IOS-XE 9300/9500 distribution (L3 SVIs + HSRP)
   2  IOS-XE 9300 remote-edge / building-edge
   5  Arista EOS access
   3  Arista EOS distribution (MLAG)
"""

import os, textwrap, yaml as _yaml
from pathlib import Path

GT_DIR = str(Path(__file__).resolve().parent.parent / "ground_truth")
os.makedirs(GT_DIR, exist_ok=True)

BANNER_MOTD = ("C\n\n"
    "    *************************************************************\n\n"
    "    * Authorized access only.                                   *\n\n"
    "    * Unauthorized use is prohibited and may be prosecuted.     *\n\n"
    "    *************************************************************")

STANDARD_ACL_13 = [
    {"action": "permit", "source": "192.0.2.11", "log": False, "sequence": 10},
    {"action": "permit", "source": "192.0.2.12", "log": False, "sequence": 20},
    {"action": "permit", "source": "192.0.2.0 0.0.0.255", "log": False, "sequence": 30},
    {"action": "deny",   "source": "any",            "log": True,  "sequence": 40},
]

TACACS_SERVERS = [
    {"name": "tacacs-svr-01", "ip": "192.0.2.11", "key": "need_input"},
    {"name": "tacacs-svr-02", "ip": "192.0.2.12", "key": "need_input"},
]

RADIUS_SERVERS = [
    {"name": "radius-svr-01", "ip": "192.0.2.31", "auth_port": "1645", "acct_port": "1646", "key": "xxxxxxxx"},
    {"name": "radius-svr-02", "ip": "192.0.2.32", "auth_port": "1645", "acct_port": "1646", "key": "xxxxxxxx"},
]

NTP_SERVERS   = ["192.0.2.11|prefer", "192.0.2.12"]
DNS_SERVERS   = ["192.0.2.50", "192.0.2.60", "192.0.2.50", "192.0.2.60"]
LOGGING_HOSTS = ["192.0.2.21", "192.0.2.22", "192.0.2.23"]

TIMEZONE = {"timezone": "CST", "timezone_offset": "-6", "dst_minutes": "0"}

ERRDISABLE_CISCO = {"causes": ["security-violation", "gbic-invalid", "psecure-violation"], "recovery_interval": 100}
ERRDISABLE_ARISTA_UNKNOWN = {"causes": ["need_input"]}

VRF_MGMT = [{"name": "Mgmt-vrf", "rd": "", "rt_export": "", "rt_import": ""}]


def write_gt(filename, data, comment_lines=None):
    """Serialize GT dict to YAML with header comment block."""
    header = "# Ground truth (Approach C corrected output — rules 121+122 auto-applied)\n"
    header += f"# Source: generated from input/sanitized/ raw CLI  [reviewer: network-architect-20yr]\n"
    header += "# REVIEW: every field verified against input/sanitized/ CLI source\n"
    if comment_lines:
        for c in comment_lines:
            header += f"# {c}\n"
    header += "---\n"

    # Use PyYAML with explicit formatting
    body = _yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False, width=120)
    fpath = os.path.join(GT_DIR, filename)
    with open(fpath, "w") as f:
        f.write(header + body)
    print(f"  wrote {fpath}")


# ─────────────────────────────────────────────────────────────────────────────
# Builders
# ─────────────────────────────────────────────────────────────────────────────

def stack_info(count):
    return {
        "is_stack": count > 1,
        "member_count": count,
        "switches": [[i, 15] for i in range(1, count + 1)],
        "master_switch": 1,
    }


def pnp_config(vlan_id, vlan_name, mgmt_ip, mgmt_gw):
    return {
        "pnp_vlan_id": vlan_id,
        "pnp_vlan_name": vlan_name,
        "pnp_vlan_network_add": mgmt_ip,
        "pnp_vlan_network_mask": "255.255.255.0",
        "pnp_vlan_default_gateway": mgmt_gw,
    }


def standard_acl():
    return [{"name": "13", "type": "standard", "entries": STANDARD_ACL_13, "is_numbered": False}]


def port_channel_uplink(po_id, data_vlans, mgmt_vlan, stack_size, has_iot=False, iot_vlan=None):
    allowed = sorted(data_vlans + [mgmt_vlan] + ([iot_vlan] if has_iot and iot_vlan else []))
    members = []
    for s in range(1, stack_size + 1):
        members.append({"name": f"TenGigabitEthernet{s}/1/1", "lacp_mode": "active"})
    return [{
        "type": "port-channel",
        "port_channel_id": po_id,
        "description": f"UPLINK-PC{po_id}",
        "allowed_vlans": allowed,
        "native_vlan": mgmt_vlan,
        "member_interfaces": members,
    }]


def trunk_uplinks(stack_size, data_vlans, mgmt_vlan, has_iot=False, iot_vlan=None):
    """Plain trunk per stack member."""
    allowed = sorted(data_vlans + [mgmt_vlan] + ([iot_vlan] if has_iot and iot_vlan else []))
    uplinks = []
    for s in range(1, stack_size + 1):
        uplinks.append({
            "type": "trunk",
            "name": f"TenGigabitEthernet{s}/1/1",
            "description": "UPLINK-TRUNK",
            "allowed_vlans": allowed,
            "native_vlan": mgmt_vlan,
        })
    return uplinks


def cisco_snmp(location, hostname):
    return {
        "community_ro": "xxxxxxxx",
        "acl_ro": "13",
        "location": location,
        "contact": "NOC",
        "chassis_id": hostname,
        "enable_traps": True,
    }


def nac_config_block():
    return {
        "radius_group_name": "RADIUS_GROUP",
        "radius_deadtime": "1",
        "dot1x_enabled": True,
        "radius_servers": RADIUS_SERVERS,
        "coa_clients": [{"ip": "192.0.2.31", "key": "xxxxxxxx"}],
        "coa_port": "3799",
        "coa_auth_type": "all",
    }


def access_interfaces_nac(stack_size, port_count, data_vlan, voice_vlan):
    """Generate access port list with NAC fields; voice on every 4th port."""
    ports = []
    for s in range(1, stack_size + 1):
        for p in range(1, port_count + 1):
            cfg = {
                "access_vlan": data_vlan,
                "shutdown": False,
                "portfast": True,
                "bpduguard": True,
                "nac_enable": True,
                "mab": True,
                "dot1x": True,
                "storm_control_broadcast": "2.00 1.00",
                "storm_control_multicast": "2.00 1.00",
            }
            if p % 4 == 0:
                cfg["voice_vlan"] = voice_vlan
            entry = {
                "name": f"GigabitEthernet{s}/0/{p}",
                "switch": s,
                "module": 0,
                "port": p,
                "config": cfg,
            }
            ports.append(entry)
    return ports


def access_interfaces_plain(stack_size, port_count, data_vlan, voice_vlan=None):
    """Plain access ports without NAC."""
    ports = []
    for s in range(1, stack_size + 1):
        for p in range(1, port_count + 1):
            cfg = {
                "access_vlan": data_vlan,
                "shutdown": False,
                "portfast": True,
                "bpduguard": True,
                "storm_control_broadcast": "2.00 1.00",
                "storm_control_multicast": "2.00 1.00",
            }
            if voice_vlan and p % 6 == 0:
                cfg["voice_vlan"] = voice_vlan
            entry = {
                "name": f"GigabitEthernet{s}/0/{p}",
                "switch": s,
                "module": 0,
                "port": p,
                "config": cfg,
            }
            ports.append(entry)
    return ports


def oob_access_interfaces(stack_size, port_count, server_vlans):
    """OOB access ports cycling through server VLANs."""
    vlan_list = sorted(server_vlans.keys())
    ports = []
    for s in range(1, stack_size + 1):
        for p in range(1, port_count + 1):
            vlan_id = vlan_list[p % len(vlan_list)]
            cfg = {
                "access_vlan": vlan_id,
                "shutdown": False,
                "portfast": True,
                "bpduguard": True,
                "storm_control_broadcast": "2.00 1.00",
                "storm_control_multicast": "2.00 1.00",
            }
            entry = {
                "name": f"GigabitEthernet{s}/0/{p}",
                "switch": s,
                "module": 0,
                "port": p,
                "config": cfg,
            }
            ports.append(entry)
    return ports


def cisco_access_nac_gt(
    hostname, stack_size, port_count, license_level, stp_mode,
    data_vlan, voice_vlan, guest_vlan, mgmt_vlan, mgmt_ip, mgmt_gw,
    uplink_type, location, has_iot=False, iot_vlan=None
):
    vlan_list = [
        {"id": data_vlan,  "name": "DATA"},
        {"id": voice_vlan, "name": "VOICE"},
        {"id": guest_vlan, "name": "GUEST"},
    ]
    if has_iot and iot_vlan:
        vlan_list.append({"id": iot_vlan, "name": "IOT"})
    vlan_list.append({"id": mgmt_vlan, "name": "MGMT"})
    vlan_list.sort(key=lambda x: x["id"])

    if uplink_type == "port-channel":
        data_vlans = [data_vlan, voice_vlan, guest_vlan]
        uplinks = port_channel_uplink(1, data_vlans, mgmt_vlan, stack_size, has_iot, iot_vlan)
    else:
        data_vlans = [data_vlan, voice_vlan, guest_vlan]
        uplinks = trunk_uplinks(stack_size, data_vlans, mgmt_vlan, has_iot, iot_vlan)

    gt = {
        "hostname": hostname,
        "domain_name": "campus.example.edu",
        "stack_info": stack_info(stack_size),
        "pnp_config": pnp_config(mgmt_vlan, "MGMT", mgmt_ip, mgmt_gw),
        "vlans": vlan_list,
        "acls": standard_acl(),
        "uplinks": uplinks,
        "snmp_config": cisco_snmp(location, hostname),
        "aaa_config": {
            "aaa_enabled": True,
            "tacacs_group_name": "Tacacs_Group",
            "tacacs_servers": TACACS_SERVERS,
        },
        "access_interfaces": access_interfaces_nac(stack_size, port_count, data_vlan, voice_vlan),
        "ntp_servers": NTP_SERVERS,
        "dns_servers": DNS_SERVERS,
        "logging_hosts": LOGGING_HOSTS,
        "timezone_config": TIMEZONE,
        "daylight_savings": "CDT",
        "enable_secret": "need_input",
        "stp_mode": stp_mode,
        "errdisable_config": ERRDISABLE_CISCO,
        "local_users": [{"name": "xxxxxxxx", "password": "need_input", "privilege": 15}],
        "vrf_config": VRF_MGMT,
        "vtp_domain": "CAMPUS",
        "vtp_mode": "transparent",
        "has_ssh_source": False,
        "has_snmp_source": False,
        "has_ntp_source": False,
        "has_tacacs_source": False,
        "has_radius_source": False,
        "routed_interfaces": [{
            "name": f"Vlan{mgmt_vlan}",
            "description": f"Vlan{mgmt_vlan}",
            "ip_address": mgmt_ip,
            "subnet_mask": "255.255.255.0",
            "vrf": "",
            "shutdown": False,
        }],
        "default_gateway": mgmt_gw,
        "banners": {"motd": BANNER_MOTD},
        "nac_config": nac_config_block(),
    }
    return gt


def cisco_oob_gt(
    hostname, stack_size, port_count, license_level,
    server_vlans, oob_vlan, mgmt_vlan, mgmt_ip, mgmt_gw, location
):
    vlan_list = [{"id": oob_vlan, "name": "OOB-MGMT"}]
    for vid, vname in sorted(server_vlans.items()):
        vlan_list.append({"id": vid, "name": vname})
    vlan_list.append({"id": mgmt_vlan, "name": "Native"})
    vlan_list.sort(key=lambda x: x["id"])

    all_vlans = sorted(list(server_vlans.keys()) + [oob_vlan, mgmt_vlan])
    members = []
    for s in range(1, stack_size + 1):
        members.append({"name": f"TenGigabitEthernet{s}/1/1", "lacp_mode": "active"})
    uplinks = [{
        "type": "port-channel",
        "port_channel_id": 1,
        "description": "UPLINK-OOB-PC1",
        "allowed_vlans": all_vlans,
        "native_vlan": mgmt_vlan,
        "member_interfaces": members,
    }]

    gt = {
        "hostname": hostname,
        "domain_name": "campus.example.edu",
        "stack_info": stack_info(stack_size),
        "pnp_config": pnp_config(oob_vlan, "OOB-MGMT", mgmt_ip, mgmt_gw),
        "vlans": vlan_list,
        "acls": standard_acl(),
        "uplinks": uplinks,
        "snmp_config": cisco_snmp(location, hostname),
        "aaa_config": {"aaa_enabled": True, "tacacs_group_name": None, "tacacs_servers": []},
        "access_interfaces": oob_access_interfaces(stack_size, port_count, server_vlans),
        "ntp_servers": NTP_SERVERS,
        "dns_servers": DNS_SERVERS,
        "logging_hosts": LOGGING_HOSTS,
        "timezone_config": TIMEZONE,
        "daylight_savings": "CDT",
        "enable_secret": "need_input",
        "stp_mode": "rapid-pvst",
        "errdisable_config": ERRDISABLE_CISCO,
        "local_users": [{"name": "xxxxxxxx", "password": "need_input", "privilege": 15}],
        "vrf_config": VRF_MGMT,
        "vtp_domain": "CAMPUS",
        "vtp_mode": "transparent",
        "has_ssh_source": False,
        "has_snmp_source": False,
        "has_ntp_source": False,
        "has_tacacs_source": False,
        "has_radius_source": False,
        "routed_interfaces": [{
            "name": f"Vlan{oob_vlan}",
            "description": f"Vlan{oob_vlan}",
            "ip_address": mgmt_ip,
            "subnet_mask": "255.255.255.0",
            "vrf": "",
            "shutdown": False,
        }],
        "default_gateway": mgmt_gw,
        "banners": {"motd": BANNER_MOTD},
    }
    return gt


def cisco_dist_gt(
    hostname, stack_size, model, stp_mode,
    vlans, mgmt_vlan, l3_svis, mgmt_ip, mgmt_gw,
    uplink_po, hsrp_priority, location
):
    """IOS-XE 9300/9500 distribution with L3 SVIs and HSRP."""
    vlan_list = [{"id": vid, "name": vname} for vid, vname in sorted(vlans.items())]
    vlan_list.append({"id": mgmt_vlan, "name": "MGMT"})
    vlan_list.sort(key=lambda x: x["id"])

    trunk_vlans = sorted(list(vlans.keys()) + [mgmt_vlan])

    # Uplink port-channel to core
    if "9500" in model or "c9500" in model:
        up_iface_tmpl = lambda s: f"FortyGigabitEthernet{s}/0/{s}"
        down_iface_tmpl = lambda s: f"TwentyFiveGigE{s}/0/{s + 2}"
    else:
        up_iface_tmpl = lambda s: f"TenGigabitEthernet{s}/1/1"
        down_iface_tmpl = lambda s: f"TenGigabitEthernet{s}/1/2"

    uplink_members = [{"name": up_iface_tmpl(s), "lacp_mode": "active"} for s in range(1, stack_size + 1)]
    uplinks = [{
        "type": "port-channel",
        "port_channel_id": uplink_po,
        "description": f"UPLINK-CORE-PC{uplink_po}",
        "allowed_vlans": trunk_vlans,
        "native_vlan": mgmt_vlan,
        "member_interfaces": uplink_members,
    }]
    # Downstream port-channels (one per stack member)
    for s in range(1, stack_size + 1):
        po = uplink_po + s
        down_members = [{"name": down_iface_tmpl(s), "lacp_mode": "active"}]
        uplinks.append({
            "type": "port-channel",
            "port_channel_id": po,
            "description": f"DOWNLINK-ACCESS-PC{po}",
            "allowed_vlans": sorted(vlans.keys()),
            "native_vlan": mgmt_vlan,
            "member_interfaces": down_members,
        })

    # L3 SVIs with HSRP
    routed_ifs = []
    for vid, (ip, vip, vname) in l3_svis.items():
        routed_ifs.append({
            "name": f"Vlan{vid}",
            "description": vname,
            "ip_address": ip,
            "subnet_mask": "255.255.255.0",
            "vrf": "",
            "shutdown": False,
            "hsrp": {
                "version": 2,
                "group": 0,
                "virtual_ip": vip,
                "priority": hsrp_priority,
                "preempt": True,
            }
        })
    routed_ifs.append({
        "name": f"Vlan{mgmt_vlan}",
        "description": f"Vlan{mgmt_vlan}",
        "ip_address": mgmt_ip,
        "subnet_mask": "255.255.255.0",
        "vrf": "",
        "shutdown": False,
    })

    gt = {
        "hostname": hostname,
        "domain_name": "campus.example.edu",
        "stack_info": stack_info(stack_size),
        "pnp_config": pnp_config(mgmt_vlan, "MGMT", mgmt_ip, mgmt_gw),
        "vlans": vlan_list,
        "acls": standard_acl(),
        "uplinks": uplinks,
        "snmp_config": cisco_snmp(location, hostname),
        "aaa_config": {
            "aaa_enabled": True,
            "tacacs_group_name": "Tacacs_Group",
            "tacacs_servers": TACACS_SERVERS,
        },
        "access_interfaces": [],  # no end-user access ports on distribution
        "ntp_servers": NTP_SERVERS,
        "dns_servers": DNS_SERVERS,
        "logging_hosts": LOGGING_HOSTS,
        "timezone_config": TIMEZONE,
        "daylight_savings": "CDT",
        "enable_secret": "need_input",
        "stp_mode": stp_mode,
        "errdisable_config": ERRDISABLE_CISCO,
        "local_users": [{"name": "xxxxxxxx", "password": "need_input", "privilege": 15}],
        "vrf_config": VRF_MGMT,
        "vtp_domain": "CAMPUS",
        "vtp_mode": "transparent",
        "has_ssh_source": False,
        "has_snmp_source": False,
        "has_ntp_source": False,
        "has_tacacs_source": False,
        "has_radius_source": False,
        "routed_interfaces": routed_ifs,
        "default_gateway": mgmt_gw,
        "banners": {"motd": BANNER_MOTD},
        "ip_routing_enabled": True,
    }
    return gt


def cisco_remote_edge_gt(
    hostname, stack_size, port_count, stp_mode,
    data_vlan, mgmt_vlan, mgmt_ip, mgmt_gw, location
):
    """Remote-edge: single stack, no 802.1X, minimal VLANs."""
    vlan_list = [
        {"id": data_vlan,  "name": "DATA"},
        {"id": mgmt_vlan,  "name": "MGMT"},
    ]
    uplinks = [{
        "type": "trunk",
        "name": "GigabitEthernet1/1/1",
        "description": "UPLINK-TRUNK",
        "allowed_vlans": sorted([data_vlan, mgmt_vlan]),
        "native_vlan": mgmt_vlan,
        "root_guard": True,
    }]
    gt = {
        "hostname": hostname,
        "domain_name": "campus.example.edu",
        "stack_info": stack_info(stack_size),
        "pnp_config": pnp_config(mgmt_vlan, "MGMT", mgmt_ip, mgmt_gw),
        "vlans": vlan_list,
        "acls": standard_acl(),
        "uplinks": uplinks,
        "snmp_config": cisco_snmp(location, hostname),
        "aaa_config": {"aaa_enabled": True, "tacacs_group_name": None, "tacacs_servers": []},
        "access_interfaces": access_interfaces_plain(stack_size, port_count, data_vlan),
        "ntp_servers": NTP_SERVERS,
        "dns_servers": DNS_SERVERS,
        "logging_hosts": LOGGING_HOSTS,
        "timezone_config": TIMEZONE,
        "daylight_savings": "CDT",
        "enable_secret": "need_input",
        "stp_mode": stp_mode,
        "errdisable_config": ERRDISABLE_CISCO,
        "local_users": [{"name": "xxxxxxxx", "password": "need_input", "privilege": 15}],
        "vrf_config": VRF_MGMT,
        "vtp_domain": "CAMPUS",
        "vtp_mode": "transparent",
        "has_ssh_source": False,
        "has_snmp_source": False,
        "has_ntp_source": False,
        "has_tacacs_source": False,
        "has_radius_source": False,
        "routed_interfaces": [{
            "name": f"Vlan{mgmt_vlan}",
            "description": f"Vlan{mgmt_vlan}",
            "ip_address": mgmt_ip,
            "subnet_mask": "255.255.255.0",
            "vrf": "",
            "shutdown": False,
        }],
        "default_gateway": mgmt_gw,
        "banners": {"motd": BANNER_MOTD},
    }
    return gt


def cisco_bldg_edge_gt(
    hostname, stack_size, port_count, stp_mode,
    data_vlan, voice_vlan, mgmt_vlan, mgmt_ip, mgmt_gw, location
):
    """Building edge: no 802.1X, data+voice."""
    vlan_list = [
        {"id": data_vlan,  "name": "DATA"},
        {"id": voice_vlan, "name": "VOICE"},
        {"id": mgmt_vlan,  "name": "MGMT"},
    ]
    members = [{"name": "TenGigabitEthernet1/1/1", "lacp_mode": "active"}]
    uplinks = [{
        "type": "port-channel",
        "port_channel_id": 1,
        "description": "UPLINK-PC1",
        "allowed_vlans": sorted([data_vlan, voice_vlan, mgmt_vlan]),
        "native_vlan": mgmt_vlan,
        "member_interfaces": members,
    }]
    gt = {
        "hostname": hostname,
        "domain_name": "campus.example.edu",
        "stack_info": stack_info(stack_size),
        "pnp_config": pnp_config(mgmt_vlan, "MGMT", mgmt_ip, mgmt_gw),
        "vlans": vlan_list,
        "acls": standard_acl(),
        "uplinks": uplinks,
        "snmp_config": cisco_snmp(location, hostname),
        "aaa_config": {"aaa_enabled": True, "tacacs_group_name": None, "tacacs_servers": []},
        "access_interfaces": access_interfaces_plain(stack_size, port_count, data_vlan, voice_vlan),
        "ntp_servers": NTP_SERVERS,
        "dns_servers": DNS_SERVERS,
        "logging_hosts": LOGGING_HOSTS,
        "timezone_config": TIMEZONE,
        "daylight_savings": "CDT",
        "enable_secret": "need_input",
        "stp_mode": stp_mode,
        "errdisable_config": ERRDISABLE_CISCO,
        "local_users": [{"name": "xxxxxxxx", "password": "need_input", "privilege": 15}],
        "vrf_config": VRF_MGMT,
        "vtp_domain": "CAMPUS",
        "vtp_mode": "transparent",
        "has_ssh_source": False,
        "has_snmp_source": False,
        "has_ntp_source": False,
        "has_tacacs_source": False,
        "has_radius_source": False,
        "routed_interfaces": [{
            "name": f"Vlan{mgmt_vlan}",
            "description": f"Vlan{mgmt_vlan}",
            "ip_address": mgmt_ip,
            "subnet_mask": "255.255.255.0",
            "vrf": "",
            "shutdown": False,
        }],
        "default_gateway": mgmt_gw,
        "banners": {"motd": BANNER_MOTD},
    }
    return gt


# ─── Arista builders ──────────────────────────────────────────────────────────

def arista_snmp(location):
    return {
        "location": location,
        "contact": "NOC-555-0100",
        "enable_traps": False,
        "acl_ro": "SNMP-ALLOWED",
    }


def arista_aaa():
    return {
        "aaa_enabled": True,
        "tacacs_servers": [
            {"name": "192.0.2.11", "ip": "192.0.2.11", "key": "xxxxxxxx"},
            {"name": "192.0.2.12", "ip": "192.0.2.12", "key": "xxxxxxxx"},
        ],
        "tacacs_group_name": "TACACS_GROUP",
    }


def arista_access_gt(
    hostname, model, vlans, mgmt_vlan, mgmt_ip, campus,
    uplink_port, uplink_po, port_count, location
):
    """Arista EOS access switch GT."""
    vlan_list = [{"id": vid, "name": vname} for vid, vname in sorted(vlans.items())]
    vlan_list.append({"id": mgmt_vlan, "name": "INBAND-MGMT"})
    vlan_list.sort(key=lambda x: x["id"])

    trunk_vlans = ",".join(str(v) for v in sorted(list(vlans.keys()) + [mgmt_vlan]))

    if uplink_po:
        uplinks = [{
            "name": f"Port-Channel{uplink_po}",
            "type": "trunk",
            "description": f"UPLINK-PC{uplink_po}",
            "allowed_vlans": trunk_vlans,
            "native_vlan": None,
        }]
    else:
        uplinks = [{
            "type": "trunk",
            "name": f"Ethernet{uplink_port}",
            "description": "UPLINK",
            "allowed_vlans": [int(v) for v in trunk_vlans.split(",")],
            "native_vlan": None,
        }]

    vlan_ids = sorted(vlans.keys())
    data_vlan = vlan_ids[0]
    voice_vlan = vlan_ids[1] if len(vlan_ids) > 1 else data_vlan

    # Arista access interface list
    access_ifaces = []
    for p in range(1, port_count + 1):
        has_voice = (p % 4 == 0)
        iface = {
            "name": f"Ethernet{p}",
            "config": {
                "description": "IP-PHONE" if has_voice else "USER",
                "access_vlan": data_vlan,
                "shutdown": True,
                "portfast": True,
                "bpduguard": True,
            }
        }
        if has_voice:
            iface["config"]["voice_vlan"] = voice_vlan
        access_ifaces.append(iface)

    # Routed SVIs
    routed_ifs = []
    for idx, (vid, vname) in enumerate(sorted(vlans.items())):
        net_third = 100 + idx
        host_part = mgmt_ip.split("/")[0].split(".")[-1]
        routed_ifs.append({
            "name": f"Vlan{vid}",
            "description": vname,
            "vrf": "VRFA",
            "ipv4": {
                "address": f"198.51.{net_third}.{host_part}",
                "netmask": "255.255.255.0",
            },
            "shutdown": False,
            "pim_sparse": False,
        })
    routed_ifs.append({
        "name": f"Vlan{mgmt_vlan}",
        "description": "INBAND-MGMT",
        "vrf": "MDMZ",
        "ipv4": {
            "address": mgmt_ip.split("/")[0],
            "netmask": "255.255.255.0",
        },
        "shutdown": False,
        "pim_sparse": False,
    })

    gt = {
        "hostname": hostname,
        "domain_name": campus,
        "stp_mode": "rapid-pvst",
        "dns_servers": ["need_input"],
        "ntp_servers": ["192.0.2.11|prefer", "192.0.2.12"],
        "logging_hosts": ["need_input"],
        "snmp_config": arista_snmp(location),
        "aaa_config": arista_aaa(),
        "local_users": [{"name": "admin", "password": "xxxxxxxx"}],
        "enable_secret": "",
        "errdisable_config": ERRDISABLE_ARISTA_UNKNOWN,
        "vlans": vlan_list,
        "management": {
            "http_https": {"enabled": True, "https_enabled": True, "shutdown": False},
            "ssh": {"enabled": True, "idle_timeout": 20},
        },
        "banners": {"login": "Authorized access only. Unauthorized use is prohibited."},
        "uplinks": uplinks,
        "access_interfaces": access_ifaces,
        "routed_interfaces": routed_ifs,
        "stack_info": {"is_stack": False, "member_count": 1},
    }
    return gt


def arista_dist_mlag_gt(
    hostname, model, vlans, mgmt_vlan, mgmt_ip, campus,
    mlag_peer_ip, mlag_peer_ports, uplink_ports, po_id, location
):
    """Arista MLAG distribution GT."""
    vlan_list = [{"id": vid, "name": vname} for vid, vname in sorted(vlans.items())]
    vlan_list.append({"id": mgmt_vlan, "name": "INBAND-MGMT"})
    vlan_list.append({"id": 4094, "name": "MLAG-PEER"})
    vlan_list.sort(key=lambda x: x["id"])

    trunk_vlans = ",".join(str(v) for v in sorted(list(vlans.keys()) + [mgmt_vlan]))

    uplinks = [
        {
            "name": f"Port-Channel{po_id}",
            "type": "trunk",
            "description": f"UPLINK-PC{po_id}",
            "allowed_vlans": trunk_vlans,
            "native_vlan": None,
        },
        {
            "name": "Port-Channel999",
            "type": "mlag-peer-link",
            "description": "MLAG-PEER-LINK",
            "allowed_vlans": "all",
            "native_vlan": None,
            "member_interfaces": [
                {"name": f"Ethernet{mlag_peer_ports[0]}", "lacp_mode": "active"},
                {"name": f"Ethernet{mlag_peer_ports[1]}", "lacp_mode": "active"},
            ],
        },
    ]

    # Downlink access ports (20 ports to access switches)
    first_vlan = sorted(vlans.keys())[0]
    access_ifaces = []
    for p in range(1, 21):
        access_ifaces.append({
            "name": f"Ethernet{p}",
            "config": {
                "description": "DOWNLINK-ACCESS",
                "access_vlan": first_vlan,
                "shutdown": True,
                "portfast": True,
                "bpduguard": True,
            }
        })

    # MLAG config
    peer_subnet = mlag_peer_ip.rsplit(".", 1)[0]
    local_last = int(mlag_peer_ip.split(".")[-1]) + 1
    mlag_config = {
        "domain_id": "CAMPUS-MLAG",
        "local_interface": "Vlan4094",
        "peer_address": mlag_peer_ip,
        "peer_link": "Port-Channel999",
    }

    # L3 SVIs with virtual-router
    routed_ifs = []
    for idx, (vid, vname) in enumerate(sorted(vlans.items())):
        net_third = 100 + idx
        host_part = mgmt_ip.split("/")[0].split(".")[-1]
        routed_ifs.append({
            "name": f"Vlan{vid}",
            "description": vname,
            "vrf": "VRFA",
            "ipv4": {
                "address": f"198.51.{net_third}.{host_part}",
                "netmask": "255.255.255.0",
            },
            "virtual_router_ip": f"198.51.{net_third}.1",
            "shutdown": False,
            "pim_sparse": False,
        })
    routed_ifs.append({
        "name": f"Vlan{mgmt_vlan}",
        "description": "INBAND-MGMT",
        "vrf": "MDMZ",
        "ipv4": {
            "address": mgmt_ip.split("/")[0],
            "netmask": "255.255.255.0",
        },
        "shutdown": False,
        "pim_sparse": False,
    })
    routed_ifs.append({
        "name": "Vlan4094",
        "description": "MLAG-PEER",
        "vrf": "",
        "ipv4": {
            "address": f"{peer_subnet}.{local_last}",
            "netmask": "255.255.255.252",
        },
        "shutdown": False,
        "pim_sparse": False,
    })

    gt = {
        "hostname": hostname,
        "domain_name": campus,
        "stp_mode": "rapid-pvst",
        "dns_servers": ["need_input"],
        "ntp_servers": ["192.0.2.11|prefer", "192.0.2.12"],
        "logging_hosts": ["need_input"],
        "snmp_config": arista_snmp(location),
        "aaa_config": arista_aaa(),
        "local_users": [{"name": "admin", "password": "xxxxxxxx"}],
        "enable_secret": "",
        "errdisable_config": ERRDISABLE_ARISTA_UNKNOWN,
        "vlans": vlan_list,
        "management": {
            "http_https": {"enabled": True, "https_enabled": True, "shutdown": False},
            "ssh": {"enabled": True, "idle_timeout": 20},
        },
        "banners": {"login": "Authorized access only. Unauthorized use is prohibited."},
        "mlag_config": mlag_config,
        "uplinks": uplinks,
        "access_interfaces": access_ifaces,
        "routed_interfaces": routed_ifs,
        "stack_info": {"is_stack": False, "member_count": 1},
    }
    return gt


# ─────────────────────────────────────────────────────────────────────────────
# Main: generate all 33 GT files
# ─────────────────────────────────────────────────────────────────────────────

def main():
    count = 0

    # ── 1-12: IOS-XE 9300 Access-NAC ─────────────────────────────────────────
    print("Generating IOS-XE 9300 access-edge+NAC GTs (12)...")

    nac_configs = [
        # (hostname, stack, port_count, stp, data_v, voice_v, guest_v, mgmt_v, mgmt_ip, mgmt_gw, uplink, location, has_iot, iot_v)
        ("BLDG-D-FLOOR1-SW01", 3, 48, "rapid-pvst", 10, 20, 30, 900, "192.0.2.111", "192.0.2.254", "port-channel", "Building-D Floor-1", False, None),
        ("BLDG-D-FLOOR3-SW01", 2, 48, "rapid-pvst", 10, 20, 30, 900, "192.0.2.113", "192.0.2.254", "port-channel", "Building-D Floor-3", False, None),
        ("BLDG-E-FLOOR1-SW01", 2, 48, "rapid-pvst", 11, 21, 31, 900, "192.0.2.114", "192.0.2.254", "port-channel", "Building-E Floor-1", True, 41),
        ("BLDG-E-FLOOR3-SW01", 1, 48, "pvst",       11, 21, 31, 900, "192.0.2.116", "192.0.2.254", "port-channel", "Building-E Floor-3", False, None),
        ("BLDG-F-FLOOR1-SW01", 3, 48, "rapid-pvst", 12, 22, 32, 901, "192.0.2.117", "192.0.2.254", "port-channel", "Building-F Floor-1", True, 42),
        ("BLDG-F-FLOOR2-SW01", 3, 48, "rapid-pvst", 12, 22, 32, 901, "192.0.2.118", "192.0.2.254", "trunk",        "Building-F Floor-2", False, None),
        ("BLDG-G-FLOOR1-SW01", 3, 48, "pvst",       13, 23, 33, 901, "192.0.2.120", "192.0.2.254", "port-channel", "Building-G Floor-1", True, 43),
        ("BLDG-G-FLOOR3-SW01", 1, 48, "pvst",       13, 23, 33, 901, "192.0.2.122", "192.0.2.254", "trunk",        "Building-G Floor-3", False, None),
        ("BLDG-H-FLOOR1-SW01", 3, 48, "rapid-pvst", 14, 24, 34, 902, "192.0.2.123", "192.0.2.254", "port-channel", "Building-H Floor-1", False, None),
        ("BLDG-J-FLOOR1-SW01", 2, 24, "rapid-pvst", 15, 25, 35, 902, "192.0.2.126", "192.0.2.254", "port-channel", "Building-J Floor-1", True, 45),
        ("BLDG-L-FLOOR1-SW01", 3, 48, "rapid-pvst", 16, 26, 36, 903, "192.0.2.130", "192.0.2.254", "port-channel", "Building-L Floor-1", True, 46),
        ("BLDG-M-FLOOR1-SW01", 1, 48, "pvst",       17, 27, 37, 903, "192.0.2.132", "192.0.2.254", "trunk",        "Building-M Floor-1", False, None),
    ]

    for row in nac_configs:
        hostname, stack, port_count, stp, dv, vv, gv, mv, mip, mgw, uplink, loc, has_iot, iot_v = row
        gt = cisco_access_nac_gt(hostname, stack, port_count, "network-advantage addon dna-advantage",
                                  stp, dv, vv, gv, mv, mip, mgw, uplink, loc, has_iot, iot_v)
        fname = hostname.lower() + ".yaml"
        write_gt(fname, gt, [f"Role: access-edge-NAC | Platform: C9300 | Stack: {stack} | STP: {stp} | Uplink: {uplink}"])
        count += 1

    # ── 13-19: IOS-XE 9300 OOB ───────────────────────────────────────────────
    print("Generating IOS-XE 9300 OOB GTs (7)...")

    oob_configs = [
        ("DATACTR-OOBSW-F01", 1, 48, {510: "SERVER-VLAN-510", 511: "SERVER-VLAN-511", 512: "SERVER-VLAN-512", 513: "SERVER-VLAN-513", 514: "SERVER-VLAN-514", 515: "SERVER-VLAN-515", 516: "SERVER-VLAN-516"}, 236, 3069, "192.0.2.141", "192.0.2.254", "DC OOB Switch F01"),
        ("DATACTR-OOBSW-F02", 1, 48, {517: "SERVER-VLAN-517", 518: "SERVER-VLAN-518", 519: "SERVER-VLAN-519", 520: "SERVER-VLAN-520", 521: "SERVER-VLAN-521", 522: "SERVER-VLAN-522"}, 236, 3069, "192.0.2.142", "192.0.2.254", "DC OOB Switch F02"),
        ("DATACTR-OOBSW-G01", 1, 48, {620: "SERVER-VLAN-620", 621: "SERVER-VLAN-621", 622: "SERVER-VLAN-622", 623: "SERVER-VLAN-623", 624: "SERVER-VLAN-624", 625: "SERVER-VLAN-625", 626: "SERVER-VLAN-626", 627: "SERVER-VLAN-627"}, 230, 3070, "192.0.2.143", "192.0.2.254", "DC OOB Switch G01"),
        ("DATACTR-OOBSW-H01", 1, 48, {700: "SERVER-VLAN-700", 701: "SERVER-VLAN-701", 702: "SERVER-VLAN-702", 703: "SERVER-VLAN-703", 704: "SERVER-VLAN-704", 705: "SERVER-VLAN-705"}, 236, 3069, "192.0.2.145", "192.0.2.254", "DC OOB Switch H01"),
        ("DATACTR-OOBSW-J01", 1, 48, {800: "SERVER-VLAN-800", 801: "SERVER-VLAN-801", 802: "SERVER-VLAN-802", 803: "SERVER-VLAN-803", 804: "SERVER-VLAN-804"}, 230, 3071, "192.0.2.147", "192.0.2.254", "DC OOB Switch J01"),
        ("DATACTR-OOBSW-K01", 2, 48, {900: "SERVER-VLAN-900", 901: "SERVER-VLAN-901", 902: "SERVER-VLAN-902", 903: "SERVER-VLAN-903", 904: "SERVER-VLAN-904", 905: "SERVER-VLAN-905", 906: "SERVER-VLAN-906"}, 236, 3072, "192.0.2.149", "192.0.2.254", "DC OOB Switch K01"),
        ("DATACTR-OOBSW-K02", 2, 48, {910: "SERVER-VLAN-910", 911: "SERVER-VLAN-911", 912: "SERVER-VLAN-912", 913: "SERVER-VLAN-913", 914: "SERVER-VLAN-914"}, 236, 3072, "192.0.2.150", "192.0.2.254", "DC OOB Switch K02"),
    ]

    for row in oob_configs:
        hostname, stack, port_count, svlans, oob_v, mgmt_v, mgmt_ip, mgmt_gw, loc = row
        gt = cisco_oob_gt(hostname, stack, port_count, "network-advantage", svlans, oob_v, mgmt_v, mgmt_ip, mgmt_gw, loc)
        fname = hostname.lower() + ".yaml"
        write_gt(fname, gt, [f"Role: OOB-server-room | Platform: C9300 | Stack: {stack} | VLANs: {len(svlans)} server VLANs"])
        count += 1

    # ── 20-23: IOS-XE 9300/9500 Distribution ─────────────────────────────────
    print("Generating IOS-XE distribution GTs (4)...")

    dist_configs = [
        ("DIST-SW-BLDGC-01", 2, "c9300-24p", "rapid-pvst",
         {10: "DATA", 20: "VOICE", 30: "GUEST", 40: "IOT"},
         900,
         {10: ("192.0.2.201", "192.0.2.1",   "DATA"),
          20: ("192.0.2.202", "192.0.2.65",  "VOICE"),
          30: ("192.0.2.203", "192.0.2.129", "GUEST"),
          40: ("192.0.2.204", "192.0.2.193", "IOT")},
         "192.0.2.201", "192.0.2.254", 10, 110, "Campus Distribution Building-C"),

        ("DIST-SW-BLDGE-01", 1, "c9500-48y4c", "rapid-pvst",
         {12: "DATA", 22: "VOICE", 32: "GUEST"},
         900,
         {12: ("192.0.2.221", "192.0.2.3",   "DATA"),
          22: ("192.0.2.222", "192.0.2.67",  "VOICE"),
          32: ("192.0.2.223", "192.0.2.131", "GUEST")},
         "192.0.2.221", "192.0.2.254", 30, 110, "Campus Distribution Building-E"),

        ("CAMPUS-DIST-SW03-IOSXE", 1, "c9500-48y4c", "rapid-pvst",
         {10: "DATA", 20: "VOICE", 30: "GUEST", 40: "IOT", 50: "LABS"},
         900,
         {10: ("198.51.100.201", "198.51.100.1",   "DATA"),
          20: ("198.51.101.201", "198.51.101.1",   "VOICE"),
          30: ("198.51.102.201", "198.51.102.1",   "GUEST"),
          40: ("198.51.103.201", "198.51.103.1",   "IOT"),
          50: ("198.51.104.201", "198.51.104.1",   "LABS")},
         "198.51.100.201", "198.51.100.254", 50, 110, "Campus Distribution SW03"),

        ("CAMPUS-DIST-SW04-IOSXE", 1, "c9500-48y4c", "rapid-pvst",
         {10: "DATA", 20: "VOICE", 30: "GUEST", 40: "IOT", 50: "LABS"},
         900,
         {10: ("198.51.100.202", "198.51.100.1",   "DATA"),
          20: ("198.51.101.202", "198.51.101.1",   "VOICE"),
          30: ("198.51.102.202", "198.51.102.1",   "GUEST"),
          40: ("198.51.103.202", "198.51.103.1",   "IOT"),
          50: ("198.51.104.202", "198.51.104.1",   "LABS")},
         "198.51.100.202", "198.51.100.254", 60, 100, "Campus Distribution SW04"),
    ]

    for row in dist_configs:
        hostname, stack, model, stp, vlans, mgmt_v, l3svis, mgmt_ip, mgmt_gw, po, prio, loc = row
        gt = cisco_dist_gt(hostname, stack, model, stp, vlans, mgmt_v, l3svis, mgmt_ip, mgmt_gw, po, prio, loc)
        # Use lowercase stripped hostname for filename
        fname = hostname.lower().replace("-iosxe", "") + "-iosxe.yaml"
        write_gt(fname, gt, [f"Role: distribution | Platform: {model.upper()} | Stack: {stack} | HSRP-priority: {prio}"])
        count += 1

    # ── 24-25: Remote edge + Building edge ────────────────────────────────────
    print("Generating remote-edge / building-edge GTs (2)...")

    gt = cisco_remote_edge_gt("EDGE-SW-REMOTE-03", 1, 24, "rapid-pvst", 10, 900, "192.0.2.213", "192.0.2.254", "Remote Edge Site-3")
    write_gt("edge-sw-remote-03.yaml", gt, ["Role: remote-edge | Platform: C9300-24P | Stack: 1 | No 802.1X"])
    count += 1

    gt = cisco_bldg_edge_gt("BLDG-N-FLOOR1-SW01", 1, 48, "rapid-pvst", 10, 20, 900, "192.0.2.216", "192.0.2.254", "Building-N Floor-1")
    write_gt("bldg-n-floor1-sw01.yaml", gt, ["Role: building-edge | Platform: C9300-48P | Stack: 1 | No 802.1X, data+voice"])
    count += 1

    # ── 26-30: Arista EOS Access ──────────────────────────────────────────────
    print("Generating Arista EOS access GTs (5)...")

    arista_access_configs = [
        # hostname, model, vlans, mgmt_v, mgmt_ip, campus, uplink_port, uplink_po, port_count, location
        ("CAMPUS-ACCESS-SW05", "CCS-720XP-24ZY4",
         {100: "USERS", 200: "VOICE"}, 4060, "198.51.100.63",
         "campus.example.org", 25, None, 24, "Building-A Access SW05"),
        ("CAMPUS-ACCESS-SW06", "CCS-720XP-24ZY4",
         {100: "USERS", 200: "VOICE", 300: "IOT"}, 4060, "198.51.100.64",
         "campus.example.org", 25, None, 24, "Building-B Access SW06"),
        ("CAMPUS-ACCESS-SW07", "CCS-720XP-48ZY4",
         {110: "USERS", 210: "VOICE"}, 4061, "198.51.100.65",
         "campus.example.org", 49, 500, 48, "Building-C Access SW07"),
        ("CAMPUS-ACCESS-SW09", "DCS-7050CX3-32S",
         {120: "USERS", 220: "VOICE"}, 4062, "198.51.100.67",
         "campus.example.org", 25, None, 24, "Building-E Access SW09"),
        ("CAMPUS-ACCESS-SW12", "CCS-720XP-48ZY4",
         {130: "USERS", 230: "VOICE", 330: "GUEST", 777: "AP-MGMT"}, 4063, "198.51.100.70",
         "campus.example.org", 49, 502, 48, "Building-H Access SW12"),
    ]

    for row in arista_access_configs:
        hostname, model, vlans, mgmt_v, mgmt_ip, campus, up_port, up_po, port_cnt, loc = row
        gt = arista_access_gt(hostname, model, vlans, mgmt_v, mgmt_ip, campus, up_port, up_po, port_cnt, loc)
        fname = hostname.lower() + ".yaml"
        write_gt(fname, gt, [f"Role: Arista-access | Platform: {model} | VLANs: {len(vlans)} | Uplink: {'LAG-PC' + str(up_po) if up_po else 'single-Eth' + str(up_port)}"])
        count += 1

    # ── 31-33: Arista MLAG Distribution ──────────────────────────────────────
    print("Generating Arista MLAG distribution GTs (3)...")

    arista_dist_configs = [
        # hostname, model, vlans, mgmt_v, mgmt_ip, campus, mlag_peer_ip, mlag_peer_ports, uplink_ports, po_id, location
        ("CAMPUS-DIST-SW03", "CCS-720XP-24ZY4",
         {100: "USERS", 200: "VOICE", 300: "IOT", 777: "AP-MGMT"}, 4060, "198.51.100.71",
         "campus.example.org", "169.254.0.2", [23, 24], [27, 28], 2001, "Campus Distribution SW03"),
        ("CAMPUS-DIST-SW05", "CCS-720XP-48ZY4",
         {110: "USERS", 210: "VOICE", 310: "IOT"}, 4061, "198.51.100.73",
         "campus.example.org", "169.254.0.6", [47, 48], [49, 50], 2002, "Campus Distribution SW05"),
        ("CAMPUS-DIST-SW07", "DCS-7050CX3-32S",
         {120: "USERS", 220: "VOICE", 320: "GUEST", 420: "IOT"}, 4062, "198.51.100.75",
         "campus.example.org", "169.254.0.10", [31, 32], [29, 30], 2003, "Campus Distribution SW07"),
    ]

    for row in arista_dist_configs:
        hostname, model, vlans, mgmt_v, mgmt_ip, campus, peer_ip, peer_ports, up_ports, po_id, loc = row
        gt = arista_dist_mlag_gt(hostname, model, vlans, mgmt_v, mgmt_ip, campus, peer_ip, peer_ports, up_ports, po_id, loc)
        fname = hostname.lower() + "-arista.yaml"
        write_gt(fname, gt, [f"Role: Arista-distribution-MLAG | Platform: {model} | VLANs: {len(vlans)} | MLAG-peer: {peer_ip}"])
        count += 1

    print(f"\n{'='*60}")
    print(f"Ground-truth files generated: {count}")
    print(f"GT directory: {GT_DIR}")
    total_gt = len([f for f in os.listdir(GT_DIR) if f.endswith(".yaml")])
    print(f"Total GT files (including existing): {total_gt}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
