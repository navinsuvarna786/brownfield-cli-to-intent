#!/usr/bin/env python3
"""
generate_100_configs.py
-----------------------
Generate 66 new synthetic sanitized configs (43 IOS-XE 9300/9500 + 20 Arista EOS + 3 NX-OS)
to expand the corpus from 34 to 100 configs for the expand-100-configs branch.

All addressing uses RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and
RFC 2606 hostnames.  SNMP credentials replaced with 'xxxxxxxx'.

Layout:
  input/sanitized/cisco/    43 IOS-XE 9300/9500 configs
  input/sanitized/arista/   20 Arista EOS configs
  input/sanitized/nxos/      3 NX-OS configs (unsupported-vendor LLM path coverage)
"""

import os
import textwrap
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent / "input" / "sanitized"
OUT_CISCO  = str(_BASE / "cisco")
OUT_ARISTA = str(_BASE / "arista")
OUT_NXOS   = str(_BASE / "nxos")

os.makedirs(OUT_CISCO,  exist_ok=True)
os.makedirs(OUT_ARISTA, exist_ok=True)
os.makedirs(OUT_NXOS,   exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """\
banner motd ^C
*************************************************************
* Authorized access only.                                   *
* Unauthorized use is prohibited and may be prosecuted.     *
*************************************************************
^C"""

CISCO_TAIL = """\
!
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
!
!

control-plane
 service-policy input system-cpp-policy
!"""

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
!
!"""

CISCO_AAA_FULL = """\
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
dot1x system-auth-control
!"""

CISCO_AAA_BASIC = """\
aaa new-model
!
aaa authentication login default local enable
aaa session-id common
!"""

CISCO_RADIUS = """\
radius server radius-svr-01
 address ipv4 192.0.2.31 auth-port 1812 acct-port 1813
 key 7 xxxxxxxx
!
radius server radius-svr-02
 address ipv4 192.0.2.32 auth-port 1812 acct-port 1813
 key 7 xxxxxxxx
!
tacacs server tacacs-svr-01
 address ipv4 192.0.2.11
 key 7 xxxxxxxx
!
tacacs server tacacs-svr-02
 address ipv4 192.0.2.12
 key 7 xxxxxxxx
!"""

CISCO_SNMP = """\
snmp-server community xxxxxxxx RO 13
snmp-server community xxxxxxxx RW 13
snmp-server location {location}
snmp-server contact NOC-555-0100
snmp-server host 192.0.2.21 version 2c xxxxxxxx
snmp-server host 192.0.2.22 version 2c xxxxxxxx
!
ip access-list standard 13
 permit 192.0.2.0 0.0.0.255
 deny   any log
!
logging host 192.0.2.21
logging host 192.0.2.22
logging host 192.0.2.23
!"""

DOT1X_ACCESS_PORT = """\
 switchport access vlan {data_vlan}
 switchport mode access
{voice_line}\
 authentication host-mode multi-auth
 authentication order dot1x mab
 authentication priority dot1x mab
 authentication port-control auto
 authentication periodic
 authentication timer reauthenticate server
 mab
 dot1x pae authenticator
 no logging event link-status
 storm-control broadcast level 2.00 1.00
 storm-control multicast level 2.00 1.00
 spanning-tree portfast
 spanning-tree bpduguard enable"""

PLAIN_ACCESS_PORT = """\
 switchport access vlan {data_vlan}
 switchport mode access
 no logging event link-status
 storm-control broadcast level 2.00 1.00
 storm-control multicast level 2.00 1.00
 spanning-tree portfast
 spanning-tree bpduguard enable"""


def write_file(path, name, content):
    fpath = os.path.join(path, name)
    with open(fpath, "w") as f:
        f.write(content)
    print(f"  wrote {fpath}")


# ─────────────────────────────────────────────────────────────────────────────
# IOS-XE 9300/9500 generators
# ─────────────────────────────────────────────────────────────────────────────

def c9300_provision_block(model, stack_size):
    """Return switch provision lines for C9300 stack."""
    lines = []
    for i in range(1, stack_size + 1):
        lines.append(f"switch {i} provision {model}")
    return "\n".join(lines)


def c9300_gi_port(stack, port, cfg):
    """Return a GigabitEthernet interface stanza."""
    return f"interface GigabitEthernet{stack}/0/{port}\n{cfg}\n!"


def c9300_access_nac_config(
    hostname, model, stack_size, license_level, stp_mode,
    uplink_type, data_vlan, voice_vlan, guest_vlan, mgmt_vlan,
    mgmt_ip, mgmt_gw, has_iot=False, iot_vlan=None, location="Campus Access Switch"
):
    """Generate a 9300 access-edge switch with 802.1X/NAC."""
    vlans = {data_vlan: "DATA", voice_vlan: "VOICE", guest_vlan: "GUEST", mgmt_vlan: "MGMT"}
    if has_iot and iot_vlan:
        vlans[iot_vlan] = "IOT"

    provision = c9300_provision_block(model, stack_size)

    # Uplink block
    if uplink_type == "port-channel":
        uplink_ports_count = 2
        uplink_block = f"""\
interface Port-channel1
 description UPLINK-PC1
 switchport trunk native vlan {mgmt_vlan}
 switchport trunk allowed vlan {data_vlan},{voice_vlan},{guest_vlan},{mgmt_vlan}{"," + str(iot_vlan) if has_iot and iot_vlan else ""}
 switchport mode trunk
!"""
        for s in range(1, stack_size + 1):
            uplink_block += f"""
interface TenGigabitEthernet{s}/1/1
 description UPLINK-MEMBER-PC1
 channel-group 1 mode active
!"""
    else:
        # plain trunk - single TenGig per stack member
        uplink_block = ""
        for s in range(1, stack_size + 1):
            uplink_block += f"""\
interface TenGigabitEthernet{s}/1/1
 description UPLINK-TRUNK
 switchport trunk native vlan {mgmt_vlan}
 switchport trunk allowed vlan {data_vlan},{voice_vlan},{guest_vlan},{mgmt_vlan}{"," + str(iot_vlan) if has_iot and iot_vlan else ""}
 switchport mode trunk
 spanning-tree guard root
!
"""

    # Build access port block (48 ports per member, alternating voice on every 4th)
    access_ports = ""
    for s in range(1, stack_size + 1):
        for p in range(1, 49):
            has_voice = (p % 4 == 0)
            voice_line = f" switchport voice vlan {voice_vlan}\n" if has_voice else ""
            port_cfg = DOT1X_ACCESS_PORT.format(data_vlan=data_vlan, voice_line=voice_line)
            access_ports += f"interface GigabitEthernet{s}/0/{p}\n{port_cfg}\n!\n!\n"

    # VLAN block
    vlan_block = ""
    for vid, vname in sorted(vlans.items()):
        vlan_block += f"vlan {vid}\n name {vname}\n!\n"

    # snmp location
    snmp = CISCO_SNMP.format(location=location)

    cfg = f"""\
{CISCO_HEADER.format(hostname=hostname)}

{CISCO_AAA_FULL}
clock timezone CST -6 0
clock summer-time CDT recurring
!
{provision}
!
ip domain name campus.example.edu
ip name-server 192.0.2.50 192.0.2.60
!

vtp domain CAMPUS
vtp mode transparent
!
!

errdisable recovery cause security-violation
errdisable recovery cause gbic-invalid
errdisable recovery cause psecure-violation
errdisable recovery interval 100
license boot level {license_level}
diagnostic bootup level minimal
spanning-tree mode {stp_mode}
spanning-tree extend system-id
!

redundancy
 mode sso
!
username xxxxxxxx privilege 15 password 7 xxxxxxxx
!
lldp run
!
!
{vlan_block}
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 no ip address
 negotiation auto
!
interface Vlan{mgmt_vlan}
 ip address {mgmt_ip} 255.255.255.0
 no ip redirects
!
ip default-gateway {mgmt_gw}
!
{uplink_block}
{access_ports}
{CISCO_RADIUS}
{snmp}
{BANNER}
{CISCO_TAIL}
"""
    return cfg


def c9300_oob_config(
    hostname, model, stack_size, license_level,
    server_vlans, oob_vlan, mgmt_vlan, mgmt_ip, mgmt_gw,
    location="Data Center OOB Switch"
):
    """Generate a 9300 OOB server-room switch (no 802.1X, large VLAN table)."""
    provision = c9300_provision_block(model, stack_size)

    vlan_block = f"vlan {oob_vlan}\n name OOB-MGMT\n!\n"
    vlan_block += f"vlan {mgmt_vlan}\n name Native\n!\n"
    for vid, vname in server_vlans.items():
        vlan_block += f"vlan {vid}\n name {vname}\n!\n"

    trunk_allowed = ",".join(str(v) for v in sorted(list(server_vlans.keys()) + [oob_vlan, mgmt_vlan]))

    # Uplink port-channel
    uplink_block = f"""\
interface Port-channel1
 description UPLINK-OOB-PC1
 switchport trunk native vlan {mgmt_vlan}
 switchport trunk allowed vlan {trunk_allowed}
 switchport mode trunk
!"""
    for s in range(1, stack_size + 1):
        uplink_block += f"""
interface TenGigabitEthernet{s}/1/1
 description UPLINK-MEMBER-PC1
 channel-group 1 mode active
!"""

    # Access ports - plain (no 802.1X)
    access_ports = ""
    for s in range(1, stack_size + 1):
        for p in range(1, 49):
            first_vlan = list(server_vlans.keys())[p % len(server_vlans)]
            port_cfg = PLAIN_ACCESS_PORT.format(data_vlan=first_vlan)
            access_ports += f"interface GigabitEthernet{s}/0/{p}\n{port_cfg}\n!\n!\n"

    snmp = CISCO_SNMP.format(location=location)

    cfg = f"""\
{CISCO_HEADER.format(hostname=hostname)}

{CISCO_AAA_BASIC}
clock timezone CST -6 0
clock summer-time CDT recurring
!
{provision}
!
ip domain name campus.example.edu
ip name-server 192.0.2.50 192.0.2.60
!

vtp domain CAMPUS
vtp mode transparent
!
!

errdisable recovery cause security-violation
errdisable recovery cause gbic-invalid
errdisable recovery cause psecure-violation
errdisable recovery interval 100
license boot level {license_level}
diagnostic bootup level minimal
spanning-tree mode rapid-pvst
spanning-tree extend system-id
!

redundancy
 mode sso
!
username xxxxxxxx privilege 15 password 7 xxxxxxxx
!
lldp run
!
!
{vlan_block}
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 no ip address
 negotiation auto
!
interface Vlan{mgmt_vlan}
 ip address {mgmt_ip} 255.255.255.0
 no ip redirects
!
ip default-gateway {mgmt_gw}
!
{uplink_block}
{access_ports}
{snmp}
{BANNER}
{CISCO_TAIL}
"""
    return cfg


def c9300_distribution_config(
    hostname, model, stack_size, license_level, stp_mode,
    vlans, mgmt_vlan, l3_svis, mgmt_ip, mgmt_gw,
    uplink_po=10, hsrp_priority=110, location="Campus Distribution Switch"
):
    """Generate a 9300 or 9500 distribution switch with L3 SVIs and HSRP."""
    provision = c9300_provision_block(model, stack_size)

    vlan_block = ""
    for vid, vname in sorted(vlans.items()):
        vlan_block += f"vlan {vid}\n name {vname}\n!\n"

    trunk_allowed = ",".join(str(v) for v in sorted(list(vlans.keys()) + [mgmt_vlan]))

    # Uplink port-channel to core
    uplink_block = f"""\
interface Port-channel{uplink_po}
 description UPLINK-CORE-PC{uplink_po}
 switchport trunk native vlan {mgmt_vlan}
 switchport trunk allowed vlan {trunk_allowed}
 switchport mode trunk
!"""
    for s in range(1, stack_size + 1):
        if "9500" in model or "c9500" in model:
            iface = f"FortyGigabitEthernet{s}/0/{s}"
        else:
            iface = f"TenGigabitEthernet{s}/1/1"
        uplink_block += f"""
interface {iface}
 description UPLINK-CORE-MEMBER
 channel-group {uplink_po} mode active
!"""

    # Downstream port-channel to access (one per stack member)
    for s in range(1, stack_size + 1):
        po = uplink_po + s
        trunk_d = ",".join(str(v) for v in sorted(vlans.keys()))
        uplink_block += f"""
interface Port-channel{po}
 description DOWNLINK-ACCESS-PC{po}
 switchport trunk native vlan {mgmt_vlan}
 switchport trunk allowed vlan {trunk_d}
 switchport mode trunk
!"""
        if "9500" in model or "c9500" in model:
            iface = f"TwentyFiveGigE{s}/0/{s+2}"
        else:
            iface = f"TenGigabitEthernet{s}/1/2"
        uplink_block += f"""
interface {iface}
 description DOWNLINK-ACCESS-MEMBER
 channel-group {po} mode active
!"""

    # L3 SVIs with HSRP
    svi_block = f"""\
interface Vlan{mgmt_vlan}
 ip address {mgmt_ip} 255.255.255.0
 no ip redirects
!
"""
    for vid, (ip, vip, vname) in l3_svis.items():
        svi_block += f"""\
interface Vlan{vid}
 description {vname}
 ip address {ip} 255.255.255.0
 no ip redirects
 no ip proxy-arp
 standby version 2
 standby 0 ip {vip}
 standby 0 priority {hsrp_priority}
 standby 0 preempt
!
"""

    snmp = CISCO_SNMP.format(location=location)

    cfg = f"""\
{CISCO_HEADER.format(hostname=hostname)}

{CISCO_AAA_FULL}
clock timezone CST -6 0
clock summer-time CDT recurring
!
{provision}
!
ip routing
!
ip domain name campus.example.edu
ip name-server 192.0.2.50 192.0.2.60
!

vtp domain CAMPUS
vtp mode transparent
!
!

errdisable recovery cause security-violation
errdisable recovery cause gbic-invalid
errdisable recovery cause psecure-violation
errdisable recovery interval 100
license boot level {license_level}
diagnostic bootup level minimal
spanning-tree mode {stp_mode}
spanning-tree extend system-id
!

redundancy
 mode sso
!
username xxxxxxxx privilege 15 password 7 xxxxxxxx
!
lldp run
!
!
{vlan_block}
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 no ip address
 negotiation auto
!
{svi_block}
ip default-gateway {mgmt_gw}
!
{uplink_block}
{snmp}
{BANNER}
{CISCO_TAIL}
"""
    return cfg


def c9300_remote_edge_config(
    hostname, model, stack_size, license_level,
    data_vlan, mgmt_vlan, mgmt_ip, mgmt_gw,
    location="Remote Edge Switch"
):
    """Generate a 9300 simple remote-edge switch (no 802.1X, minimal VLANs)."""
    provision = c9300_provision_block(model, stack_size)
    snmp = CISCO_SNMP.format(location=location)

    access_ports = ""
    for p in range(1, 25):
        port_cfg = PLAIN_ACCESS_PORT.format(data_vlan=data_vlan)
        access_ports += f"interface GigabitEthernet1/0/{p}\n{port_cfg}\n!\n!\n"

    cfg = f"""\
{CISCO_HEADER.format(hostname=hostname)}

{CISCO_AAA_BASIC}
clock timezone CST -6 0
clock summer-time CDT recurring
!
{provision}
!
ip domain name campus.example.edu
ip name-server 192.0.2.50 192.0.2.60
!

vtp domain CAMPUS
vtp mode transparent
!
!

errdisable recovery cause security-violation
errdisable recovery cause gbic-invalid
errdisable recovery cause psecure-violation
errdisable recovery interval 100
license boot level {license_level}
diagnostic bootup level minimal
spanning-tree mode rapid-pvst
spanning-tree extend system-id
!

redundancy
 mode sso
!
username xxxxxxxx privilege 15 password 7 xxxxxxxx
!
lldp run
!
!
vlan {data_vlan}
 name DATA
!
vlan {mgmt_vlan}
 name MGMT
!
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 no ip address
 negotiation auto
!
interface Vlan{mgmt_vlan}
 ip address {mgmt_ip} 255.255.255.0
 no ip redirects
!
ip default-gateway {mgmt_gw}
!
interface GigabitEthernet1/1/1
 description UPLINK-TRUNK
 switchport trunk native vlan {mgmt_vlan}
 switchport trunk allowed vlan {data_vlan},{mgmt_vlan}
 switchport mode trunk
 spanning-tree guard root
!
{access_ports}
{snmp}
{BANNER}
{CISCO_TAIL}
"""
    return cfg


def c9300_building_edge_config(
    hostname, model, stack_size, license_level, stp_mode,
    data_vlan, voice_vlan, mgmt_vlan, mgmt_ip, mgmt_gw,
    location="Building Edge Switch"
):
    """Generate a 9300 building-edge switch (simple, no 802.1X, data+voice)."""
    provision = c9300_provision_block(model, stack_size)
    snmp = CISCO_SNMP.format(location=location)

    access_ports = ""
    for s in range(1, stack_size + 1):
        for p in range(1, 49):
            has_voice = (p % 6 == 0)
            voice_line = f" switchport voice vlan {voice_vlan}\n" if has_voice else ""
            port_cfg = f""" switchport access vlan {data_vlan}
 switchport mode access
{voice_line} no logging event link-status
 storm-control broadcast level 2.00 1.00
 storm-control multicast level 2.00 1.00
 spanning-tree portfast
 spanning-tree bpduguard enable"""
            access_ports += f"interface GigabitEthernet{s}/0/{p}\n{port_cfg}\n!\n!\n"

    cfg = f"""\
{CISCO_HEADER.format(hostname=hostname)}

{CISCO_AAA_BASIC}
clock timezone CST -6 0
clock summer-time CDT recurring
!
{provision}
!
ip domain name campus.example.edu
ip name-server 192.0.2.50 192.0.2.60
!

vtp domain CAMPUS
vtp mode transparent
!
!

errdisable recovery cause security-violation
errdisable recovery cause gbic-invalid
errdisable recovery cause psecure-violation
errdisable recovery interval 100
license boot level {license_level}
diagnostic bootup level minimal
spanning-tree mode {stp_mode}
spanning-tree extend system-id
!

redundancy
 mode sso
!
username xxxxxxxx privilege 15 password 7 xxxxxxxx
!
lldp run
!
!
vlan {data_vlan}
 name DATA
!
vlan {voice_vlan}
 name VOICE
!
vlan {mgmt_vlan}
 name MGMT
!
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 no ip address
 negotiation auto
!
interface Vlan{mgmt_vlan}
 ip address {mgmt_ip} 255.255.255.0
 no ip redirects
!
ip default-gateway {mgmt_gw}
!
interface Port-channel1
 description UPLINK-PC1
 switchport trunk native vlan {mgmt_vlan}
 switchport trunk allowed vlan {data_vlan},{voice_vlan},{mgmt_vlan}
 switchport mode trunk
!
interface TenGigabitEthernet1/1/1
 description UPLINK-MEMBER-PC1
 channel-group 1 mode active
!
{access_ports}
{snmp}
{BANNER}
{CISCO_TAIL}
"""
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# Arista EOS generators
# ─────────────────────────────────────────────────────────────────────────────

ARISTA_BANNER = """\
banner login
Authorized access only. Unauthorized use is prohibited.
EOF
!"""

ARISTA_MGMT = """\
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

ARISTA_TAIL = """\
ntp server 192.0.2.11 prefer
ntp server 192.0.2.12
!
aaa group server tacacs+ TACACS_GROUP
   server 192.0.2.11
   server 192.0.2.12
!
tacacs-server host 192.0.2.11 key 7 xxxxxxxx
tacacs-server host 192.0.2.12 key 7 xxxxxxxx
!
username admin privilege 15 role network-admin secret sha512 xxxxxxxx
!"""


def arista_access_config(
    hostname, model, eos_version, vlans, mgmt_vlan, mgmt_ip,
    uplink_port, uplink_po=None, port_count=24,
    location="Campus Access Switch", campus="campus.example.org"
):
    """Generate an Arista EOS access switch config."""
    vlan_block = ""
    for vid, vname in sorted(vlans.items()):
        vlan_block += f"vlan {vid}\n   name {vname}\n!\n"
    vlan_block += f"vlan {mgmt_vlan}\n   name INBAND-MGMT\n!\n"

    trunk_vlans = ",".join(str(v) for v in sorted(list(vlans.keys()) + [mgmt_vlan]))

    # Uplink block
    if uplink_po:
        uplink_block = f"""\
interface Port-Channel{uplink_po}
   description UPLINK-PC{uplink_po}
   switchport mode trunk
   switchport trunk allowed vlan {trunk_vlans}
!
interface Ethernet{uplink_port}
   description UPLINK-MEMBER
   channel-group {uplink_po} mode active
!
interface Ethernet{uplink_port + 1}
   description UPLINK-MEMBER
   channel-group {uplink_po} mode active
!"""
    else:
        uplink_block = f"""\
interface Ethernet{uplink_port}
   description UPLINK
   switchport mode trunk
   switchport trunk allowed vlan {trunk_vlans}
!"""

    # Determine data and voice VLANs for access ports
    vlan_ids = sorted(vlans.keys())
    data_vlan = vlan_ids[0]
    voice_vlan = vlan_ids[1] if len(vlan_ids) > 1 else data_vlan

    access_block = ""
    for p in range(1, port_count + 1):
        has_voice = (p % 4 == 0)
        if has_voice:
            access_block += f"""\
interface Ethernet{p}
   description IP-PHONE
   switchport access vlan {data_vlan}
   switchport trunk native vlan {data_vlan}
   switchport trunk allowed vlan {data_vlan},{voice_vlan}
   switchport mode trunk
   switchport
!
"""
        else:
            access_block += f"""\
interface Ethernet{p}
   description USER
   switchport access vlan {data_vlan}
   switchport
!
"""

    svi_block = ""
    for vid, vname in sorted(vlans.items()):
        octet = 100 + list(sorted(vlans.keys())).index(vid)
        svi_block += f"""\
interface Vlan{vid}
   description {vname}
   vrf VRFA
   ip address 198.51.{octet}.{mgmt_ip.split('.')[-1]}/24
!
"""
    svi_block += f"""\
interface Vlan{mgmt_vlan}
   description INBAND-MGMT
   vrf MDMZ
   ip address {mgmt_ip}/24
!"""

    cfg = f"""\
! Command: show running-config
! device: {hostname} ({model}, {eos_version})
!
no aaa root
!
hostname {hostname}
!
switchport default mode routed
!
vlan internal order ascending range 3500 3750
!
{vlan_block}
dns domain {campus}
!
snmp-server ipv4 access-list SNMP-ALLOWED vrf MDMZ
snmp-server contact NOC-555-0100
snmp-server location {location}
snmp-server vrf MDMZ local-interface Vlan{mgmt_vlan}
!
{uplink_block}
{access_block}
{svi_block}
{ARISTA_MGMT}
{ARISTA_TAIL}
{ARISTA_BANNER}
"""
    return cfg


def arista_distribution_config(
    hostname, model, eos_version, vlans, mgmt_vlan, mgmt_ip,
    mlag_peer_ip, mlag_peer_link_ports, uplink_ports, po_id=2000,
    location="Campus Distribution Switch", campus="campus.example.org"
):
    """Generate an Arista EOS distribution switch with MLAG."""
    vlan_block = ""
    for vid, vname in sorted(vlans.items()):
        vlan_block += f"vlan {vid}\n   name {vname}\n!\n"
    vlan_block += f"vlan {mgmt_vlan}\n   name INBAND-MGMT\n!\n"
    vlan_block += "vlan 4094\n   name MLAG-PEER\n!\n"

    trunk_vlans = ",".join(str(v) for v in sorted(list(vlans.keys()) + [mgmt_vlan]))

    # MLAG peer-link
    mlag_block = f"""\
interface Port-Channel999
   description MLAG-PEER-LINK
   switchport mode trunk
   switchport trunk allowed vlan all
!
interface Ethernet{mlag_peer_link_ports[0]}
   description MLAG-PEER-LINK-MEMBER
   channel-group 999 mode active
!
interface Ethernet{mlag_peer_link_ports[1]}
   description MLAG-PEER-LINK-MEMBER
   channel-group 999 mode active
!
mlag configuration
   domain-id CAMPUS-MLAG
   local-interface Vlan4094
   peer-address {mlag_peer_ip}
   peer-link Port-Channel999
!
interface Vlan4094
   description MLAG-PEER
   ip address {mlag_peer_ip.rsplit(".", 1)[0]}.{int(mlag_peer_ip.split(".")[-1]) + 1}/30
!"""

    # Uplink to core
    uplink_block = f"""\
interface Port-Channel{po_id}
   description UPLINK-PC{po_id}
   switchport mode trunk
   switchport trunk allowed vlan {trunk_vlans}
!"""
    for p in uplink_ports:
        uplink_block += f"""
interface Ethernet{p}
   description UPLINK-MEMBER
   channel-group {po_id} mode active
!"""

    # Access ports (downlink to access switches)
    access_block = ""
    for p in range(1, 21):
        first_vlan = sorted(vlans.keys())[0]
        access_block += f"""\
interface Ethernet{p}
   description DOWNLINK-ACCESS
   switchport access vlan {first_vlan}
   switchport
!
"""

    # L3 SVIs + HSRP equivalent (Arista uses virtual-router)
    svi_block = ""
    for idx, (vid, vname) in enumerate(sorted(vlans.items())):
        net_third = 100 + idx
        host_part = mgmt_ip.split(".")[-1]
        svi_block += f"""\
interface Vlan{vid}
   description {vname}
   vrf VRFA
   ip address 198.51.{net_third}.{host_part}/24
   ip virtual-router address 198.51.{net_third}.1
!
"""
    svi_block += f"""\
interface Vlan{mgmt_vlan}
   description INBAND-MGMT
   vrf MDMZ
   ip address {mgmt_ip}/24
!"""

    cfg = f"""\
! Command: show running-config
! device: {hostname} ({model}, {eos_version})
!
no aaa root
!
hostname {hostname}
!
switchport default mode routed
!
vlan internal order ascending range 3500 3750
!
{vlan_block}
dns domain {campus}
!
snmp-server ipv4 access-list SNMP-ALLOWED vrf MDMZ
snmp-server contact NOC-555-0100
snmp-server location {location}
snmp-server vrf MDMZ local-interface Vlan{mgmt_vlan}
!
{mlag_block}
{uplink_block}
{access_block}
{svi_block}
{ARISTA_MGMT}
{ARISTA_TAIL}
{ARISTA_BANNER}
"""
    return cfg


def arista_spine_config(
    hostname, model, eos_version, mgmt_vlan, mgmt_ip,
    bgp_asn, bgp_peers, location="Campus Spine Switch", campus="campus.example.org"
):
    """Generate an Arista spine/core switch with BGP EVPN underlay."""
    bgp_peer_block = ""
    for peer_ip, peer_asn in bgp_peers:
        bgp_peer_block += f"""\
   neighbor {peer_ip} remote-as {peer_asn}
   neighbor {peer_ip} send-community
   neighbor {peer_ip} maximum-routes 12000
"""

    cfg = f"""\
! Command: show running-config
! device: {hostname} ({model}, {eos_version})
!
no aaa root
!
hostname {hostname}
!
switchport default mode routed
!
vlan internal order ascending range 3500 3750
!
vlan {mgmt_vlan}
   name INBAND-MGMT
!
dns domain {campus}
!
snmp-server ipv4 access-list SNMP-ALLOWED vrf MDMZ
snmp-server contact NOC-555-0100
snmp-server location {location}
snmp-server vrf MDMZ local-interface Vlan{mgmt_vlan}
!
ip routing
ip routing vrf MDMZ
!
router bgp {bgp_asn}
   router-id {mgmt_ip}
{bgp_peer_block}   !
   address-family ipv4
      neighbor default activate
   !
!
interface Vlan{mgmt_vlan}
   description INBAND-MGMT
   vrf MDMZ
   ip address {mgmt_ip}/24
!
interface Loopback0
   ip address {mgmt_ip.rsplit(".", 1)[0]}.{int(mgmt_ip.split(".")[-1]) + 100}/32
!
interface Ethernet1
   description DOWNLINK-DIST-01
   no switchport
   ip address 203.0.113.{int(mgmt_ip.split(".")[-1]) * 4}/30
!
interface Ethernet2
   description DOWNLINK-DIST-02
   no switchport
   ip address 203.0.113.{int(mgmt_ip.split(".")[-1]) * 4 + 4}/30
!
interface Ethernet3
   description DOWNLINK-DIST-03
   no switchport
   ip address 203.0.113.{int(mgmt_ip.split(".")[-1]) * 4 + 8}/30
!
interface Ethernet4
   description DOWNLINK-DIST-04
   no switchport
   ip address 203.0.113.{int(mgmt_ip.split(".")[-1]) * 4 + 12}/30
!
{ARISTA_MGMT}
{ARISTA_TAIL}
{ARISTA_BANNER}
"""
    return cfg


def arista_oob_config(
    hostname, model, eos_version, server_vlans, mgmt_vlan, mgmt_ip,
    uplink_port, location="Data Center OOB Switch", campus="campus.example.org"
):
    """Generate an Arista OOB/server-room switch."""
    vlan_block = ""
    for vid, vname in sorted(server_vlans.items()):
        vlan_block += f"vlan {vid}\n   name {vname}\n!\n"
    vlan_block += f"vlan {mgmt_vlan}\n   name INBAND-MGMT\n!\n"

    trunk_vlans = ",".join(str(v) for v in sorted(list(server_vlans.keys()) + [mgmt_vlan]))

    access_block = ""
    vlan_list = sorted(server_vlans.keys())
    for p in range(1, 49):
        vlan_id = vlan_list[p % len(vlan_list)]
        access_block += f"""\
interface Ethernet{p}
   description SERVER-PORT
   switchport access vlan {vlan_id}
   switchport
!
"""

    cfg = f"""\
! Command: show running-config
! device: {hostname} ({model}, {eos_version})
!
no aaa root
!
hostname {hostname}
!
switchport default mode routed
!
vlan internal order ascending range 3500 3750
!
{vlan_block}
dns domain {campus}
!
snmp-server ipv4 access-list SNMP-ALLOWED vrf MDMZ
snmp-server contact NOC-555-0100
snmp-server location {location}
snmp-server vrf MDMZ local-interface Vlan{mgmt_vlan}
!
interface Ethernet{uplink_port}
   description UPLINK-OOB
   switchport mode trunk
   switchport trunk allowed vlan {trunk_vlans}
!
{access_block}
interface Vlan{mgmt_vlan}
   description INBAND-MGMT
   vrf MDMZ
   ip address {mgmt_ip}/24
!
{ARISTA_MGMT}
{ARISTA_TAIL}
{ARISTA_BANNER}
"""
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# NX-OS generator (unsupported-vendor LLM path coverage)
# ─────────────────────────────────────────────────────────────────────────────

def nxos_config(hostname, vlans, mgmt_ip, location="Data Center NX-OS Switch"):
    """Generate a Cisco NX-OS config (unsupported vendor for LLM fallback)."""
    vlan_block = ""
    for vid, vname in sorted(vlans.items()):
        vlan_block += f"vlan {vid}\n  name {vname}\n"
    access_block = ""
    vlan_list = sorted(vlans.keys())
    for p in range(1, 25):
        vid = vlan_list[p % len(vlan_list)]
        access_block += f"""\
interface Ethernet1/{p}
  description SERVER-PORT
  switchport
  switchport access vlan {vid}
  no shutdown
!
"""
    trunk_vlans = ",".join(str(v) for v in sorted(vlans.keys()))
    cfg = f"""\
!Command: show running-config
!Time: Sat May  1 00:00:00 2026
version 10.3(4a)
hostname {hostname}
!
feature lldp
feature telnet
feature ssh
feature nxapi
!
username admin password 7 xxxxxxxx role network-admin
!
vrf context management
  ip route 0.0.0.0/0 192.0.2.254
!
vlan 1,{trunk_vlans}
{vlan_block}
!
interface mgmt0
  vrf member management
  ip address {mgmt_ip}/24
!
interface Ethernet1/25
  description UPLINK-TRUNK
  switchport
  switchport mode trunk
  switchport trunk allowed vlan {trunk_vlans}
  no shutdown
!
interface Ethernet1/26
  description UPLINK-TRUNK
  switchport
  switchport mode trunk
  switchport trunk allowed vlan {trunk_vlans}
  no shutdown
!
{access_block}
ntp server 192.0.2.11
ntp server 192.0.2.12
!
snmp-server community xxxxxxxx group network-operator
snmp-server host 192.0.2.21 traps version 2c xxxxxxxx
!
ip domain-name campus.example.edu
ip name-server 192.0.2.50
!
line vty
  exec-timeout 20
!
"""
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# Main: generate all 66 configs
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("Generating IOS-XE 9300/9500 configs (43)...")

    # ── ACCESS-NAC (22 configs) ───────────────────────────────────────────────
    # Parameters: model, stack_size, license, stp_mode, uplink_type, vlans, mgmt, has_iot
    access_nac_params = [
        # (hostname, model, stack, license, stp, uplink, data_v, voice_v, guest_v, mgmt_v, mgmt_ip, mgmt_gw, has_iot, iot_v)
        ("BLDG-D-FLOOR1-SW01", "c9300-48p", 3, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 10, 20, 30, 900, "192.0.2.111", "192.0.2.254", False, None, "Building-D Floor-1"),
        ("BLDG-D-FLOOR2-SW01", "c9300-48p", 3, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 10, 20, 30, 900, "192.0.2.112", "192.0.2.254", False, None, "Building-D Floor-2"),
        ("BLDG-D-FLOOR3-SW01", "c9300-48p", 2, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 10, 20, 30, 900, "192.0.2.113", "192.0.2.254", False, None, "Building-D Floor-3"),
        ("BLDG-E-FLOOR1-SW01", "c9300-48u", 2, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 11, 21, 31, 900, "192.0.2.114", "192.0.2.254", True, 41, "Building-E Floor-1"),
        ("BLDG-E-FLOOR2-SW01", "c9300-48u", 2, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 11, 21, 31, 900, "192.0.2.115", "192.0.2.254", True, 41, "Building-E Floor-2"),
        ("BLDG-E-FLOOR3-SW01", "c9300-48u", 1, "network-advantage addon dna-advantage", "pvst",       "port-channel", 11, 21, 31, 900, "192.0.2.116", "192.0.2.254", False, None, "Building-E Floor-3"),
        ("BLDG-F-FLOOR1-SW01", "c9300-48p", 3, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 12, 22, 32, 901, "192.0.2.117", "192.0.2.254", True, 42, "Building-F Floor-1"),
        ("BLDG-F-FLOOR2-SW01", "c9300-48p", 3, "network-advantage addon dna-advantage", "rapid-pvst", "trunk",        12, 22, 32, 901, "192.0.2.118", "192.0.2.254", False, None, "Building-F Floor-2"),
        ("BLDG-F-FLOOR3-SW01", "c9300-48p", 2, "network-advantage addon dna-advantage", "rapid-pvst", "trunk",        12, 22, 32, 901, "192.0.2.119", "192.0.2.254", False, None, "Building-F Floor-3"),
        ("BLDG-G-FLOOR1-SW01", "c9300-48u", 3, "network-advantage addon dna-advantage", "pvst",       "port-channel", 13, 23, 33, 901, "192.0.2.120", "192.0.2.254", True, 43, "Building-G Floor-1"),
        ("BLDG-G-FLOOR2-SW01", "c9300-48u", 2, "network-advantage addon dna-advantage", "pvst",       "port-channel", 13, 23, 33, 901, "192.0.2.121", "192.0.2.254", True, 43, "Building-G Floor-2"),
        ("BLDG-G-FLOOR3-SW01", "c9300-48u", 1, "network-advantage addon dna-advantage", "pvst",       "trunk",        13, 23, 33, 901, "192.0.2.122", "192.0.2.254", False, None, "Building-G Floor-3"),
        ("BLDG-H-FLOOR1-SW01", "c9300-48p", 3, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 14, 24, 34, 902, "192.0.2.123", "192.0.2.254", False, None, "Building-H Floor-1"),
        ("BLDG-H-FLOOR2-SW01", "c9300-48p", 2, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 14, 24, 34, 902, "192.0.2.124", "192.0.2.254", False, None, "Building-H Floor-2"),
        ("BLDG-H-FLOOR3-SW01", "c9300-48p", 1, "network-advantage addon dna-advantage", "rapid-pvst", "trunk",        14, 24, 34, 902, "192.0.2.125", "192.0.2.254", False, None, "Building-H Floor-3"),
        ("BLDG-J-FLOOR1-SW01", "c9300-24p", 2, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 15, 25, 35, 902, "192.0.2.126", "192.0.2.254", True, 45, "Building-J Floor-1"),
        ("BLDG-J-FLOOR2-SW01", "c9300-24p", 2, "network-advantage addon dna-advantage", "pvst",       "port-channel", 15, 25, 35, 902, "192.0.2.127", "192.0.2.254", True, 45, "Building-J Floor-2"),
        ("BLDG-K-FLOOR1-SW01", "c9300-48p", 3, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 10, 20, 30, 900, "192.0.2.128", "192.0.2.254", False, None, "Building-K Floor-1"),
        ("BLDG-K-FLOOR2-SW01", "c9300-48p", 3, "network-advantage addon dna-advantage", "rapid-pvst", "trunk",        10, 20, 30, 900, "192.0.2.129", "192.0.2.254", False, None, "Building-K Floor-2"),
        ("BLDG-L-FLOOR1-SW01", "c9300-48u", 3, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 16, 26, 36, 903, "192.0.2.130", "192.0.2.254", True, 46, "Building-L Floor-1"),
        ("BLDG-L-FLOOR2-SW01", "c9300-48u", 2, "network-advantage addon dna-advantage", "rapid-pvst", "port-channel", 16, 26, 36, 903, "192.0.2.131", "192.0.2.254", True, 46, "Building-L Floor-2"),
        ("BLDG-M-FLOOR1-SW01", "c9300-48p", 1, "network-advantage addon dna-advantage", "pvst",       "trunk",        17, 27, 37, 903, "192.0.2.132", "192.0.2.254", False, None, "Building-M Floor-1"),
    ]

    for row in access_nac_params:
        hostname, model, stack, lic, stp, uplink, dv, vv, gv, mv, mip, mgw, has_iot, iotv, loc = row
        cfg = c9300_access_nac_config(
            hostname=hostname, model=model, stack_size=stack,
            license_level=lic, stp_mode=stp, uplink_type=uplink,
            data_vlan=dv, voice_vlan=vv, guest_vlan=gv, mgmt_vlan=mv,
            mgmt_ip=mip, mgmt_gw=mgw, has_iot=has_iot, iot_vlan=iotv,
            location=loc
        )
        write_file(OUT_CISCO, f"{hostname}.txt", cfg)

    # ── OOB SERVER-ROOM (10 configs) ──────────────────────────────────────────
    datactr_oob_params = [
        # (hostname, model, stack, license, server_vlans_dict, oob_vlan, mgmt_vlan, mgmt_ip, mgmt_gw, location)
        ("DATACTR-OOBSW-F01", "c9300-48p", 1, "network-advantage",
         {510: "SERVER-VLAN-510", 511: "SERVER-VLAN-511", 512: "SERVER-VLAN-512", 513: "SERVER-VLAN-513", 514: "SERVER-VLAN-514", 515: "SERVER-VLAN-515", 516: "SERVER-VLAN-516"},
         236, 3069, "192.0.2.141", "192.0.2.254", "DC OOB Switch F01"),
        ("DATACTR-OOBSW-F02", "c9300-48p", 1, "network-advantage",
         {517: "SERVER-VLAN-517", 518: "SERVER-VLAN-518", 519: "SERVER-VLAN-519", 520: "SERVER-VLAN-520", 521: "SERVER-VLAN-521", 522: "SERVER-VLAN-522"},
         236, 3069, "192.0.2.142", "192.0.2.254", "DC OOB Switch F02"),
        ("DATACTR-OOBSW-G01", "c9300-48u", 1, "network-advantage",
         {620: "SERVER-VLAN-620", 621: "SERVER-VLAN-621", 622: "SERVER-VLAN-622", 623: "SERVER-VLAN-623", 624: "SERVER-VLAN-624", 625: "SERVER-VLAN-625", 626: "SERVER-VLAN-626", 627: "SERVER-VLAN-627"},
         230, 3070, "192.0.2.143", "192.0.2.254", "DC OOB Switch G01"),
        ("DATACTR-OOBSW-G02", "c9300-48u", 1, "network-advantage",
         {628: "SERVER-VLAN-628", 629: "SERVER-VLAN-629", 630: "SERVER-VLAN-630", 631: "SERVER-VLAN-631", 632: "SERVER-VLAN-632"},
         230, 3070, "192.0.2.144", "192.0.2.254", "DC OOB Switch G02"),
        ("DATACTR-OOBSW-H01", "c9300-48p", 1, "network-advantage",
         {700: "SERVER-VLAN-700", 701: "SERVER-VLAN-701", 702: "SERVER-VLAN-702", 703: "SERVER-VLAN-703", 704: "SERVER-VLAN-704", 705: "SERVER-VLAN-705"},
         236, 3069, "192.0.2.145", "192.0.2.254", "DC OOB Switch H01"),
        ("DATACTR-OOBSW-H02", "c9300-48p", 1, "network-advantage",
         {706: "SERVER-VLAN-706", 707: "SERVER-VLAN-707", 708: "SERVER-VLAN-708", 709: "SERVER-VLAN-709", 710: "SERVER-VLAN-710", 711: "SERVER-VLAN-711"},
         236, 3069, "192.0.2.146", "192.0.2.254", "DC OOB Switch H02"),
        ("DATACTR-OOBSW-J01", "c9300-48u", 1, "network-advantage",
         {800: "SERVER-VLAN-800", 801: "SERVER-VLAN-801", 802: "SERVER-VLAN-802", 803: "SERVER-VLAN-803", 804: "SERVER-VLAN-804"},
         230, 3071, "192.0.2.147", "192.0.2.254", "DC OOB Switch J01"),
        ("DATACTR-OOBSW-J02", "c9300-48u", 1, "network-advantage",
         {805: "SERVER-VLAN-805", 806: "SERVER-VLAN-806", 807: "SERVER-VLAN-807", 808: "SERVER-VLAN-808", 809: "SERVER-VLAN-809"},
         230, 3071, "192.0.2.148", "192.0.2.254", "DC OOB Switch J02"),
        ("DATACTR-OOBSW-K01", "c9300-48p", 2, "network-advantage",
         {900: "SERVER-VLAN-900", 901: "SERVER-VLAN-901", 902: "SERVER-VLAN-902", 903: "SERVER-VLAN-903", 904: "SERVER-VLAN-904", 905: "SERVER-VLAN-905", 906: "SERVER-VLAN-906"},
         236, 3072, "192.0.2.149", "192.0.2.254", "DC OOB Switch K01"),
        ("DATACTR-OOBSW-K02", "c9300-48p", 2, "network-advantage",
         {910: "SERVER-VLAN-910", 911: "SERVER-VLAN-911", 912: "SERVER-VLAN-912", 913: "SERVER-VLAN-913", 914: "SERVER-VLAN-914"},
         236, 3072, "192.0.2.150", "192.0.2.254", "DC OOB Switch K02"),
    ]

    for row in datactr_oob_params:
        hostname, model, stack, lic, svlans, ov, mv, mip, mgw, loc = row
        cfg = c9300_oob_config(
            hostname=hostname, model=model, stack_size=stack,
            license_level=lic, server_vlans=svlans, oob_vlan=ov,
            mgmt_vlan=mv, mgmt_ip=mip, mgmt_gw=mgw, location=loc
        )
        write_file(OUT_CISCO, f"{hostname}.txt", cfg)

    # ── DISTRIBUTION (6 configs) ──────────────────────────────────────────────
    dist_params = [
        # hostname, model, stack, license, stp_mode, vlans, mgmt_v, l3_svis, mgmt_ip, mgmt_gw, uplink_po, hsrp_prio, location
        ("DIST-SW-BLDGC-01", "c9300-24p", 2, "network-advantage addon dna-advantage", "rapid-pvst",
         {10: "DATA", 20: "VOICE", 30: "GUEST", 40: "IOT", 900: "MGMT"},
         900,
         {10: ("192.0.2.201", "192.0.2.1", "DATA"), 20: ("192.0.2.202", "192.0.2.65", "VOICE"),
          30: ("192.0.2.203", "192.0.2.129", "GUEST"), 40: ("192.0.2.204", "192.0.2.193", "IOT")},
         "192.0.2.201", "192.0.2.254", 10, 110, "Campus Distribution Building-C"),

        ("DIST-SW-BLDGD-01", "c9300-24p", 2, "network-advantage addon dna-advantage", "rapid-pvst",
         {11: "DATA", 21: "VOICE", 31: "GUEST", 41: "IOT", 901: "MGMT"},
         901,
         {11: ("192.0.2.211", "192.0.2.2", "DATA"), 21: ("192.0.2.212", "192.0.2.66", "VOICE"),
          31: ("192.0.2.213", "192.0.2.130", "GUEST"), 41: ("192.0.2.214", "192.0.2.194", "IOT")},
         "192.0.2.211", "192.0.2.254", 20, 100, "Campus Distribution Building-D"),

        ("DIST-SW-BLDGE-01", "c9500-48y4c", 1, "network-advantage addon dna-advantage", "rapid-pvst",
         {12: "DATA", 22: "VOICE", 32: "GUEST", 900: "MGMT"},
         900,
         {12: ("192.0.2.221", "192.0.2.3", "DATA"), 22: ("192.0.2.222", "192.0.2.67", "VOICE"),
          32: ("192.0.2.223", "192.0.2.131", "GUEST")},
         "192.0.2.221", "192.0.2.254", 30, 110, "Campus Distribution Building-E"),

        ("DIST-SW-BLDGF-01", "c9500-48y4c", 1, "network-advantage addon dna-advantage", "rapid-pvst",
         {13: "DATA", 23: "VOICE", 33: "GUEST", 43: "IOT", 901: "MGMT"},
         901,
         {13: ("192.0.2.231", "192.0.2.4", "DATA"), 23: ("192.0.2.232", "192.0.2.68", "VOICE"),
          33: ("192.0.2.233", "192.0.2.132", "GUEST"), 43: ("192.0.2.234", "192.0.2.196", "IOT")},
         "192.0.2.231", "192.0.2.254", 40, 100, "Campus Distribution Building-F"),

        ("CAMPUS-DIST-SW03", "c9500-48y4c", 1, "network-advantage addon dna-advantage", "rapid-pvst",
         {10: "DATA", 20: "VOICE", 30: "GUEST", 40: "IOT", 50: "LABS", 900: "MGMT"},
         900,
         {10: ("198.51.100.201", "198.51.100.1", "DATA"), 20: ("198.51.101.201", "198.51.101.1", "VOICE"),
          30: ("198.51.102.201", "198.51.102.1", "GUEST"), 40: ("198.51.103.201", "198.51.103.1", "IOT"),
          50: ("198.51.104.201", "198.51.104.1", "LABS")},
         "198.51.100.201", "198.51.100.254", 50, 110, "Campus Distribution SW03"),

        ("CAMPUS-DIST-SW04", "c9500-48y4c", 1, "network-advantage addon dna-advantage", "rapid-pvst",
         {10: "DATA", 20: "VOICE", 30: "GUEST", 40: "IOT", 50: "LABS", 900: "MGMT"},
         900,
         {10: ("198.51.100.202", "198.51.100.1", "DATA"), 20: ("198.51.101.202", "198.51.101.1", "VOICE"),
          30: ("198.51.102.202", "198.51.102.1", "GUEST"), 40: ("198.51.103.202", "198.51.103.1", "IOT"),
          50: ("198.51.104.202", "198.51.104.1", "LABS")},
         "198.51.100.202", "198.51.100.254", 60, 100, "Campus Distribution SW04"),
    ]

    for row in dist_params:
        hostname, model, stack, lic, stp, vlans, mv, l3svis, mip, mgw, po, prio, loc = row
        cfg = c9300_distribution_config(
            hostname=hostname, model=model, stack_size=stack, license_level=lic,
            stp_mode=stp, vlans=vlans, mgmt_vlan=mv, l3_svis=l3svis,
            mgmt_ip=mip, mgmt_gw=mgw, uplink_po=po, hsrp_priority=prio, location=loc
        )
        write_file(OUT_CISCO, f"{hostname}.txt", cfg)

    # ── REMOTE EDGE (3 configs) ───────────────────────────────────────────────
    remote_params = [
        ("EDGE-SW-REMOTE-03", "c9300-24p", 1, "network-advantage", 10, 900, "192.0.2.213", "192.0.2.254", "Remote Edge Site-3"),
        ("EDGE-SW-REMOTE-04", "c9300-24p", 1, "network-advantage", 17, 903, "192.0.2.214", "192.0.2.254", "Remote Edge Site-4"),
        ("EDGE-SW-REMOTE-05", "c9300-48p", 1, "network-advantage", 18, 903, "192.0.2.215", "192.0.2.254", "Remote Edge Site-5"),
    ]
    for row in remote_params:
        hostname, model, stack, lic, dv, mv, mip, mgw, loc = row
        cfg = c9300_remote_edge_config(
            hostname=hostname, model=model, stack_size=stack, license_level=lic,
            data_vlan=dv, mgmt_vlan=mv, mgmt_ip=mip, mgmt_gw=mgw, location=loc
        )
        write_file(OUT_CISCO, f"{hostname}.txt", cfg)

    # ── BUILDING EDGE (2 configs) ─────────────────────────────────────────────
    bldg_params = [
        ("BLDG-N-FLOOR1-SW01", "c9300-48p", 1, "network-advantage", "rapid-pvst", 10, 20, 900, "192.0.2.216", "192.0.2.254", "Building-N Floor-1"),
        ("BLDG-P-FLOOR1-SW01", "c9300-48p", 2, "network-advantage", "pvst",       11, 21, 901, "192.0.2.217", "192.0.2.254", "Building-P Floor-1"),
    ]
    for row in bldg_params:
        hostname, model, stack, lic, stp, dv, vv, mv, mip, mgw, loc = row
        cfg = c9300_building_edge_config(
            hostname=hostname, model=model, stack_size=stack, license_level=lic,
            stp_mode=stp, data_vlan=dv, voice_vlan=vv, mgmt_vlan=mv,
            mgmt_ip=mip, mgmt_gw=mgw, location=loc
        )
        write_file(OUT_CISCO, f"{hostname}.txt", cfg)

    print(f"\nGenerating Arista EOS configs (20)...")

    # ── ARISTA ACCESS (8 configs) ─────────────────────────────────────────────
    arista_access_params = [
        # hostname, model, eos, vlans, mgmt_v, mgmt_ip, uplink_port, uplink_po, port_count, location
        ("CAMPUS-ACCESS-SW05", "CCS-720XP-24ZY4", "EOS-4.31.3M",
         {100: "USERS", 200: "VOICE"}, 4060, "198.51.100.63", 25, None, 24, "Building-A Access SW05"),
        ("CAMPUS-ACCESS-SW06", "CCS-720XP-24ZY4", "EOS-4.31.3M",
         {100: "USERS", 200: "VOICE", 300: "IOT"}, 4060, "198.51.100.64", 25, None, 24, "Building-B Access SW06"),
        ("CAMPUS-ACCESS-SW07", "CCS-720XP-48ZY4", "EOS-4.32.1F",
         {110: "USERS", 210: "VOICE"}, 4061, "198.51.100.65", 49, 500, 48, "Building-C Access SW07"),
        ("CAMPUS-ACCESS-SW08", "CCS-720XP-48ZY4", "EOS-4.32.1F",
         {110: "USERS", 210: "VOICE", 310: "GUEST"}, 4061, "198.51.100.66", 49, 501, 48, "Building-D Access SW08"),
        ("CAMPUS-ACCESS-SW09", "DCS-7050CX3-32S", "EOS-4.30.5M",
         {120: "USERS", 220: "VOICE"}, 4062, "198.51.100.67", 25, None, 24, "Building-E Access SW09"),
        ("CAMPUS-ACCESS-SW10", "DCS-7050CX3-32S", "EOS-4.30.5M",
         {120: "USERS", 220: "VOICE", 320: "IOT"}, 4062, "198.51.100.68", 25, None, 24, "Building-F Access SW10"),
        ("CAMPUS-ACCESS-SW11", "CCS-720XP-24ZY4", "EOS-4.31.3M",
         {130: "USERS", 230: "VOICE"}, 4063, "198.51.100.69", 25, None, 24, "Building-G Access SW11"),
        ("CAMPUS-ACCESS-SW12", "CCS-720XP-48ZY4", "EOS-4.32.1F",
         {130: "USERS", 230: "VOICE", 330: "GUEST", 777: "AP-MGMT"}, 4063, "198.51.100.70", 49, 502, 48, "Building-H Access SW12"),
    ]

    for row in arista_access_params:
        hostname, model, eos, vlans, mgmt_v, mgmt_ip, up_port, up_po, port_cnt, loc = row
        cfg = arista_access_config(
            hostname=hostname, model=model, eos_version=eos,
            vlans=vlans, mgmt_vlan=mgmt_v, mgmt_ip=mgmt_ip,
            uplink_port=up_port, uplink_po=up_po, port_count=port_cnt, location=loc
        )
        write_file(OUT_ARISTA, f"{hostname}.txt", cfg)

    # ── ARISTA DISTRIBUTION (7 configs) ──────────────────────────────────────
    arista_dist_params = [
        # hostname, model, eos, vlans, mgmt_v, mgmt_ip, mlag_peer_ip, mlag_peer_ports, uplink_ports, po_id, location
        ("CAMPUS-DIST-SW03", "CCS-720XP-24ZY4", "EOS-4.31.3M",
         {100: "USERS", 200: "VOICE", 300: "IOT", 777: "AP-MGMT"}, 4060, "198.51.100.71",
         "169.254.0.2", [23, 24], [27, 28], 2001, "Campus Distribution SW03"),
        ("CAMPUS-DIST-SW04", "CCS-720XP-24ZY4", "EOS-4.31.3M",
         {100: "USERS", 200: "VOICE", 300: "IOT", 777: "AP-MGMT"}, 4060, "198.51.100.72",
         "169.254.0.1", [23, 24], [27, 28], 2001, "Campus Distribution SW04"),
        ("CAMPUS-DIST-SW05", "CCS-720XP-48ZY4", "EOS-4.32.1F",
         {110: "USERS", 210: "VOICE", 310: "IOT"}, 4061, "198.51.100.73",
         "169.254.0.6", [47, 48], [49, 50], 2002, "Campus Distribution SW05"),
        ("CAMPUS-DIST-SW06", "CCS-720XP-48ZY4", "EOS-4.32.1F",
         {110: "USERS", 210: "VOICE", 310: "IOT"}, 4061, "198.51.100.74",
         "169.254.0.5", [47, 48], [49, 50], 2002, "Campus Distribution SW06"),
        ("CAMPUS-DIST-SW07", "DCS-7050CX3-32S", "EOS-4.30.5M",
         {120: "USERS", 220: "VOICE", 320: "GUEST", 420: "IOT"}, 4062, "198.51.100.75",
         "169.254.0.10", [31, 32], [29, 30], 2003, "Campus Distribution SW07"),
        ("CAMPUS-DIST-SW08", "DCS-7050CX3-32S", "EOS-4.30.5M",
         {120: "USERS", 220: "VOICE", 320: "GUEST", 420: "IOT"}, 4062, "198.51.100.76",
         "169.254.0.9", [31, 32], [29, 30], 2003, "Campus Distribution SW08"),
        ("CAMPUS-DIST-SW09", "CCS-720XP-24ZY4", "EOS-4.31.3M",
         {130: "USERS", 230: "VOICE", 330: "GUEST"}, 4063, "198.51.100.77",
         "169.254.0.14", [23, 24], [27, 28], 2004, "Campus Distribution SW09"),
    ]

    for row in arista_dist_params:
        hostname, model, eos, vlans, mgmt_v, mgmt_ip, peer_ip, peer_ports, up_ports, po_id, loc = row
        cfg = arista_distribution_config(
            hostname=hostname, model=model, eos_version=eos,
            vlans=vlans, mgmt_vlan=mgmt_v, mgmt_ip=mgmt_ip,
            mlag_peer_ip=peer_ip, mlag_peer_link_ports=peer_ports,
            uplink_ports=up_ports, po_id=po_id, location=loc
        )
        write_file(OUT_ARISTA, f"{hostname}.txt", cfg)

    # ── ARISTA SPINE (3 configs) ──────────────────────────────────────────────
    spine_params = [
        ("CAMPUS-SPINE-SW01", "DCS-7280CR3K-96TX", "EOS-4.32.1F", 4090, "198.51.100.81", 65001,
         [("203.0.113.2", 65002), ("203.0.113.6", 65003), ("203.0.113.10", 65004), ("203.0.113.14", 65005)],
         "Campus Spine SW01"),
        ("CAMPUS-SPINE-SW02", "DCS-7280CR3K-96TX", "EOS-4.32.1F", 4090, "198.51.100.82", 65001,
         [("203.0.113.18", 65002), ("203.0.113.22", 65003), ("203.0.113.26", 65004), ("203.0.113.30", 65005)],
         "Campus Spine SW02"),
        ("DATACTR-SPINE-SW01", "DCS-7280CR3MK-32D4", "EOS-4.32.1F", 4091, "198.51.100.83", 65010,
         [("203.0.113.34", 65011), ("203.0.113.38", 65012), ("203.0.113.42", 65013)],
         "Data Center Spine SW01"),
    ]

    for row in spine_params:
        hostname, model, eos, mgmt_v, mgmt_ip, asn, peers, loc = row
        cfg = arista_spine_config(
            hostname=hostname, model=model, eos_version=eos,
            mgmt_vlan=mgmt_v, mgmt_ip=mgmt_ip, bgp_asn=asn,
            bgp_peers=peers, location=loc
        )
        write_file(OUT_ARISTA, f"{hostname}.txt", cfg)

    # ── ARISTA OOB (2 configs) ────────────────────────────────────────────────
    arista_oob_params = [
        ("DATACTR-OOBSW-AR01", "DCS-7050TX3-48C8", "EOS-4.30.5M",
         {510: "SERVER-510", 511: "SERVER-511", 512: "SERVER-512", 513: "SERVER-513", 514: "SERVER-514", 515: "SERVER-515"},
         4090, "198.51.100.84", 49, "DC OOB Arista SW01"),
        ("DATACTR-OOBSW-AR02", "DCS-7050TX3-48C8", "EOS-4.30.5M",
         {620: "SERVER-620", 621: "SERVER-621", 622: "SERVER-622", 623: "SERVER-623", 624: "SERVER-624"},
         4090, "198.51.100.85", 49, "DC OOB Arista SW02"),
    ]

    for row in arista_oob_params:
        hostname, model, eos, svlans, mgmt_v, mgmt_ip, up_port, loc = row
        cfg = arista_oob_config(
            hostname=hostname, model=model, eos_version=eos,
            server_vlans=svlans, mgmt_vlan=mgmt_v, mgmt_ip=mgmt_ip,
            uplink_port=up_port, location=loc
        )
        write_file(OUT_ARISTA, f"{hostname}.txt", cfg)

    # ── NX-OS (3 configs) ─────────────────────────────────────────────────────
    print("\nGenerating NX-OS configs (3, unsupported-vendor LLM path)...")
    nxos_params = [
        ("DATACTR-NXOS-SW01",
         {800: "SERVER-800", 801: "SERVER-801", 802: "SERVER-802", 803: "SERVER-803"}, "198.51.100.90"),
        ("DATACTR-NXOS-SW02",
         {900: "SERVER-900", 901: "SERVER-901", 902: "SERVER-902"}, "198.51.100.91"),
        ("DATACTR-NXOS-SW03",
         {1000: "SERVER-1000", 1001: "SERVER-1001", 1002: "SERVER-1002"}, "198.51.100.92"),
    ]
    for hostname, vlans, mgmt_ip in nxos_params:
        cfg = nxos_config(hostname=hostname, vlans=vlans, mgmt_ip=mgmt_ip)
        write_file(OUT_NXOS, f"{hostname}.txt", cfg)

    # ── Summary ───────────────────────────────────────────────────────────────
    cisco_count  = len([f for f in os.listdir(OUT_CISCO)  if f.endswith(".txt")])
    arista_count = len([f for f in os.listdir(OUT_ARISTA) if f.endswith(".txt")])
    nxos_count   = len([f for f in os.listdir(OUT_NXOS)   if f.endswith(".txt")])
    print(f"\n{'='*60}")
    print(f"Cisco IOS-XE (all): {cisco_count} configs in {OUT_CISCO}")
    print(f"  (29 existing 3850 + {cisco_count - 29} new 9300/9500)")
    print(f"Arista EOS (all):   {arista_count} configs in {OUT_ARISTA}")
    print(f"  (5 existing + {arista_count - 5} new)")
    print(f"NX-OS (new):        {nxos_count} configs in {OUT_NXOS}")
    total_new = (cisco_count - 29) + (arista_count - 5) + nxos_count
    total_all  = cisco_count + arista_count + nxos_count
    print(f"\nNew configs generated: {total_new}")
    print(f"Total corpus size:     {total_all}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
