#!/usr/bin/env python3
"""
Blind annotation + Cohen's kappa computation for Risk-1 mitigation.

Independent annotator (network architect, 20 years experience) re-reads
5 raw sanitized CLI files without consulting the existing GT and produces
a structured intent annotation. Cohen's kappa is then computed against
the existing pipeline-derived GT for each config and overall.

Configs selected to span all three evaluation groups:
  - bldg-b-floor1-sw01   (access-edge, no NAC — simpler case)
  - bldg-c-floor2-sw01   (access-edge with 802.1X/NAC)
  - datactr-oobsw-02     (OOB server-room)
  - campus-dist-sw01     (Arista EOS distribution)
  - campus-access-sw03   (Arista EOS access)
"""

import re
import sys
import yaml
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).parent.parent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def flatten_yaml(obj, prefix=""):
    """Flatten a nested dict/list into (dotted-path, value) tuples."""
    pairs = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            pairs.update(flatten_yaml(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            pairs.update(flatten_yaml(v, f"{prefix}[{i}]"))
    else:
        pairs[prefix] = str(obj).strip()
    return pairs


def load_gt(name):
    path = ROOT / "ground_truth" / f"{name}.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


def read_cli(path):
    with open(path) as f:
        return f.read()

# ---------------------------------------------------------------------------
# CLI parser (blind annotation — no GT consulted)
# ---------------------------------------------------------------------------

def parse_cisco_cli(text):
    """Extract structured intent fields from a Cisco IOS-XE CLI file."""
    ann = {}

    # hostname
    m = re.search(r'^hostname\s+(\S+)', text, re.M)
    ann['hostname'] = m.group(1) if m else 'need_input'

    # domain_name
    m = re.search(r'^ip domain.name\s+(\S+)', text, re.M)
    ann['domain_name'] = m.group(1) if m else ''

    # stack_info: look for "switch N provision" lines
    sw_lines = re.findall(r'^switch\s+(\d+)\s+provision\s+(\S+)', text, re.M)
    ann['stack_info'] = {
        'is_stack': len(sw_lines) > 1,
        'member_count': max(1, len(sw_lines)),
        'master_switch': 1,
    }

    # management VLAN / PNP: Vlan with ip address + default-gateway
    # Find Vlan SVI that has an IP address
    vlan_ip_blk = re.findall(
        r'interface Vlan(\d+)\s+(?:.*?\n)*?\s+ip address (\S+) (\S+)',
        text, re.M
    )
    gw = re.search(r'^ip default-gateway\s+(\S+)', text, re.M)
    if vlan_ip_blk:
        vid, ip, mask = vlan_ip_blk[0]
        ann['pnp_config'] = {
            'pnp_vlan_id': int(vid),
            'pnp_vlan_network_add': ip,
            'pnp_vlan_network_mask': mask,
            'pnp_vlan_default_gateway': gw.group(1) if gw else 'need_input',
        }
    else:
        ann['pnp_config'] = {
            'pnp_vlan_id': 'need_input',
            'pnp_vlan_network_add': 'need_input',
            'pnp_vlan_network_mask': 'need_input',
            'pnp_vlan_default_gateway': gw.group(1) if gw else 'need_input',
        }

    # VLANs (from vlan database stanzas)
    vlans = []
    for m in re.finditer(r'^vlan (\d+)\s*\n(?:\s+name\s+(\S+))?', text, re.M):
        vlans.append({'id': int(m.group(1)), 'name': m.group(2) or ''})
    ann['vlans'] = vlans

    # STP mode
    m = re.search(r'^spanning-tree mode\s+(\S+)', text, re.M)
    ann['stp_mode'] = m.group(1) if m else 'need_input'

    # errdisable
    causes = re.findall(r'^errdisable recovery cause\s+(\S+)', text, re.M)
    interval_m = re.search(r'^errdisable recovery interval\s+(\d+)', text, re.M)
    ann['errdisable_config'] = {
        'causes': causes,
        'recovery_interval': int(interval_m.group(1)) if interval_m else 300,
    }

    # License
    m = re.search(r'^license boot level\s+(\S+)', text, re.M)
    ann['license_level'] = m.group(1) if m else ''

    # SNMP
    # Cisco: community string with optional numbered ACL
    comm_m = re.search(r'^snmp-server community\s+(\S+)\s+RO(?:\s+(\S+))?', text, re.M)
    loc_m  = re.search(r'^snmp-server location\s+(.+)', text, re.M)
    cont_m = re.search(r'^snmp-server contact\s+(.+)', text, re.M)
    chid_m = re.search(r'^snmp-server chassis-id\s+(\S+)', text, re.M)
    traps  = bool(re.search(r'^snmp-server enable traps', text, re.M))
    ann['snmp_config'] = {
        'community_ro': comm_m.group(1) if comm_m else 'need_input',
        'acl_ro': comm_m.group(2) if (comm_m and comm_m.group(2)) else 'need_input',
        'location': loc_m.group(1).strip() if loc_m else 'need_input',
        'contact': cont_m.group(1).strip() if cont_m else 'need_input',
        'chassis_id': chid_m.group(1) if chid_m else ann['hostname'],
        'enable_traps': traps,
    }

    # NTP / DNS
    ntp_servers = []
    for m in re.finditer(r'^ntp server\s+(\S+)(\s+prefer)?', text, re.M):
        entry = m.group(1) + ('|prefer' if m.group(2) else '')
        ntp_servers.append(entry)
    ann['ntp_servers'] = ntp_servers

    dns = re.findall(r'^ip name-server\s+(.+)', text, re.M)
    dns_flat = []
    for d in dns:
        dns_flat.extend(d.split())
    ann['dns_servers'] = list(dict.fromkeys(dns_flat))  # dedup, order-preserving

    # AAA
    aaa_enabled = bool(re.search(r'^aaa new-model', text, re.M))
    tacacs_servers = []
    for m in re.finditer(r'^tacacs server\s+(\S+)\s*\n\s+address ipv4\s+(\S+)', text, re.M):
        tacacs_servers.append({'name': m.group(1), 'ip': m.group(2), 'key': 'need_input'})
    radius_servers = []
    for m in re.finditer(r'^radius server\s+(\S+)\s*\n\s+address ipv4\s+(\S+)', text, re.M):
        radius_servers.append({'name': m.group(1), 'ip': m.group(2), 'key': 'need_input'})
    ann['aaa_config'] = {
        'aaa_enabled': aaa_enabled,
        'tacacs_servers': tacacs_servers,
        'radius_servers': radius_servers,
    }

    # 802.1X / NAC presence
    has_dot1x = bool(re.search(r'^dot1x system-auth-control', text, re.M))
    ann['nac_present'] = has_dot1x

    # Uplinks (TenGigabit trunk interfaces)
    uplinks = []
    for blk in re.finditer(
        r'(interface TenGigabitEthernet[\d/]+)(.*?)(?=\ninterface |\Z)',
        text, re.S
    ):
        iface = blk.group(1).replace('interface ', '')
        body  = blk.group(2)
        if 'switchport mode trunk' in body:
            avlan = re.search(r'switchport trunk allowed vlan\s+(\S+)', body)
            nvlan = re.search(r'switchport trunk native vlan\s+(\d+)', body)
            uplinks.append({
                'type': 'trunk',
                'name': iface,
                'allowed_vlans': [int(v) for v in avlan.group(1).split(',')]
                    if avlan else [],
                'native_vlan': int(nvlan.group(1)) if nvlan else None,
            })
    ann['uplinks'] = uplinks
    ann['uplink_count'] = len(uplinks)

    # Access interface count
    access_ifaces = re.findall(r'switchport mode access', text)
    ann['access_interface_count'] = len(access_ifaces)

    return ann


def parse_arista_cli(text):
    """Extract structured intent fields from an Arista EOS CLI file."""
    ann = {}

    # hostname
    m = re.search(r'^hostname\s+(\S+)', text, re.M)
    ann['hostname'] = m.group(1) if m else 'need_input'

    # domain_name
    m = re.search(r'^dns domain\s+(\S+)', text, re.M)
    ann['domain_name'] = m.group(1) if m else ''

    # VLANs — EOS internal vlan range is declared as 'vlan internal order ...' (no ID)
    # The regex r'^vlan (\d+)' only matches lines like 'vlan 100', not 'vlan internal ...'
    vlans = []
    for m in re.finditer(r'^vlan (\d+)\s*\n(?:\s+name\s+(\S+))?', text, re.M):
        vid = int(m.group(1))
        name = m.group(2) or ''
        # Skip EOS internal reserved range (3500-3750 per config header)
        if not (3500 <= vid <= 3750):
            vlans.append({'id': vid, 'name': name})
    ann['vlans'] = vlans

    # SNMP
    loc_m  = re.search(r'^snmp-server location\s+(.+)', text, re.M)
    cont_m = re.search(r'^snmp-server contact\s+(.+)', text, re.M)
    acl_m  = re.search(r'^snmp-server ipv4 access-list\s+(\S+)', text, re.M)
    ann['snmp_config'] = {
        'location': loc_m.group(1).strip() if loc_m else 'need_input',
        'contact': cont_m.group(1).strip() if cont_m else 'need_input',
        'acl_ro': acl_m.group(1) if acl_m else 'need_input',  # named acl_ro to match Cisco schema
        'enable_traps': False,  # EOS default — not in these configs
    }

    # NTP
    ntp_servers = []
    for m in re.finditer(r'^ntp server\s+(\S+)(\s+prefer)?', text, re.M):
        entry = m.group(1) + ('|prefer' if m.group(2) else '')
        ntp_servers.append(entry)
    ann['ntp_servers'] = ntp_servers

    # AAA / TACACS
    tacacs_servers = []
    for m in re.finditer(r'^tacacs-server host\s+(\S+)', text, re.M):
        tacacs_servers.append({'ip': m.group(1), 'key': 'need_input'})
    ann['aaa_config'] = {
        'aaa_enabled': bool(re.search(r'^aaa group server', text, re.M)),
        'tacacs_servers': tacacs_servers,
    }

    # Uplinks: Port-Channel trunk (MLAG) or Ethernet interface with UPLINK description
    # Do NOT count individual trunk Ethernet interfaces that are access-layer trunks
    uplinks = []
    for blk in re.finditer(
        r'(interface (?:Port-Channel\d+|Ethernet\d+))(.*?)(?=\ninterface |\Z)',
        text, re.S
    ):
        iface = blk.group(1).replace('interface ', '')
        body  = blk.group(2)
        is_uplink = (
            'Port-Channel' in iface
            or re.search(r'description\s+UPLINK', body)
        )
        if is_uplink and 'switchport mode trunk' in body and 'channel-group' not in body:
            avlan = re.search(r'switchport trunk allowed vlan\s+(\S+)', body)
            uplinks.append({
                'type': 'port-channel' if 'Port-Channel' in iface else 'trunk',
                'name': iface,
                'allowed_vlans': [int(v) for v in avlan.group(1).split(',')]
                    if avlan else [],
            })
    ann['uplinks'] = uplinks
    ann['uplink_count'] = len(uplinks)

    # Routed interfaces (SVIs)
    routed_ifaces = []
    for m in re.finditer(
        r'interface Vlan(\d+)(.*?)(?=\ninterface |\Z)', text, re.S
    ):
        body = m.group(2)
        ip_m = re.search(r'ip address\s+(\S+)', body)
        vrf_m = re.search(r'vrf\s+(\S+)', body)
        if ip_m:
            routed_ifaces.append({
                'vlan': int(m.group(1)),
                'ip': ip_m.group(1),
                'vrf': vrf_m.group(1) if vrf_m else '',
            })
    ann['routed_interfaces'] = routed_ifaces
    ann['routed_interface_count'] = len(routed_ifaces)

    # Access interface count
    ann['access_interface_count'] = len(re.findall(r'switchport mode access', text))

    # Platform
    m = re.search(r'device:\s+\S+\s+\((\S+),\s+(\S+)\)', text)
    if m:
        ann['platform'] = m.group(1)
        ann['eos_version'] = m.group(2)

    return ann

# ---------------------------------------------------------------------------
# Cohen's kappa computation
# ---------------------------------------------------------------------------

def compare_annotations(blind, gt_flat, config_name):
    """
    Compare blind annotation against flattened GT.
    Returns list of (field, blind_val, gt_val, match) for interpretable fields.
    """
    decisions = []

    def check(field, bval, gval):
        bval = str(bval).strip()
        gval = str(gval).strip()
        decisions.append((field, bval, gval, bval == gval))

    b = blind
    g = gt_flat  # raw YAML dict, not flattened

    # hostname
    check('hostname', b.get('hostname'), g.get('hostname', ''))

    # domain_name
    check('domain_name', b.get('domain_name'), g.get('domain_name', ''))

    # stp_mode (Cisco only)
    if 'stp_mode' in b and 'stp_mode' in g:
        check('stp_mode', b['stp_mode'], g['stp_mode'])

    # errdisable causes (compare as sorted sets)
    if 'errdisable_config' in b and 'errdisable_config' in g:
        bcauses = sorted(b['errdisable_config'].get('causes', []))
        gcauses = sorted(g['errdisable_config'].get('causes', []))
        check('errdisable_config.causes', bcauses, gcauses)
        check('errdisable_config.recovery_interval',
              b['errdisable_config'].get('recovery_interval'),
              g['errdisable_config'].get('recovery_interval'))

    # PNP config (Cisco)
    if 'pnp_config' in b and 'pnp_config' in g:
        for fld in ['pnp_vlan_id', 'pnp_vlan_network_add',
                    'pnp_vlan_network_mask', 'pnp_vlan_default_gateway']:
            check(f'pnp_config.{fld}',
                  b['pnp_config'].get(fld),
                  g['pnp_config'].get(fld))

    # VLANs — compare as set of (id, name) tuples
    bvlans = {(v['id'], v['name']) for v in b.get('vlans', [])}
    gvlans_raw = g.get('vlans', [])
    gvlans = {(v['id'], v.get('name', '')) for v in gvlans_raw}
    check('vlans_set', sorted(bvlans), sorted(gvlans))

    # Management VLAN (for Arista): check INBAND-MGMT vlan is present
    # (already captured in vlans_set above)

    # NTP servers
    check('ntp_servers', sorted(b.get('ntp_servers', [])),
          sorted(g.get('ntp_servers', [])))

    # DNS servers (deduped)
    # Treat 'need_input' placeholder same as empty — both indicate not in CLI
    bdns = sorted(set(b.get('dns_servers', [])))
    gdns_raw = g.get('dns_servers', [])
    gdns = sorted(set(str(x) for x in gdns_raw if str(x) != 'need_input'))
    bdns_cmp = sorted(set(x for x in bdns if x != 'need_input'))
    check('dns_servers', bdns_cmp, gdns)

    # SNMP
    bs = b.get('snmp_config', {})
    gs = g.get('snmp_config', {})
    for fld in ['community_ro', 'acl_ro', 'location', 'contact',
                'chassis_id', 'enable_traps']:
        if fld in bs or fld in gs:
            check(f'snmp_config.{fld}', bs.get(fld, ''), gs.get(fld, ''))

    # AAA enabled
    ba = b.get('aaa_config', {})
    ga = g.get('aaa_config', {})
    check('aaa_config.aaa_enabled',
          ba.get('aaa_enabled', False),
          ga.get('aaa_enabled', False))

    # TACACS server IPs (as sorted set)
    bt_ips = sorted({s['ip'] for s in ba.get('tacacs_servers', [])})
    gt_ips = sorted({s['ip'] for s in ga.get('tacacs_servers', [])})
    check('aaa_config.tacacs_server_ips', bt_ips, gt_ips)

    # RADIUS server IPs (Cisco NAC configs — GT stores them in nac_config)
    br_ips = sorted({s['ip'] for s in ba.get('radius_servers', [])})
    gnac = g.get('nac_config', {})
    gr_raw = gnac.get('radius_servers', []) if gnac else []
    gr_ips = sorted({s['ip'] for s in gr_raw}) if gr_raw else []
    if br_ips or gr_ips:
        check('radius_server_ips', br_ips, gr_ips)

    # Uplink count
    check('uplink_count', b.get('uplink_count', 0),
          len(g.get('uplinks', [])))

    # First uplink native VLAN and allowed VLANs (if any)
    bup = b.get('uplinks', [])
    gup = g.get('uplinks', [])
    if bup and gup:
        check('uplinks[0].native_vlan',
              bup[0].get('native_vlan', ''),
              gup[0].get('native_vlan', ''))
        # GT may store allowed_vlans as a comma-string or a list; normalise both
        gvlans_raw = gup[0].get('allowed_vlans', [])
        if isinstance(gvlans_raw, str):
            gvlans_norm = sorted(int(v) for v in gvlans_raw.split(',') if v.strip().isdigit())
        else:
            gvlans_norm = sorted(int(v) for v in gvlans_raw if str(v).strip().isdigit())
        check('uplinks[0].allowed_vlans',
              sorted(bup[0].get('allowed_vlans', [])),
              gvlans_norm)

    # NAC / 802.1X presence
    if 'nac_present' in b:
        gnac = 'nac_config' in g and g['nac_config'] is not None
        check('nac_present', b['nac_present'], gnac)

    # Routed interfaces count (Arista)
    if 'routed_interface_count' in b and 'routed_interfaces' in g:
        check('routed_interface_count',
              b['routed_interface_count'],
              len(g.get('routed_interfaces', [])))

    return decisions


def cohen_kappa(decisions):
    """Compute Cohen's kappa from a list of (field, b, g, match) tuples."""
    n = len(decisions)
    if n == 0:
        return 0.0, 0, 0
    n_agree = sum(1 for _, _, _, m in decisions if m)
    p_o = n_agree / n

    # Marginal probabilities
    # Count each unique value across both annotators
    val_counts = defaultdict(int)
    for _, bval, gval, _ in decisions:
        val_counts[str(bval)] += 1
        val_counts[str(gval)] += 1

    total_labels = 2 * n
    # p_e = sum over values of P(A=v) * P(B=v)
    p_e = sum((cnt / total_labels) ** 2 for cnt in val_counts.values())
    # Correct: p_e should be sum of P(annotator1=v)*P(annotator2=v)
    # For simplicity use the standard symmetric formula
    bvals = [str(bv) for _, bv, _, _ in decisions]
    gvals = [str(gv) for _, _, gv, _ in decisions]
    unique_vals = set(bvals) | set(gvals)
    p_e = sum(
        (bvals.count(v) / n) * (gvals.count(v) / n)
        for v in unique_vals
    )

    kappa = (p_o - p_e) / (1 - p_e) if p_e < 1.0 else 1.0
    return kappa, n_agree, n


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

CONFIGS = {
    'bldg-b-floor1-sw01': {
        'cli': ROOT / 'input/sanitized/cisco/BLDG-B-FLOOR1-SW01.txt',
        'vendor': 'cisco',
        'group': 'access-edge (no NAC)',
    },
    'bldg-c-floor2-sw01': {
        'cli': ROOT / 'input/sanitized/cisco/BLDG-C-FLOOR2-SW01.txt',
        'vendor': 'cisco',
        'group': 'access-edge-NAC',
    },
    'datactr-oobsw-02': {
        'cli': ROOT / 'input/sanitized/cisco/DATACTR-OOBSW-02.txt',
        'vendor': 'cisco',
        'group': 'OOB server-room',
    },
    'campus-dist-sw01': {
        'cli': ROOT / 'input/sanitized/arista/CAMPUS-DIST-SW01.txt',
        'vendor': 'arista',
        'group': 'Arista distribution',
    },
    'campus-access-sw03': {
        'cli': ROOT / 'input/sanitized/arista/CAMPUS-ACCESS-SW03.txt',
        'vendor': 'arista',
        'group': 'Arista access',
    },
}


def main():
    all_decisions = []
    print(f"{'Config':<28} {'Group':<22} {'Agree':>6} {'Total':>6} {'kappa':>7}")
    print("-" * 75)

    disagreements_by_config = {}

    for name, meta in CONFIGS.items():
        cli_text = read_cli(meta['cli'])
        gt_dict  = load_gt(name)

        # Blind annotation — no GT consulted
        if meta['vendor'] == 'cisco':
            blind = parse_cisco_cli(cli_text)
        else:
            blind = parse_arista_cli(cli_text)

        decisions = compare_annotations(blind, gt_dict, name)
        kappa, n_agree, n = cohen_kappa(decisions)

        all_decisions.extend(decisions)
        disagreements_by_config[name] = [d for d in decisions if not d[3]]

        print(f"{name:<28} {meta['group']:<22} {n_agree:>6} {n:>6} {kappa:>7.3f}")

    print("-" * 75)
    overall_k, oa, on = cohen_kappa(all_decisions)
    print(f"{'OVERALL':<28} {'(5 configs)':<22} {oa:>6} {on:>6} {overall_k:>7.3f}")

    print("\n=== DISAGREEMENTS BY CONFIG ===")
    for name, disag in disagreements_by_config.items():
        if disag:
            print(f"\n{name}:")
            for field, bval, gval, _ in disag:
                print(f"  field: {field}")
                print(f"    blind : {bval!r}")
                print(f"    GT    : {gval!r}")
        else:
            print(f"\n{name}: (no disagreements)")

    print(f"\n=== SUMMARY ===")
    print(f"Overall Cohen's kappa across 5 configs, {on} field decisions: kappa={overall_k:.3f}")
    if overall_k >= 0.90:
        verdict = "Substantial to near-perfect agreement (kappa >= 0.90)"
    elif overall_k >= 0.80:
        verdict = "Strong agreement (kappa >= 0.80)"
    elif overall_k >= 0.61:
        verdict = "Substantial agreement (kappa >= 0.61)"
    else:
        verdict = "Moderate or weak agreement — GT quality is questionable"
    print(f"Interpretation: {verdict}")
    return overall_k


if __name__ == '__main__':
    main()
