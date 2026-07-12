#!/usr/bin/env python3
"""
Cisco Catalyst 3850 to 9300 Migration Script

This script analyzes Cisco Catalyst 3850 configurations and generates
9300-compliant NAC Tool device configurations for automated deployment.

Usage:
    # Process single 3850 configuration file
    python 3850_parser.py --config path/to/3850-config.txt --output-dir path/to/outputs/

    # Process multiple 3850 configuration files in a directory
    python 3850_parser.py --input-dir path/to/configs/ --output-dir path/to/outputs/

    # Retrieve configuration from live 3850 device via SSH (interactive - will prompt for credentials)
    python 3850_parser.py --device-ip 10.1.1.100 --output-dir path/to/outputs/

    # Retrieve from live device with credentials (non-interactive)
    python 3850_parser.py --device-ip 10.1.1.100 --username admin --password mypass --output-dir path/to/outputs/

    # Enable verbose logging for debugging
    python 3850_parser.py --config config.txt --output-dir ./output/ --verbose

Features:
    - Automatically extracts hostname from config and uses it as output filename
    - Sets site field to 'need_input' for manual configuration per device
    - Supports both single file and batch directory processing
    - SSH connectivity to retrieve running configs from live 3850 devices
    - Dynamic uplink discovery (TenGig first, GigE fallback)
    - One-to-one access port mapping with full configuration preservation
    - Generates NAC Tool compatible device.nac.yaml files

Examples:
    Input file: va-3850-idf-1.txt (hostname: va-3850-idf-1) → Output: va-3850-idf-1.yaml
    Input file: dallas-core-sw01.txt (hostname: dallas-core-sw01) → Output: dallas-core-sw01.yaml
    Live device: 10.1.1.100 (hostname detected: va-3850-idf-1) → Output: va-3850-idf-1.yaml

Author: Network Automation Team
Version: 1.0
"""

import os
import sys
import re
import argparse
import ipaddress
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging
from getpass import getpass

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    from netmiko import ConnectHandler
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False
    ConnectHandler = None
    logger.warning("netmiko not available - live device retrieval disabled. Install with: pip install netmiko")

# Custom string class to force YAML quoting
class QuotedString(str):
    pass

# Add YAML representer for quoted strings
def quoted_string_representer(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='"')

yaml.add_representer(QuotedString, quoted_string_representer)



class Catalyst3850Parser:
    """Parser for Cisco Catalyst 3850 configurations"""

    def __init__(self, config_text: str):
        self.config = config_text
        self.lines = config_text.split('\n')

    def extract_hostname(self) -> Optional[str]:
        """Extract hostname from configuration"""
        pattern = r'^hostname\s+(.+)$'
        match = re.search(pattern, self.config, re.MULTILINE)
        return match.group(1).strip() if match else None

    def extract_domain_name(self) -> Optional[str]:
        """Extract domain name from configuration"""
        pattern = r'^ip domain[- ]name\s+(.+)$'
        match = re.search(pattern, self.config, re.MULTILINE)
        return match.group(1).strip() if match else None

    def analyze_stack_config(self) -> Dict[str, Any]:
        """Analyze stack configuration"""
        # Check for provision-based stack configuration (common format)
        provision_pattern = r'^switch\s+(\d+)\s+provision\s+\S+'
        provision_matches = re.findall(provision_pattern, self.config, re.MULTILINE)

        # Also check for priority-based configuration (if present)
        priority_pattern = r'^switch\s+(\d+)\s+priority\s+(\d+)$'
        priority_matches = re.findall(priority_pattern, self.config, re.MULTILINE)

        if provision_matches:
            switches = [(int(num), 15) for num in provision_matches]  # Default priority 15
            # Override with actual priorities if found
            if priority_matches:
                priority_dict = {int(num): int(priority) for num, priority in priority_matches}
                switches = [(num, priority_dict.get(num, 15)) for num, _ in switches]

            switches.sort()  # Sort by switch number
            return {
                'is_stack': len(switches) > 1,
                'member_count': len(switches),
                'switches': switches,
                'master_switch': max(switches, key=lambda x: x[1])[0] if len(switches) > 1 else switches[0][0]
            }
        elif priority_matches:
            switches = [(int(num), int(priority)) for num, priority in priority_matches]
            switches.sort()  # Sort by switch number
            return {
                'is_stack': True,
                'member_count': len(switches),
                'switches': switches,
                'master_switch': max(switches, key=lambda x: x[1])[0]  # Highest priority
            }
        else:
            return {
                'is_stack': False,
                'member_count': 1,
                'switches': [(1, 15)],  # Default single switch
                'master_switch': 1
            }

    def determine_pnp_vlan(self) -> Dict[str, Any]:
        """
        Find management VLAN by analyzing SVI + default gateway correlation
        """
        # Extract all SVIs with IP addresses - improved pattern
        svi_pattern = r'^interface Vlan(\d+)\n((?:\s.*\n)*?)(?=^!|\n^[a-zA-Z]|\Z)'
        svi_matches = re.findall(svi_pattern, self.config, re.MULTILINE)

        svis = []
        for vlan_id, svi_config in svi_matches:
            ip_match = re.search(r'ip address (\S+) (\S+)', svi_config)
            if ip_match:
                svis.append({
                    'vlan_id': int(vlan_id),
                    'ip_address': ip_match.group(1),
                    'subnet_mask': ip_match.group(2)
                })

        # Extract default gateway (check both formats)
        default_routes = re.findall(r'ip route 0\.0\.0\.0 0\.0\.0\.0 (\S+)', self.config)
        default_gateway = re.findall(r'ip default-gateway (\S+)', self.config)

        gateway_ip = None
        if default_routes:
            gateway_ip = default_routes[0]
        elif default_gateway:
            gateway_ip = default_gateway[0]

        if not svis:
            return {'pnp_vlan_id': 1, 'pnp_vlan_name': 'default'}

        # If we have a default gateway, find which SVI network contains it
        if gateway_ip:
            for svi in svis:
                try:
                    network = ipaddress.IPv4Network(f"{svi['ip_address']}/{svi['subnet_mask']}", strict=False)
                    if ipaddress.IPv4Address(gateway_ip) in network:
                        vlan_name = self.extract_vlan_name(svi['vlan_id']) or 'MGMT'
                        return {
                            'pnp_vlan_id': svi['vlan_id'],
                            'pnp_vlan_name': vlan_name,
                            'pnp_vlan_network_add': svi['ip_address'],
                            'pnp_vlan_network_mask': svi['subnet_mask'],
                            'pnp_vlan_default_gateway': gateway_ip
                        }
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                    continue

        # Fallback to first SVI found
        first_svi = svis[0]
        vlan_name = self.extract_vlan_name(first_svi['vlan_id']) or 'MGMT'
        return {
            'pnp_vlan_id': first_svi['vlan_id'],
            'pnp_vlan_name': vlan_name,
            'pnp_vlan_network_add': first_svi['ip_address'],
            'pnp_vlan_network_mask': first_svi['subnet_mask'],
            'pnp_vlan_default_gateway': gateway_ip or first_svi['ip_address']
        }

    def extract_vlan_name(self, vlan_id: int) -> Optional[str]:
        """Extract VLAN name for given VLAN ID"""
        pattern = rf'^vlan {vlan_id}\n(?:\s.*\n)*?\s*name\s+(.+)$'
        match = re.search(pattern, self.config, re.MULTILINE)
        return match.group(1).strip() if match else None

    def extract_all_vlans(self) -> List[Dict[str, Any]]:
        """Extract all VLAN configurations"""
        vlan_blocks = re.findall(r'^vlan (\d+(?:-\d+|,\d+)*)\s*\n((?:\s.*\n)*?)(?=^!|^vlan|^[a-zA-Z]|\Z)', self.config, re.MULTILINE)

        vlans = []
        for vlan_range, vlan_config in vlan_blocks:
            # Handle VLAN ranges (e.g., "10-20" or "10,20,30")
            vlan_ids = self._parse_vlan_range(vlan_range)

            # Extract VLAN name if present
            name_match = re.search(r'name\s+(.+)', vlan_config)
            vlan_name = name_match.group(1).strip() if name_match else None

            for vlan_id in vlan_ids:
                vlans.append({
                    'id': vlan_id,
                    'name': vlan_name or f'VLAN_{vlan_id:04d}'
                })

        return vlans

    def _parse_vlan_range(self, vlan_range: str) -> List[int]:
        """Parse VLAN range string into list of VLAN IDs"""
        vlans = []
        parts = vlan_range.split(',')

        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                vlans.extend(range(start, end + 1))
            else:
                vlans.append(int(part))

        return vlans

    def extract_vtp_domain(self) -> Optional[str]:
        """Extract VTP domain from configuration"""
        pattern = r'^vtp domain\s+(.+)$'
        match = re.search(pattern, self.config, re.MULTILINE)
        return match.group(1).strip() if match else None

    def extract_vtp_mode(self) -> str:
        """Extract VTP mode from configuration, default to transparent"""
        pattern = r'^vtp mode\s+(.+)$'
        match = re.search(pattern, self.config, re.MULTILINE)
        return match.group(1).strip() if match else 'transparent'

    def has_ssh_source_interface(self) -> bool:
        """Check if SSH source interface is configured"""
        pattern = r'^ip ssh source-interface'
        return bool(re.search(pattern, self.config, re.MULTILINE))

    def has_snmp_source_interface(self) -> bool:
        """Check if SNMP source interface is configured"""
        pattern = r'^snmp-server source-interface'
        return bool(re.search(pattern, self.config, re.MULTILINE))

    def has_ntp_source_interface(self) -> bool:
        """Check if NTP source interface is configured"""
        pattern = r'^ntp source'
        return bool(re.search(pattern, self.config, re.MULTILINE))

    def has_tacacs_source_interface(self) -> bool:
        """Check if TACACS source interface is configured"""
        pattern = r'^ip tacacs source-interface'
        return bool(re.search(pattern, self.config, re.MULTILINE))

    def has_radius_source_interface(self) -> bool:
        """Check if RADIUS source interface is configured"""
        pattern = r'^ip radius source-interface'
        return bool(re.search(pattern, self.config, re.MULTILINE))

    def extract_acls(self) -> List[Dict[str, Any]]:
        """Extract both numbered and named ACLs, preserving their original format"""
        acls = []

        # Extract numbered ACL entries
        numbered_acls = {}
        numbered_acl_pattern = r'^access-list\s+(\d+)\s+(.+)$'

        for match in re.finditer(numbered_acl_pattern, self.config, re.MULTILINE):
            acl_num = int(match.group(1))
            acl_line = match.group(2).strip()

            if acl_num not in numbered_acls:
                numbered_acls[acl_num] = []
            numbered_acls[acl_num].append(acl_line)

        # Process numbered ACLs
        for acl_num, acl_entries in numbered_acls.items():
            # Determine ACL type based on number range
            if 1 <= acl_num <= 99 or 1300 <= acl_num <= 1999:
                acl_type = 'standard'
            elif 100 <= acl_num <= 199 or 2000 <= acl_num <= 2699:
                acl_type = 'extended'
            else:
                # For numbers outside standard ranges, determine by content
                acl_type = 'extended' if any('tcp' in entry or 'udp' in entry for entry in acl_entries) else 'standard'

            # Parse entries
            parsed_entries = []
            sequence = 10

            for entry in acl_entries:
                parsed_entry = self._parse_acl_entry(entry, acl_type)
                if parsed_entry:
                    parsed_entry['sequence'] = sequence
                    parsed_entries.append(parsed_entry)
                    sequence += 10

            if parsed_entries:
                acls.append({
                    'name': str(acl_num),  # Keep as number
                    'type': acl_type,
                    'entries': parsed_entries,
                    'is_numbered': True
                })

        # Extract named ACL entries (if any exist)
        # Standard named ACLs
        named_standard_pattern = r'^ip access-list standard\s+(\S+)\n((?:^\s.*\n)*?)(?=^!|^ip access-list|\Z)'
        for match in re.finditer(named_standard_pattern, self.config, re.MULTILINE):
            acl_name = match.group(1)

            # NOTE: Previously skipped AutoQoS ACLs here, but user requested full mapping.
            # If needed, filter can be re-enabled later.

            acl_config = match.group(2)

            # Parse named ACL entries
            parsed_entries = []
            entry_lines = [line.strip() for line in acl_config.split('\n') if line.strip()]

            for line in entry_lines:
                # Skip comment lines and empty lines
                if not line or line.startswith('!'):
                    continue

                # Parse sequence number and entry (handle both with and without sequence numbers)
                seq_match = re.match(r'(\d+)\s+(.+)', line)
                if seq_match:
                    sequence = int(seq_match.group(1))
                    entry_text = seq_match.group(2)
                else:
                    # If no sequence number, generate one
                    sequence = len(parsed_entries) * 10 + 10
                    entry_text = line

                parsed_entry = self._parse_acl_entry(entry_text, 'standard')
                if parsed_entry:
                    parsed_entry['sequence'] = sequence
                    parsed_entries.append(parsed_entry)

            if parsed_entries:
                acls.append({
                    'name': acl_name,
                    'type': 'standard',
                    'entries': parsed_entries,
                    'is_numbered': False
                })

        # Extended named ACLs
        named_extended_pattern = r'^ip access-list extended\s+(\S+)\n((?:^\s.*\n)*?)(?=^!|^ip access-list|\Z)'
        for match in re.finditer(named_extended_pattern, self.config, re.MULTILINE):
            acl_name = match.group(1)

            # NOTE: Previously skipped AutoQoS ACLs here, but user requested full mapping.

            acl_config = match.group(2)

            # Parse named ACL entries
            parsed_entries = []
            entry_lines = [line.strip() for line in acl_config.split('\n') if line.strip()]

            for line in entry_lines:
                # Skip comment lines and empty lines
                if not line or line.startswith('!'):
                    continue

                # Parse sequence number and entry (handle both with and without sequence numbers)
                seq_match = re.match(r'(\d+)\s+(.+)', line)
                if seq_match:
                    sequence = int(seq_match.group(1))
                    entry_text = seq_match.group(2)
                else:
                    # If no sequence number, generate one
                    sequence = len(parsed_entries) * 10 + 10
                    entry_text = line

                parsed_entry = self._parse_acl_entry(entry_text, 'extended')
                if parsed_entry:
                    parsed_entry['sequence'] = sequence
                    parsed_entries.append(parsed_entry)

            if parsed_entries:
                acls.append({
                    'name': acl_name,
                    'type': 'extended',
                    'entries': parsed_entries,
                    'is_numbered': False
                })

        return acls

    def _parse_acl_entry(self, entry: str, acl_type: str) -> Optional[Dict[str, Any]]:
        """Parse individual ACL entry"""
        # Skip remark lines
        if 'remark' in entry.lower():
            return None

        if acl_type == 'standard':
            # Standard ACL: permit/deny source [wildcard] or permit/deny host x.x.x.x
            if 'host' in entry:
                # Handle "permit host 192.168.100.10" format
                match = re.match(r'(permit|deny)\s+host\s+(\S+)(?:\s+log)?', entry)
                if match:
                    action, host_ip = match.groups()
                    return {
                        'action': action,
                        'source': f'host {host_ip}',
                        'log': 'log' in entry
                    }
            else:
                # Handle "permit 192.168.1.0 0.0.0.255" or "permit any" format
                match = re.match(r'(permit|deny)\s+(\S+)(?:\s+(\S+))?(?:\s+log)?', entry)
                if match:
                    action, source, wildcard = match.groups()
                    if source == 'any':
                        source_formatted = 'any'
                    else:
                        source_formatted = source if not wildcard else f'{source} {wildcard}'

                    return {
                        'action': action,
                        'source': source_formatted,
                        'log': 'log' in entry
                    }
        else:
            # Extended ACL - more complex parsing
            # permit/deny protocol source [source-wildcard] destination [dest-wildcard] [port-options]
            tokens = entry.split()
            if len(tokens) < 4:
                return None

            parsed = {
                'action': tokens[0],
                'protocol': tokens[1],
                'log': 'log' in entry
            }

            # Helper function to check if a token is an IP address or wildcard mask
            def is_ip_address(token):
                parts = token.split('.')
                if len(parts) != 4:
                    return False
                try:
                    return all(0 <= int(part) <= 255 for part in parts)
                except ValueError:
                    return False

            # Helper function to check if a token is a port operator
            def is_port_operator(token):
                return token in ['eq', 'gt', 'lt', 'range', 'neq']

            token_idx = 2  # Starting after action and protocol

            # Parse source
            if tokens[token_idx] == 'any':
                parsed['source'] = 'any'
                token_idx += 1
            elif tokens[token_idx] == 'host':
                parsed['source'] = f'host {tokens[token_idx + 1]}'
                token_idx += 2
            else:
                # Network address - check for wildcard mask
                source_addr = tokens[token_idx]
                token_idx += 1
                source_wildcard = None

                if (token_idx < len(tokens) and
                    is_ip_address(tokens[token_idx]) and
                    tokens[token_idx] != 'any' and
                    tokens[token_idx] != 'host' and
                    not is_port_operator(tokens[token_idx])):
                    source_wildcard = tokens[token_idx]
                    token_idx += 1

                # Keep original format for extended ACLs
                parsed['source'] = source_addr if not source_wildcard else f'{source_addr} {source_wildcard}'

            # Parse destination (if present)
            if token_idx < len(tokens) and not is_port_operator(tokens[token_idx]):
                if tokens[token_idx] == 'any':
                    parsed['destination'] = 'any'
                    token_idx += 1
                elif tokens[token_idx] == 'host':
                    parsed['destination'] = f'host {tokens[token_idx + 1]}'
                    token_idx += 2
                else:
                    # Network address - check for wildcard mask
                    dest_addr = tokens[token_idx]
                    token_idx += 1
                    dest_wildcard = None

                    if (token_idx < len(tokens) and
                        is_ip_address(tokens[token_idx]) and
                        tokens[token_idx] != 'any' and
                        tokens[token_idx] != 'host' and
                        not is_port_operator(tokens[token_idx])):
                        dest_wildcard = tokens[token_idx]
                        token_idx += 1

                    # Keep original format for extended ACLs
                    parsed['destination'] = dest_addr if not dest_wildcard else f'{dest_addr} {dest_wildcard}'
            else:
                # No destination specified, default to 'any'
                parsed['destination'] = 'any'

            # Parse port information (eq, gt, lt, range)
            while token_idx < len(tokens):
                if is_port_operator(tokens[token_idx]):
                    parsed['port_operator'] = tokens[token_idx]
                    if tokens[token_idx] == 'range' and token_idx + 2 < len(tokens):
                        parsed['port_start'] = tokens[token_idx + 1]
                        parsed['port_end'] = tokens[token_idx + 2]
                        token_idx += 3
                    elif token_idx + 1 < len(tokens):
                        parsed['port'] = tokens[token_idx + 1]
                        token_idx += 2
                    else:
                        token_idx += 1
                    break
                else:
                    token_idx += 1

            return parsed

        return None

    def _convert_wildcard_to_named_format(self, address: str, wildcard: Optional[str]) -> str:
        """Convert wildcard mask format to named ACL format"""
        if address == 'any':
            return 'any'

        if not wildcard:
            return f'host {address}'

        if wildcard == '0.0.0.0':
            return f'host {address}'

        try:
            # Convert wildcard to prefix length
            wildcard_int = int(ipaddress.IPv4Address(wildcard))
            prefix_len = 32 - bin(wildcard_int).count('1')
            return f'{address}/{prefix_len}'
        except:
            # Fallback to original format
            return f'{address} {wildcard}'

    def determine_uplink_interfaces(self) -> List[Dict[str, Any]]:
        """
        Dynamically discover uplink interfaces by scanning Port-channels first, then TenGig, then GigE as fallback
        Always maps to TenGig target interfaces regardless of source type
        """
        stack_info = self.analyze_stack_config()

        # First, try to discover Port-channel trunk interfaces (highest priority)
        portchannel_uplinks = self._discover_portchannel_interfaces()
        logger.debug(f"Discovered {len(portchannel_uplinks)} Port-channel trunk interfaces")

        if portchannel_uplinks:
            # Process Port-channel trunks directly
            uplinks = self._process_portchannel_uplinks(portchannel_uplinks, stack_info, 'TenGigabitEthernet')
            logger.debug(f"Generated {len(uplinks)} uplinks from Port-channel interfaces")
            return uplinks

        # Second, try to discover TenGig trunk interfaces
        tengig_uplinks = self._discover_trunk_interfaces('TenGigabitEthernet')
        logger.debug(f"Discovered {len(tengig_uplinks)} TenGig trunk interfaces")

        if tengig_uplinks:
            # Process TenGig trunks and map to TenGig targets
            uplinks = self._process_discovered_uplinks(tengig_uplinks, stack_info, 'TenGigabitEthernet')
            logger.debug(f"Generated {len(uplinks)} uplinks from TenGig interfaces")
            return uplinks

        # Fallback: discover GigE trunk interfaces but map to TenGig targets
        gige_uplinks = self._discover_trunk_interfaces('GigabitEthernet')
        logger.debug(f"Discovered {len(gige_uplinks)} GigE trunk interfaces")

        if gige_uplinks:
            # Process GigE trunks but map to TenGig targets (for consistency)
            uplinks = self._process_discovered_uplinks(gige_uplinks, stack_info, 'TenGigabitEthernet')
            logger.debug(f"Generated {len(uplinks)} uplinks from GigE interfaces")
            return uplinks

        # No trunk interfaces found
        logger.debug("No trunk interfaces found")
        return []

    def _discover_portchannel_interfaces(self) -> List[Dict[str, Any]]:
        """Discover all Port-channel interfaces that are configured as trunks"""
        portchannel_interfaces = []

        # Pattern to match Port-channel interface blocks
        intf_pattern = r'^interface Port-channel(\d+)\n((?:\s.*\n)*?)(?=^!|\n^interface|\n^[a-zA-Z]|\Z)'

        for match in re.finditer(intf_pattern, self.config, re.MULTILINE):
            pc_id = match.group(1)
            intf_config = match.group(2)
            interface_name = f'Port-channel{pc_id}'

            # Check if this is a trunk interface
            if 'switchport mode trunk' in intf_config:
                # Extract trunk configuration using existing method
                trunk_config = self._extract_interface_config(interface_name)

                if trunk_config and trunk_config.get('mode') == 'trunk':
                    # Find member interfaces for this port-channel
                    member_interfaces = self._find_portchannel_members(int(pc_id))

                    portchannel_interfaces.append({
                        'name': interface_name,
                        'port_channel_id': int(pc_id),
                        'switch': 1,  # Port-channels span the entire stack
                        'module': 0,
                        'port': int(pc_id),
                        'config': trunk_config,
                        'member_interfaces': member_interfaces
                    })

        return portchannel_interfaces

    def _find_portchannel_members(self, pc_id: int) -> List[Dict[str, Any]]:
        """Find all member interfaces for a given port-channel ID"""
        members = []

        # Pattern to find interfaces with channel-group configuration
        channel_pattern = rf'interface ((?:Gig|TenGig)abitEthernet\d+/\d+/\d+)\n((?:\s.*\n)*?)(?=^!|\n^interface|\n^[a-zA-Z]|\Z)'

        for match in re.finditer(channel_pattern, self.config, re.MULTILINE):
            intf_name = match.group(1)
            intf_config = match.group(2)

            # Check for channel-group membership
            channel_match = re.search(rf'channel-group\s+{pc_id}\s+mode\s+(\w+)', intf_config)
            if channel_match:
                lacp_mode = channel_match.group(1)
                description_match = re.search(r'description\s+(.+)', intf_config)
                description = description_match.group(1).strip() if description_match else f'PORT-CHANNEL-{pc_id}-MEMBER'

                members.append({
                    'name': intf_name,
                    'lacp_mode': lacp_mode,
                    'description': description
                })

        return members

    def _process_portchannel_uplinks(self, portchannel_interfaces: List[Dict[str, Any]],
                                   stack_info: Dict[str, Any], target_interface_type: str) -> List[Dict[str, Any]]:
        """Process discovered Port-channel interfaces and generate uplink configuration"""
        uplinks = []

        for pc_intf in portchannel_interfaces:
            pc_config = pc_intf['config']
            member_interfaces = pc_intf.get('member_interfaces', [])

            # Determine target interfaces based on stack configuration
            target_interfaces = self._get_target_uplink_interfaces_for_portchannel(
                member_interfaces, stack_info, target_interface_type
            )

            uplinks.append({
                'type': 'port-channel',
                'port_channel_id': pc_intf['port_channel_id'],
                'description': pc_config.get('description', f"DISCOVERED-UPLINK-PC{pc_intf['port_channel_id']}"),
                'allowed_vlans': pc_config.get('allowed_vlans', []),
                'native_vlan': pc_config.get('native_vlan'),
                'member_interfaces': [
                    {
                        'name': target_intf,
                        'lacp_mode': 'active'  # Default to active mode
                    }
                    for target_intf in target_interfaces
                ]
            })

        return uplinks

    def _get_target_uplink_interfaces_for_portchannel(self, member_interfaces: List[Dict[str, Any]],
                                                    stack_info: Dict[str, Any], target_type: str) -> List[str]:
        """Map port-channel member interfaces to target interface types based on stack configuration"""
        target_interfaces = []

        if stack_info['is_stack']:
            # For stacks: use first port on first switch and first port on last switch
            switches = [sw[0] for sw in stack_info['switches']]  # Get switch numbers
            first_switch = min(switches)
            last_switch = max(switches)

            if len(member_interfaces) >= 1:
                # First member goes to first switch, first port
                target_interfaces.append(f'{target_type}{first_switch}/1/1')

            if len(member_interfaces) >= 2 and first_switch != last_switch:
                # Second member goes to last switch, first port (if different from first)
                target_interfaces.append(f'{target_type}{last_switch}/1/1')
            elif len(member_interfaces) >= 2:
                # If only one switch, use second port on same switch
                target_interfaces.append(f'{target_type}{first_switch}/1/2')

            # Additional members alternate between first and last switches
            for i in range(2, len(member_interfaces)):
                if first_switch != last_switch:
                    # Alternate between first and last switch, incrementing port numbers
                    if i % 2 == 0:  # Even index (3rd, 5th member, etc.)
                        port_num = (i // 2) + 1
                        target_interfaces.append(f'{target_type}{first_switch}/1/{port_num}')
                    else:  # Odd index (4th, 6th member, etc.)
                        port_num = ((i - 1) // 2) + 2
                        target_interfaces.append(f'{target_type}{last_switch}/1/{port_num}')
                else:
                    # Single switch stack - use consecutive ports
                    target_interfaces.append(f'{target_type}{first_switch}/1/{i + 1}')
        else:
            # Standalone switch - use first and second ports, then consecutive
            for port in range(1, len(member_interfaces) + 1):
                if port <= 4:  # Limit to available ports
                    target_interfaces.append(f'{target_type}1/1/{port}')

        return target_interfaces

    def _discover_trunk_interfaces(self, interface_type: str) -> List[Dict[str, Any]]:
        """Discover all trunk interfaces of specified type"""
        trunk_interfaces = []

        # Pattern to match interface blocks (improved to handle interface termination better)
        intf_pattern = rf'^interface {interface_type}(\d+)/(\d+)/(\d+)\n((?:\s.*\n)*?)(?=^!|\n^interface|\n^[a-zA-Z]|\Z)'

        for match in re.finditer(intf_pattern, self.config, re.MULTILINE):
            switch_num, module, port = match.groups()[:3]
            intf_config = match.group(4)
            interface_name = f'{interface_type}{switch_num}/{module}/{port}'

            # Check if this is a trunk interface
            if 'switchport mode trunk' in intf_config:
                # Extract trunk configuration using existing method
                trunk_config = self._extract_interface_config(interface_name)

                if trunk_config and trunk_config.get('mode') == 'trunk':
                    trunk_interfaces.append({
                        'name': interface_name,
                        'switch': int(switch_num),
                        'module': int(module),
                        'port': int(port),
                        'config': trunk_config
                    })

        return trunk_interfaces

    def _process_discovered_uplinks(self, trunk_interfaces: List[Dict[str, Any]],
                                  stack_info: Dict[str, Any], interface_type: str) -> List[Dict[str, Any]]:
        """Process discovered trunk interfaces and generate uplink configuration"""

        # Group interfaces by port-channel membership
        port_channels = {}
        individual_trunks = []

        for trunk_intf in trunk_interfaces:
            # Check for port-channel membership
            pc_id = self._get_interface_portchannel(trunk_intf['name'])

            if pc_id:
                if pc_id not in port_channels:
                    port_channels[pc_id] = {
                        'id': pc_id,
                        'members': [],
                        'vlans': set(),
                        'native_vlans': []
                    }

                port_channels[pc_id]['members'].append(trunk_intf)

                # Collect VLANs from this member
                if trunk_intf['config'].get('allowed_vlans'):
                    port_channels[pc_id]['vlans'].update(trunk_intf['config']['allowed_vlans'])

                if trunk_intf['config'].get('native_vlan'):
                    port_channels[pc_id]['native_vlans'].append(trunk_intf['config']['native_vlan'])
            else:
                individual_trunks.append(trunk_intf)

        uplinks = []

        # Process port-channels first (higher priority)
        for pc_id, pc_info in port_channels.items():
            # Get port-channel configuration
            pc_config = self._extract_interface_config(f'Port-channel{pc_id}')

            # Determine target interfaces based on stack configuration
            target_interfaces = self._get_target_uplink_interfaces(
                pc_info['members'], stack_info, interface_type
            )

            # Merge VLANs from port-channel config and member interfaces
            merged_vlans = set(pc_info['vlans'])
            if pc_config and pc_config.get('allowed_vlans'):
                merged_vlans.update(pc_config['allowed_vlans'])

            # Determine native VLAN (use most common, or port-channel config, or first found)
            native_vlan = None
            if pc_config and pc_config.get('native_vlan'):
                native_vlan = pc_config['native_vlan']
            elif pc_info['native_vlans']:
                # Use most common native VLAN
                from collections import Counter
                native_vlan = Counter(pc_info['native_vlans']).most_common(1)[0][0]

            uplinks.append({
                'type': 'port-channel',
                'port_channel_id': pc_id,
                'description': pc_config.get('description', 'DISCOVERED-UPLINK-PC') if pc_config else 'DISCOVERED-UPLINK-PC',
                'allowed_vlans': sorted(list(merged_vlans)) if merged_vlans else [],
                'native_vlan': native_vlan,
                'member_interfaces': [
                    {'name': target_intf, 'lacp_mode': 'active'}
                    for target_intf in target_interfaces
                ]
            })

        # Process individual trunk interfaces if no port-channels found
        if not uplinks and individual_trunks:
            logger.debug(f"Processing {len(individual_trunks)} individual trunk interfaces")

            # Merge VLANs from ALL discovered trunk interfaces
            merged_vlans = set()
            native_vlans = []

            for trunk in individual_trunks:
                if trunk['config'].get('allowed_vlans'):
                    merged_vlans.update(trunk['config']['allowed_vlans'])
                if trunk['config'].get('native_vlan'):
                    native_vlans.append(trunk['config']['native_vlan'])

            # Determine most common native VLAN
            most_common_native = None
            if native_vlans:
                from collections import Counter
                most_common_native = Counter(native_vlans).most_common(1)[0][0]

            merged_vlan_list = sorted(list(merged_vlans)) if merged_vlans else []
            logger.debug(f"Merged VLANs from all trunks: {merged_vlan_list}, Native VLAN: {most_common_native}")

            # Select best individual trunks based on stack configuration
            selected_trunks = self._select_individual_trunks(individual_trunks, stack_info, interface_type)
            logger.debug(f"Selected {len(selected_trunks)} trunks for uplinks")

            # Always create exactly 2 uplinks for single switch with consistent naming
            if not stack_info['is_stack']:
                # First uplink - create a copy of the VLAN list
                uplinks.append({
                    'type': 'trunk',
                    'name': f'{interface_type}1/1/1',
                    'description': 'DISCOVERED-UPLINK-1',
                    'allowed_vlans': list(merged_vlan_list),
                    'native_vlan': most_common_native
                })

                # Second uplink - create another copy of the VLAN list
                uplinks.append({
                    'type': 'trunk',
                    'name': f'{interface_type}1/1/2',
                    'description': 'DISCOVERED-UPLINK-2',
                    'allowed_vlans': list(merged_vlan_list),
                    'native_vlan': most_common_native
                })
            else:
                # For stack: create uplinks based on selected trunks but with merged VLANs
                for index, trunk in enumerate(selected_trunks):
                    uplinks.append({
                        'type': 'trunk',
                        'name': self._map_to_target_interface(trunk, stack_info, interface_type, index),
                        'description': f'DISCOVERED-UPLINK-{index + 1}',
                        'allowed_vlans': list(merged_vlan_list),
                        'native_vlan': most_common_native
                    })

        return uplinks

    def _get_interface_portchannel(self, interface_name: str) -> Optional[int]:
        """Get port-channel ID for an interface"""
        intf_pattern = rf'interface {re.escape(interface_name)}\n((?:\s.*\n)*?)(?=^!|\ninterface|\n^[a-zA-Z]|\Z)'
        match = re.search(intf_pattern, self.config, re.MULTILINE)

        if match:
            intf_config = match.group(1)
            channel_match = re.search(r'channel-group\s+(\d+)', intf_config)
            if channel_match:
                return int(channel_match.group(1))

        return None

    def _get_target_uplink_interfaces(self, member_interfaces: List[Dict[str, Any]],
                                    stack_info: Dict[str, Any], interface_type: str) -> List[str]:
        """Map discovered interfaces to target 9300 interface names"""
        if stack_info['is_stack']:
            # Stack: First interface on switch 1 and first on last switch
            last_switch = stack_info['member_count']
            return [
                f'{interface_type}1/1/1',
                f'{interface_type}{last_switch}/1/1'
            ]
        else:
            # Single switch: First two interfaces
            return [
                f'{interface_type}1/1/1',
                f'{interface_type}1/1/2'
            ]

    def _select_individual_trunks(self, trunk_interfaces: List[Dict[str, Any]],
                                stack_info: Dict[str, Any], interface_type: str) -> List[Dict[str, Any]]:
        """Select best individual trunk interfaces based on stack configuration"""
        if not trunk_interfaces:
            return []

        if stack_info['is_stack']:
            # For stack: find first trunk on switch 1 and first on last switch
            last_switch = stack_info['member_count']

            switch1_trunks = [t for t in trunk_interfaces if t['switch'] == 1]
            last_switch_trunks = [t for t in trunk_interfaces if t['switch'] == last_switch]

            selected = []
            if switch1_trunks:
                # Sort by module/port and take first
                switch1_trunks.sort(key=lambda x: (x['module'], x['port']))
                selected.append(switch1_trunks[0])

            if last_switch_trunks and last_switch != 1:
                # Sort by module/port and take first
                last_switch_trunks.sort(key=lambda x: (x['module'], x['port']))
                selected.append(last_switch_trunks[0])

            return selected
        else:
            # Single switch: take first two trunks
            trunk_interfaces.sort(key=lambda x: (x['switch'], x['module'], x['port']))
            return trunk_interfaces[:2]

    def _map_to_target_interface(self, trunk_interface: Dict[str, Any],
                               stack_info: Dict[str, Any], interface_type: str,
                               trunk_index: int = 0) -> str:
        """Map discovered interface to target 9300 interface name"""
        if stack_info['is_stack']:
            if trunk_interface['switch'] == 1:
                return f'{interface_type}1/1/1'
            else:
                return f'{interface_type}{stack_info["member_count"]}/1/1'
        else:
            # For single switch, use trunk_index to determine interface
            if trunk_index == 0:
                return f'{interface_type}1/1/1'
            else:
                return f'{interface_type}1/1/2'

    def _extract_portchannel_for_interfaces(self, interfaces: List[str]) -> Optional[Dict[str, Any]]:
        """Check if given interfaces are members of a port-channel"""
        for interface in interfaces:
            # Look for channel-group configuration on interface
            intf_pattern = rf'interface {re.escape(interface)}\n((?:\s.*\n)*?)(?=\ninterface|\n\S|\n*$)'
            match = re.search(intf_pattern, self.config, re.MULTILINE)

            if match:
                intf_config = match.group(1)
                channel_match = re.search(r'channel-group\s+(\d+)', intf_config)

                if channel_match:
                    pc_id = int(channel_match.group(1))

                    # Extract port-channel configuration
                    pc_config = self._extract_interface_config(f'Port-channel{pc_id}')
                    if pc_config:
                        pc_config['id'] = pc_id
                        return pc_config

        return None

    def _extract_interface_config(self, interface_name: str) -> Optional[Dict[str, Any]]:
        """Extract configuration for specific interface"""
        intf_pattern = rf'interface {re.escape(interface_name)}\n((?:\s.*\n)*?)(?=^!|\ninterface|\n^[a-zA-Z]|\Z)'
        match = re.search(intf_pattern, self.config, re.MULTILINE)

        if not match:
            return None

        intf_config = match.group(1)
        config = {}

        # Extract description
        desc_match = re.search(r'description\s+(.+)', intf_config)
        if desc_match:
            config['description'] = desc_match.group(1).strip()

        # Check if trunk mode
        if 'switchport mode trunk' in intf_config:
            config['mode'] = 'trunk'

            # Extract allowed VLANs
            allowed_match = re.search(r'switchport trunk allowed vlan\s+(.+)', intf_config)
            if allowed_match:
                vlan_list = allowed_match.group(1).strip()
                config['allowed_vlans'] = self._parse_vlan_list(vlan_list)

            # Extract native VLAN
            native_match = re.search(r'switchport trunk native vlan\s+(\d+)', intf_config)
            if native_match:
                config['native_vlan'] = int(native_match.group(1))

        return config

    def _parse_vlan_list(self, vlan_list: str) -> List[int]:
        """Parse VLAN list string (e.g., '10,20-30,40') into list of integers"""
        vlans = []

        if vlan_list.lower() in ['all', 'none']:
            return vlans

        parts = vlan_list.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                vlans.extend(range(start, end + 1))
            else:
                vlans.append(int(part))

        return sorted(vlans)

    def extract_snmp_config(self) -> Dict[str, Any]:
        """Extract SNMP configuration"""
        snmp_config = {}

        # Extract communities with optional ACL restrictions
        ro_match = re.search(r'snmp-server community\s+(\S+)\s+RO(?:\s+(\S+))?', self.config, re.IGNORECASE)
        rw_match = re.search(r'snmp-server community\s+(\S+)\s+RW(?:\s+(\S+))?', self.config, re.IGNORECASE)

        if ro_match:
            snmp_config['community_ro'] = ro_match.group(1)
            if ro_match.group(2):  # ACL restriction
                snmp_config['acl_ro'] = ro_match.group(2)
        if rw_match:
            snmp_config['community_rw'] = rw_match.group(1)
            if rw_match.group(2):  # ACL restriction
                snmp_config['acl_rw'] = rw_match.group(2)

        # Extract location
        location_match = re.search(r'snmp-server location\s+(.+)', self.config)
        if location_match:
            snmp_config['location'] = location_match.group(1).strip()

        # Extract contact
        contact_match = re.search(r'snmp-server contact\s+(.+)', self.config)
        if contact_match:
            snmp_config['contact'] = contact_match.group(1).strip()

        # Extract chassis ID
        chassis_match = re.search(r'snmp-server chassis-id\s+(\S+)', self.config)
        if chassis_match:
            snmp_config['chassis_id'] = chassis_match.group(1)

        # Check if SNMP traps are enabled
        traps_enabled = bool(re.search(r'snmp-server enable traps', self.config))
        snmp_config['enable_traps'] = traps_enabled

        return snmp_config

    def extract_ntp_servers(self) -> List[str]:
        """Extract NTP server configuration with options"""
        ntp_servers = []

        # Pattern to match NTP server lines with optional parameters
        ntp_pattern = r'^ntp server\s+(\S+)(?:\s+(.+))?$'

        for match in re.finditer(ntp_pattern, self.config, re.MULTILINE):
            server_ip = match.group(1)
            options = match.group(2).strip() if match.group(2) else ""

            # Build server entry with pipe-separated options
            server_entry = server_ip

            if options:
                # Parse individual options
                option_parts = []

                # Check for prefer
                if 'prefer' in options:
                    option_parts.append('prefer')

                # Check for version
                version_match = re.search(r'version\s+(\d+)', options)
                if version_match:
                    option_parts.append(f'version:{version_match.group(1)}')

                # Check for key
                key_match = re.search(r'key\s+(\d+)', options)
                if key_match:
                    option_parts.append(f'key:{key_match.group(1)}')

                # Add options to server entry if any found
                if option_parts:
                    server_entry += '|' + '|'.join(option_parts)

            ntp_servers.append(server_entry)

        return ntp_servers

    def extract_ntp_auth_keys(self) -> List[str]:
        """Extract NTP authentication keys configuration"""
        ntp_auth_keys = []

        # Pattern to match NTP authentication key lines
        auth_key_pattern = r'^ntp authentication-key\s+(\d+)\s+md5\s+(\S+)'

        for match in re.finditer(auth_key_pattern, self.config, re.MULTILINE):
            key_id = match.group(1)
            key_value = match.group(2)
            # Format as pipe-delimited: key_id|key_value
            ntp_auth_keys.append(f"{key_id}|{key_value}")

        return ntp_auth_keys

    def extract_dns_servers(self) -> List[str]:
        """Extract DNS server configuration"""
        dns_pattern = r'ip name-server\s+(.+)'
        dns_matches = re.findall(dns_pattern, self.config)

        dns_servers = []
        for match in dns_matches:
            # Handle multiple servers on one line
            servers = match.split()
            dns_servers.extend(servers)

        return dns_servers

    def extract_logging_hosts(self) -> List[str]:
        """Extract logging host configuration"""
        logging_pattern = r'logging host\s+(\S+)'
        return re.findall(logging_pattern, self.config)

    def extract_timezone_config(self) -> Dict[str, Optional[str]]:
        """Extract timezone configuration"""
        # Look for "clock timezone CST -6 0"
        tz_pattern = r'clock timezone\s+(\S+)\s+([-+]?\d+)\s+(\d+)'
        match = re.search(tz_pattern, self.config)

        if match:
            return {
                'timezone': match.group(1),
                'timezone_offset': match.group(2),
                'dst_minutes': match.group(3)
            }

        return {'timezone': None, 'timezone_offset': None, 'dst_minutes': None}

    def extract_daylight_savings(self) -> Optional[str]:
        """Extract daylight savings configuration"""
        # Look for "clock summer-time CDT recurring"
        dst_pattern = r'clock summer-time\s+(\S+)\s+'
        match = re.search(dst_pattern, self.config)
        return match.group(1) if match else None

    def extract_enable_secret(self) -> Optional[str]:
        """Extract enable secret configuration"""
        # Don't extract the actual secret for security, just detect if it exists
        secret_pattern = r'enable secret'
        return 'need_input' if re.search(secret_pattern, self.config) else None

    def extract_spanning_tree_mode(self) -> Optional[str]:
        """Extract spanning tree mode"""
        stp_pattern = r'spanning-tree mode\s+(\S+)'
        match = re.search(stp_pattern, self.config)
        return match.group(1) if match else None

    def extract_errdisable_config(self) -> Dict[str, Any]:
        """Extract error disable configuration"""
        errdisable_config = {}

        # Extract errdisable recovery causes
        causes = re.findall(r'^errdisable recovery cause\s+(\S+)', self.config, re.MULTILINE)
        errdisable_config['causes'] = causes

        # Extract recovery interval
        interval_match = re.search(r'^errdisable recovery interval\s+(\d+)', self.config, re.MULTILINE)
        if interval_match:
            errdisable_config['recovery_interval'] = int(interval_match.group(1))

        return errdisable_config

    def extract_local_users(self) -> List[Dict[str, Any]]:
        """Extract local user accounts"""
        users = []

        # Find all username configurations
        user_matches = re.findall(r'^username\s+(\S+)(?:\s+privilege\s+(\d+))?\s+password\s+\d+\s+(\S+)', self.config, re.MULTILINE)

        for match in user_matches:
            username, privilege, password = match
            user = {
                'name': username,
                'password': 'need_input'  # Security: don't extract actual passwords
            }
            if privilege:
                user['privilege'] = int(privilege)
            users.append(user)

        return users

    def extract_vrf_config(self) -> Optional[Dict[str, Any]]:
        """Extract VRF configuration if present"""
        # Look for VRF definition blocks
        vrf_pattern = r'^vrf definition\s+(\S+)\n((?:^\s.*\n)*?)(?=^!|^vrf definition|\Z)'
        matches = re.finditer(vrf_pattern, self.config, re.MULTILINE)

        for match in matches:
            vrf_name = match.group(1)
            vrf_config = match.group(2)

            # Extract RD
            rd_match = re.search(r'rd\s+(\S+)', vrf_config)
            rd = rd_match.group(1) if rd_match else ''

            # Extract route targets
            rt_export_match = re.search(r'route-target export\s+(\S+)', vrf_config)
            rt_export = rt_export_match.group(1) if rt_export_match else ''

            rt_import_match = re.search(r'route-target import\s+(\S+)', vrf_config)
            rt_import = rt_import_match.group(1) if rt_import_match else ''

            # Check if this VRF is used for management (look for management VLAN using this VRF)
            mgmt_vlan_pattern = rf'vrf forwarding\s+{re.escape(vrf_name)}'
            if re.search(mgmt_vlan_pattern, self.config):
                return {
                    'name': vrf_name,
                    'rd': rd,
                    'rt_export': rt_export,
                    'rt_import': rt_import
                }

        return None

    def extract_aaa_config(self) -> Dict[str, Any]:
        """Extract AAA and TACACS configuration"""
        aaa_config = {}

        # Check if AAA is enabled
        aaa_enabled = bool(re.search(r'^aaa new-model', self.config, re.MULTILINE))
        aaa_config['aaa_enabled'] = aaa_enabled

        if not aaa_enabled:
            return aaa_config

        # Extract TACACS group name
        tacacs_group_match = re.search(r'aaa group server tacacs\+\s+(\S+)', self.config)
        if tacacs_group_match:
            aaa_config['tacacs_group_name'] = tacacs_group_match.group(1)

        # Extract TACACS servers from group configuration
        tacacs_servers = []
        if tacacs_group_match:
            group_name = tacacs_group_match.group(1)
            # Find the group block and extract server names
            group_pattern = rf'^aaa group server tacacs\+ {re.escape(group_name)}\n((?:^\s.*\n)*?)(?=^!)'
            group_match = re.search(group_pattern, self.config, re.MULTILINE)
            if group_match:
                group_config = group_match.group(1)
                server_names = re.findall(r'server name\s+(\S+)', group_config)
                tacacs_servers.extend(server_names)

        # Extract TACACS server details (name, IP, key) - find all server blocks
        tacacs_server_details = []

        # Find all TACACS server blocks in the configuration
        server_blocks = re.findall(r'^tacacs server (\S+)\n((?:^\s.*\n)*?)(?=^!|^tacacs server|\Z)', self.config, re.MULTILINE)

        for server_name, server_config in server_blocks:
            # Extract IP address
            ip_match = re.search(r'address ipv4\s+(\S+)', server_config)

            if ip_match:
                tacacs_server_details.append({
                    'name': server_name,
                    'ip': ip_match.group(1),
                    'key': 'need_input'  # Security: don't extract actual keys
                })

        aaa_config['tacacs_servers'] = tacacs_server_details

        # Extract TACACS timeout
        timeout_match = re.search(r'tacacs-server timeout\s+(\d+)', self.config)
        if timeout_match:
            aaa_config['tacacs_timeout'] = int(timeout_match.group(1))

        return aaa_config

    def extract_access_interfaces(self) -> List[Dict[str, Any]]:
        """Extract all access interface configurations for one-to-one mapping"""
        access_interfaces = []

        # Pattern to match all GigabitEthernet access interfaces
        intf_pattern = r'^interface GigabitEthernet(\d+)/(\d+)/(\d+)\n((?:\s.*\n)*?)(?=^!|\n^interface|\n^[a-zA-Z]|\Z)'

        for match in re.finditer(intf_pattern, self.config, re.MULTILINE):
            switch_num, module, port = match.groups()[:3]
            intf_config = match.group(4)
            interface_name = f'GigabitEthernet{switch_num}/{module}/{port}'

            # Check if this is an access interface (not trunk)
            if 'switchport mode access' in intf_config:
                # Extract interface configuration
                config = {}

                # Extract description
                desc_match = re.search(r'description\s+(.+)', intf_config)
                if desc_match:
                    config['description'] = desc_match.group(1).strip()

                # Extract access VLAN
                vlan_match = re.search(r'switchport access vlan\s+(\d+)', intf_config)
                if vlan_match:
                    config['access_vlan'] = int(vlan_match.group(1))

                # Check if interface is shutdown
                config['shutdown'] = 'shutdown' in intf_config

                # Extract voice VLAN if present
                voice_match = re.search(r'switchport voice vlan\s+(\d+)', intf_config)
                if voice_match:
                    config['voice_vlan'] = int(voice_match.group(1))

                # Extract port-security settings
                if 'switchport port-security' in intf_config:
                    config['port_security'] = True

                    # Extract maximum MAC addresses
                    max_match = re.search(r'switchport port-security maximum\s+(\d+)', intf_config)
                    if max_match:
                        config['port_security_max'] = int(max_match.group(1))

                    # Extract violation action
                    violation_match = re.search(r'switchport port-security violation\s+(\S+)', intf_config)
                    if violation_match:
                        config['port_security_violation'] = violation_match.group(1)

                    # Extract aging time
                    aging_match = re.search(r'switchport port-security aging time\s+(\d+)', intf_config)
                    if aging_match:
                        config['port_security_aging_time'] = int(aging_match.group(1))

                # Extract spanning-tree settings
                if 'spanning-tree portfast' in intf_config:
                    config['portfast'] = True
                if 'spanning-tree bpduguard enable' in intf_config:
                    config['bpduguard'] = True

                # Extract NAC settings
                if 'authentication port-control auto' in intf_config:
                    config['nac_enable'] = True
                if 'mab' in intf_config:
                    config['mab'] = True
                if 'dot1x pae authenticator' in intf_config:
                    config['dot1x'] = True
                
                access_interfaces.append({
                    'name': interface_name,
                    'switch': int(switch_num),
                    'module': int(module),
                    'port': int(port),
                    'config': config
                })

        logger.debug(f"Discovered {len(access_interfaces)} access interfaces")
        return access_interfaces

class DeviceConfigGenerator:
    """Generate NAC Tool device configuration from parsed 3850 config"""

    # Template defaults loaded from template files
    # Only include defaults explicitly stated in templates
    TEMPLATE_DEFAULTS = {
        'system': {
            'license_level': 'network-advantage',  # From EDGE_SYSTEM_template.j2 | default('network-advantage')
            'stp_mode': 'pvst'  # From EDGE_SYSTEM_template.j2 | default('pvst')
        },
        'management': {
            'mgmt_interface': 'GigabitEthernet0/0',  # From template | default('GigabitEthernet0/0')
            'mgmt_vlan_name': 'MGMT',  # From template | default('MGMT')
            'mgmt_description': 'Management VLAN Interface',  # From template | default(...)
            'http_server': True,  # From template | default(true)
            'https_server': True  # From template | default(true)
        },
        'snmp': {
            'enable_traps': True  # From EDGE_SNMP_template.j2 | default(true)
        }
    }

    def __init__(self, parser: Catalyst3850Parser):
        self.parser = parser

    def generate_device_config(self) -> Dict[str, Any]:
        """Generate complete device configuration"""

        # Basic device information
        hostname = self.parser.extract_hostname() or 'MIGRATED-DEVICE'
        domain = self.parser.extract_domain_name() or 'need_input'

        # PnP configuration
        pnp_config = self.parser.determine_pnp_vlan()
        stack_info = self.parser.analyze_stack_config()

        # Determine 9300 model based on 3850 configuration
        model = self._determine_9300_model()

        device_config = {
            'name': hostname,
            'fqdn_name': f"{hostname}.{domain}",
            'device_ip': pnp_config.get('pnp_vlan_network_add', '192.168.1.10'),
            'pid': model,
            'serial_number': 'TBD-MIGRATION',
            'state': 'PNP',
            'device_role': 'ACCESS',
            'site': 'need_input',

            'onboarding_template': {
                'name': 'EDGE_PNP_template',
                'variables': self._generate_pnp_variables(pnp_config, stack_info)
            },

            'dayn_templates': {
                'regular': self._generate_dayn_templates()
            }
        }

        return device_config

    def _determine_9300_model(self) -> str:
        """Determine appropriate 9300 model based on 3850 configuration"""
        # Count access interfaces to determine port density
        access_interfaces = len(re.findall(r'interface GigabitEthernet\d+/0/\d+', self.parser.config))

        if access_interfaces <= 24:
            return 'C9300-24P'  # Assuming PoE requirement
        elif access_interfaces <= 48:
            return 'C9300-48P'
        else:
            return 'C9300-48P'  # Default to 48-port

    def _generate_pnp_variables(self, pnp_config: Dict[str, Any], stack_info: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate PnP template variables"""

        # Get values with defaults - use parsed hostname for PnP device name too
        hostname = self.parser.extract_hostname() or 'PNP-DEVICE'
        domain = self.parser.extract_domain_name() or 'need_input'
        snmp_config = self.parser.extract_snmp_config()
        logging_hosts = self.parser.extract_logging_hosts()

        variables = [
            {'name': 'device_host_name', 'value': hostname},
            {'name': 'domain_name', 'value': domain},
            {'name': 'pnp_vlan_id', 'value': str(pnp_config.get('pnp_vlan_id', 1))},
            {'name': 'pnp_vlan_name', 'value': pnp_config.get('pnp_vlan_name', 'MGMT')},
            {'name': 'pnp_vlan_network_add', 'value': pnp_config.get('pnp_vlan_network_add', '192.168.1.10')},
            {'name': 'pnp_vlan_network_mask', 'value': pnp_config.get('pnp_vlan_network_mask', '255.255.255.0')},
            {'name': 'pnp_vlan_default_gateway', 'value': pnp_config.get('pnp_vlan_default_gateway', '192.168.1.1')},
            {'name': 'pnp_interface', 'value': 'GigabitEthernet1/0/1'},
            {'name': 'snmp_community_ro', 'value': snmp_config.get('community_ro', 'need_input')},
            {'name': 'log_server', 'value': logging_hosts[0] if logging_hosts else '192.168.1.100'},
            {'name': 'is_stack', 'value': str(stack_info['is_stack']).lower()},
            {'name': 'stack_members', 'value': str(stack_info['member_count'])}
        ]

        return variables

    def _generate_dayn_templates(self) -> List[Dict[str, Any]]:
        """Generate Day-N template configurations"""

        templates = []

        # Always include system template
        templates.append({
            'name': 'EDGE_SYSTEM_template',
            'variables': self._generate_system_variables(),
            'redeploy_template': 'ON_CHANGE'
        })

        # VLAN template if VLANs exist
        vlans = self.parser.extract_all_vlans()
        if vlans:
            templates.append({
                'name': 'EDGE_VLAN_template',
                'variables': self._generate_vlan_variables(vlans),
                'redeploy_template': 'ON_CHANGE'
            })

        # Management template
        templates.append({
            'name': 'EDGE_MGMT_template',
            'variables': self._generate_mgmt_variables(),
            'redeploy_template': 'ON_CHANGE'
        })

        # ACL template if ACLs exist
        acls = self.parser.extract_acls()
        if acls:
            templates.append({
                'name': 'EDGE_ACL_template',
                'variables': self._generate_acl_variables(acls),
                'redeploy_template': 'ON_CHANGE'
            })

        # Uplink template
        uplinks = self.parser.determine_uplink_interfaces()
        if uplinks:
            templates.append({
                'name': 'EDGE_UPLINK_template',
                'variables': self._generate_uplink_variables(uplinks),
                'redeploy_template': 'ON_CHANGE'
            })

        # SNMP template
        snmp_config = self.parser.extract_snmp_config()
        if snmp_config:
            templates.append({
                'name': 'EDGE_SNMP_template',
                'variables': self._generate_snmp_variables(snmp_config),
                'redeploy_template': 'ON_CHANGE'
            })

        # AAA template if AAA is configured
        aaa_config = self.parser.extract_aaa_config()
        if aaa_config.get('aaa_enabled') and aaa_config.get('tacacs_servers'):
            templates.append({
                'name': 'EDGE_AAA_template',
                'variables': self._generate_aaa_variables(aaa_config),
                'redeploy_template': 'ON_CHANGE'
            })

        # Access port template for one-to-one mapping
        access_interfaces = self.parser.extract_access_interfaces()
        if access_interfaces:
            templates.append({
                'name': 'EDGE_ACCESS_PORT_template',
                'variables': self._generate_access_port_variables(access_interfaces),
                'redeploy_template': 'ON_CHANGE'
            })

        return templates

    def _generate_system_variables(self) -> List[Dict[str, str]]:
        """Generate system template variables with proper handling of missing values"""

        # Extract configuration values
        hostname = self.parser.extract_hostname()
        domain = self.parser.extract_domain_name()
        tz_config = self.parser.extract_timezone_config()
        daylight_savings = self.parser.extract_daylight_savings()
        enable_secret = self.parser.extract_enable_secret()
        stp_mode = self.parser.extract_spanning_tree_mode()
        ntp_servers = self.parser.extract_ntp_servers()
        ntp_auth_keys = self.parser.extract_ntp_auth_keys()
        dns_servers = self.parser.extract_dns_servers()

        # Generate variables with explicit default handling
        variables = []

        # Required variables without template defaults - 3850 config first, then need_input
        variables.append({
            'name': 'enable_secret',
            'value': enable_secret or 'need_input'
        })

        variables.append({
            'name': 'hostname',
            'value': hostname or 'need_input'
        })

        variables.append({
            'name': 'domain_name',
            'value': domain or 'need_input'
        })

        # Timezone handling - required variables without template defaults
        variables.append({
            'name': 'timezone',
            'value': tz_config['timezone'] or 'need_input'
        })

        variables.append({
            'name': 'timezone_offset',
            'value': tz_config['timezone_offset'] or 'need_input'
        })

        variables.append({
            'name': 'daylight_savings_name',
            'value': daylight_savings or 'need_input'
        })

        # DNS servers - required variable without template default
        variables.append({
            'name': 'dns_servers',
            'value': QuotedString(','.join(dns_servers)) if dns_servers else 'need_input'
        })

        # NTP servers - only include if found in 3850 config
        if ntp_servers:
            # Convert list of NTP servers to comma-separated string format for template
            # Format: "server1,server2" or with options: "server1|prefer,server2|version:3"
            variables.append({
                'name': 'ntp_servers',
                'value': QuotedString(','.join(ntp_servers))
            })
        else:
            # No NTP servers found - template will skip NTP configuration
            variables.append({
                'name': 'ntp_servers',
                'value': 'false'
            })

        # Template defaults from EDGE_SYSTEM_template.j2
        variables.append({
            'name': 'license_level',
            'value': self.TEMPLATE_DEFAULTS['system']['license_level']
        })

        variables.append({
            'name': 'stp_mode',
            'value': stp_mode if stp_mode else self.TEMPLATE_DEFAULTS['system']['stp_mode']
        })

        # Required variables with no template defaults - set false if not found
        variables.append({
            'name': 'ntp_authenticate',
            'value': 'true' if ntp_auth_keys else 'false'
        })

        # NTP authentication keys - pipe delimited format: key_id|key_value,key_id2|key_value2
        if ntp_auth_keys:
            variables.append({
                'name': 'ntp_auth_keys',
                'value': QuotedString(','.join(ntp_auth_keys))
            })

        variables.append({
            'name': 'ntp_master',
            'value': 'false'
        })

        # Logging configuration
        logging_hosts = self.parser.extract_logging_hosts()
        if logging_hosts:
            variables.append({
                'name': 'logging_servers',
                'value': QuotedString(','.join(logging_hosts))
            })

        # Variable with template default for log severity
        variables.append({
            'name': 'log_severity_level',
            'value': 'informational'  # Use template default
        })

        # Error disable configuration
        errdisable_config = self.parser.extract_errdisable_config()
        if errdisable_config.get('causes'):
            variables.append({
                'name': 'errdisable_causes',
                'value': QuotedString(','.join(errdisable_config['causes']))
            })

        if errdisable_config.get('recovery_interval'):
            variables.append({
                'name': 'recovery_interval',
                'value': str(errdisable_config['recovery_interval'])
            })

        # Local users configuration - convert to colon-separated string format
        local_users = self.parser.extract_local_users()
        if local_users:
            # Convert user objects to "username:password" format, multiple users separated by commas
            user_strings = []
            for user in local_users:
                user_strings.append(f"{user['name']}:{user.get('password', 'need_input')}")

            variables.append({
                'name': 'local_users',
                'value': QuotedString(','.join(user_strings))
            })

        return variables

    def _generate_vlan_variables(self, vlans: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate VLAN template variables in pipe-delimited format"""
        # Extract VTP configuration
        vtp_domain = self.parser.extract_vtp_domain()
        vtp_mode = self.parser.extract_vtp_mode()

        # Convert VLAN list to pipe-delimited string format
        vlan_entries = []
        for vlan in vlans:
            vlan_id = str(vlan.get('id', ''))
            vlan_name = vlan.get('name', '')

            if vlan_id:
                if vlan_name:
                    vlan_entries.append(f"{vlan_id}|{vlan_name}")
                else:
                    vlan_entries.append(vlan_id)

        # Create pipe-delimited VLAN string
        vlans_string = ','.join(vlan_entries)

        variables = [
            {'name': 'vlans', 'value': vlans_string}
        ]

        # Add VTP domain if found, otherwise use default
        if vtp_domain:
            variables.append({'name': 'vtp_domain', 'value': vtp_domain})
        else:
            variables.append({'name': 'vtp_domain', 'value': 'CWAN'})

        # Add VTP mode
        variables.append({'name': 'vtp_mode', 'value': vtp_mode})

        return variables

    def _generate_mgmt_variables(self) -> List[Dict[str, str]]:
        """Generate management template variables based on template requirements"""
        pnp_config = self.parser.determine_pnp_vlan()
        vrf_config = self.parser.extract_vrf_config()

        variables = []

        # Determine if management should be enabled based on 3850 config
        # If we found management VLAN with IP, enable management
        has_mgmt = bool(pnp_config.get('pnp_vlan_id') and pnp_config.get('pnp_vlan_network_add'))

        variables.append({'name': 'enable_management', 'value': str(has_mgmt).lower()})
        variables.append({'name': 'http_server', 'value': str(self.TEMPLATE_DEFAULTS['management']['http_server']).lower()})
        variables.append({'name': 'https_server', 'value': str(self.TEMPLATE_DEFAULTS['management']['https_server']).lower()})

        # VRF Configuration - pipe delimited format: name|rd|rt_export|rt_import
        if vrf_config:
            vrf_string = f"{vrf_config['name']}|{vrf_config['rd']}|{vrf_config['rt_export']}|{vrf_config['rt_import']}"
            variables.append({'name': 'mgmt_vrf_config', 'value': QuotedString(vrf_string)})

        # Extract source interface configurations from 3850 config
        has_ssh_source = self.parser.has_ssh_source_interface()
        has_snmp_source = self.parser.has_snmp_source_interface()
        has_ntp_source = self.parser.has_ntp_source_interface()
        has_tacacs_source = self.parser.has_tacacs_source_interface()
        has_radius_source = self.parser.has_radius_source_interface()

        # Only include source interface variables if they exist in 3850 config
        if has_ssh_source:
            variables.append({'name': 'ssh_source_interface', 'value': 'true'})
        if has_snmp_source:
            variables.append({'name': 'snmp_source_interface', 'value': 'true'})
        if has_ntp_source:
            variables.append({'name': 'ntp_source_interface', 'value': 'true'})
        if has_tacacs_source:
            variables.append({'name': 'tacacs_source_interface', 'value': 'true'})
        if has_radius_source:
            variables.append({'name': 'radius_source_interface', 'value': 'true'})

        # Required variables without template defaults - 3850 config first, then need_input
        variables.append({'name': 'mgmt_interface_type', 'value': 'vlan'})  # Inferred from VLAN-based mgmt
        variables.append({'name': 'mgmt_vlan_id', 'value': str(pnp_config.get('pnp_vlan_id', 'need_input'))})
        variables.append({'name': 'mgmt_ip_address', 'value': pnp_config.get('pnp_vlan_network_add', 'need_input')})
        variables.append({'name': 'mgmt_subnet_mask', 'value': pnp_config.get('pnp_vlan_network_mask', 'need_input')})
        variables.append({'name': 'mgmt_default_gateway', 'value': pnp_config.get('pnp_vlan_default_gateway', 'need_input')})

        # Variable with template default - use template default first
        variables.append({'name': 'mgmt_vlan_name', 'value': pnp_config.get('pnp_vlan_name') or self.TEMPLATE_DEFAULTS['management']['mgmt_vlan_name']})

        return variables

    def _generate_acl_variables(self, acls: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate ACL template variables using pipe delimiter format"""
        standard_acl_strings = []
        extended_acl_strings = []

        for acl in acls:
            if acl['type'] == 'standard':
                for entry in acl['entries']:
                    # Format: acl_name|sequence|action|source|wildcard|log
                    sequence = str(entry.get('sequence', ''))
                    action = entry.get('action', 'permit')
                    source = entry.get('source', 'any')

                    # Handle different source formats
                    if 'host' in source:
                        # Keep the full "host x.x.x.x" format
                        source_addr = source
                        wildcard = ''
                    elif source == 'any':
                        source_addr = 'any'
                        wildcard = ''
                    else:
                        # Handle network/wildcard format
                        if ' ' in source:
                            # Already has wildcard (e.g., "192.168.1.0 0.0.0.255")
                            source_parts = source.split(' ')
                            source_addr = source_parts[0]
                            wildcard = source_parts[1]
                        else:
                            # Single IP address, treat as host
                            source_addr = f'host {source}'
                            wildcard = ''

                    log_flag = 'true' if entry.get('log') else 'false'

                    acl_string = f"{acl['name']}|{sequence}|{action}|{source_addr}|{wildcard}|{log_flag}"
                    standard_acl_strings.append(acl_string)

            elif acl['type'] == 'extended':
                for entry in acl['entries']:
                    # Format: acl_name|sequence|action|protocol|source|source_op|dest|dest_op|log
                    sequence = str(entry.get('sequence', ''))
                    action = entry.get('action', 'permit')
                    protocol = entry.get('protocol', 'ip')

                    # Handle source
                    source = entry.get('source', 'any')
                    if 'host' in source:
                        source_formatted = f"host {source.replace('host ', '')}"
                    elif source == 'any':
                        source_formatted = 'any'
                    else:
                        source_formatted = source

                    # Source port operator (simplified)
                    source_op = entry.get('source_port_operator', '')
                    if source_op and entry.get('source_port'):
                        source_op = f"{source_op} {entry['source_port']}"

                    # Handle destination
                    destination = entry.get('destination', 'any')
                    if 'host' in destination:
                        dest_formatted = f"host {destination.replace('host ', '')}"
                    elif destination == 'any':
                        dest_formatted = 'any'
                    else:
                        dest_formatted = destination

                    # Destination port operator (simplified)
                    dest_op = entry.get('dest_port_operator', '') or entry.get('port_operator', '')
                    
                    if dest_op:
                        if dest_op == 'range':
                            start = entry.get('dest_port_start') or entry.get('port_start', '')
                            end = entry.get('dest_port_end') or entry.get('port_end', '')
                            if start and end:
                                dest_op = f"{dest_op} {start} {end}"
                        else:
                            port = entry.get('dest_port') or entry.get('port', '')
                            if port:
                                dest_op = f"{dest_op} {port}"

                    log_flag = 'true' if entry.get('log') else 'false'

                    acl_string = f"{acl['name']}|{sequence}|{action}|{protocol}|{source_formatted}|{source_op}|{dest_formatted}|{dest_op}|{log_flag}"
                    extended_acl_strings.append(acl_string)

        variables = []

        if standard_acl_strings:
            # Format exactly like access interfaces for consistent YAML rendering
            std_acls_multiline = ',\n'.join(standard_acl_strings)
            std_acls_formatted = QuotedString(std_acls_multiline)
            variables.append({'name': 'standard_acls', 'value': std_acls_formatted})
        else:
            variables.append({'name': 'standard_acls', 'value': QuotedString('')})

        if extended_acl_strings:
            # Format exactly like access interfaces for consistent YAML rendering
            ext_acls_multiline = ',\n'.join(extended_acl_strings)
            ext_acls_formatted = QuotedString(ext_acls_multiline)
            variables.append({'name': 'extended_acls', 'value': ext_acls_formatted})
        else:
            variables.append({'name': 'extended_acls', 'value': QuotedString('')})

        return variables

    def _generate_uplink_variables(self, uplinks: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate uplink template variables using pipe delimiter format"""
        uplink_strings = []

        for uplink in uplinks:
            # Extract uplink configuration values
            uplink_type = uplink.get('type', 'trunk')
            uplink_name = uplink.get('name', '')
            description = uplink.get('description', 'UPSTREAM-TRUNK')
            port_channel_id = str(uplink.get('port_channel_id', '')) if uplink.get('port_channel_id') else ''

            # Format allowed VLANs as comma-separated string
            allowed_vlans = ','.join(map(str, uplink.get('allowed_vlans', []))) if uplink.get('allowed_vlans') else ''

            native_vlan = str(uplink.get('native_vlan', '')) if uplink.get('native_vlan') else ''
            root_guard = 'true'  # Default to enabled
            load_interval = str(uplink.get('load_interval', '')) if uplink.get('load_interval') else ''

            # Format member interfaces for port-channels: interface1:lacp_mode:description;interface2:lacp_mode:description
            member_interfaces_str = ''
            if uplink.get('member_interfaces'):
                member_strs = []
                for member in uplink['member_interfaces']:
                    member_name = member.get('name', '')
                    lacp_mode = member.get('lacp_mode', 'active')
                    member_desc = member.get('description', 'PORT-CHANNEL MEMBER')
                    member_strs.append(f"{member_name}:{lacp_mode}:{member_desc}")
                member_interfaces_str = ';'.join(member_strs)

            # Format as pipe-delimited string: type|name|description|port_channel_id|allowed_vlans|native_vlan|root_guard|load_interval|member_interfaces
            uplink_string = f"{uplink_type}|{uplink_name}|{description}|{port_channel_id}|{allowed_vlans}|{native_vlan}|{root_guard}|{load_interval}|{member_interfaces_str}"

            uplink_strings.append(uplink_string)

        # Join all uplink strings with commas for better YAML readability
        if uplink_strings:
            uplinks_multiline = ',\n'.join(uplink_strings)
            uplinks_formatted = QuotedString(uplinks_multiline)
        else:
            uplinks_formatted = QuotedString('')

        return [
            {'name': 'uplinks', 'value': uplinks_formatted}
        ]

    def _generate_snmp_variables(self, snmp_config: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate SNMP template variables based on template requirements"""
        variables = []

        # Required variables without template defaults - 3850 config first, then need_input
        variables.append({'name': 'snmp_community_ro', 'value': snmp_config.get('community_ro', 'need_input')})
        variables.append({'name': 'snmp_community_rw', 'value': snmp_config.get('community_rw', 'need_input')})
        variables.append({'name': 'snmp_location', 'value': snmp_config.get('location', 'need_input')})
        variables.append({'name': 'snmp_contact', 'value': snmp_config.get('contact', 'need_input')})

        # Optional variables - only include if found in 3850 config
        if snmp_config.get('chassis_id'):
            variables.append({'name': 'chassis_id', 'value': snmp_config['chassis_id']})

        if snmp_config.get('acl_ro'):
            variables.append({'name': 'snmp_acl_ro', 'value': snmp_config['acl_ro']})

        if snmp_config.get('acl_rw'):
            variables.append({'name': 'snmp_acl_rw', 'value': snmp_config['acl_rw']})

        # Variable with template default - use template default if not found in 3850
        enable_traps = snmp_config.get('enable_traps')
        if enable_traps is not None:
            variables.append({'name': 'enable_traps', 'value': str(enable_traps).lower()})
        else:
            # Template has | default(true), so use template default
            variables.append({'name': 'enable_traps', 'value': str(self.TEMPLATE_DEFAULTS['snmp']['enable_traps']).lower()})

        return variables

    def _generate_aaa_variables(self, aaa_config: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate AAA template variables based on template requirements"""
        variables = []

        # Required variable without template default - use 3850 config first, then need_input
        tacacs_group_name = aaa_config.get('tacacs_group_name', 'need_input')
        variables.append({'name': 'tacacs_group_name', 'value': tacacs_group_name})

        # Required variable - TACACS servers (formatted for pipe delimiter template)
        tacacs_servers = aaa_config.get('tacacs_servers', [])
        if tacacs_servers:
            # Format as "name|ip|key,name2|ip2|key2" for CC-compatible template
            server_strings = []
            for server in tacacs_servers:
                server_string = f"{server['name']}|{server['ip']}|{server['key']}"
                server_strings.append(server_string)
            tacacs_servers_formatted = QuotedString(','.join(server_strings))
            variables.append({'name': 'tacacs_servers', 'value': tacacs_servers_formatted})
        else:
            variables.append({'name': 'tacacs_servers', 'value': 'need_input'})

        # Variable with template default - use template default if not found in 3850
        tacacs_timeout = aaa_config.get('tacacs_timeout')
        if tacacs_timeout is not None:
            variables.append({'name': 'tacacs_timeout', 'value': str(tacacs_timeout)})
        # If not found, template will use | default(3), so no need to add variable

        return variables

    def _generate_access_port_variables(self, access_interfaces: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate access port template variables using pipe delimiter format"""

        # Group interfaces by switch for organized output
        interfaces_by_switch = {}
        for intf in access_interfaces:
            switch_num = intf['switch']
            if switch_num not in interfaces_by_switch:
                interfaces_by_switch[switch_num] = []

            # Extract interface configuration values
            name = intf['name']
            description = intf['config'].get('description', 'Access Port')
            access_vlan = str(intf['config'].get('access_vlan', '1'))
            voice_vlan = str(intf['config'].get('voice_vlan', '')) if intf['config'].get('voice_vlan') else ''
            port_security = 'true' if intf['config'].get('port_security') else 'false'
            security_max = str(intf['config'].get('port_security_max', '2'))
            security_violation = intf['config'].get('port_security_violation', 'restrict')
            portfast = 'false' if intf['config'].get('shutdown') else 'true'  # Inverted logic
            bpduguard = 'true'  # Default enabled for access ports
            disable_logging = 'true'  # Default enabled for access ports
            nac_enable = 'true' if intf['config'].get('nac_enable') or intf['config'].get('mab') or intf['config'].get('dot1x') else 'false'

            # Format as pipe-delimited string: name|description|access_vlan|voice_vlan|port_security|max|violation|portfast|bpduguard|disable_logging|nac_enable
            interface_string = f"{name}|{description}|{access_vlan}|{voice_vlan}|{port_security}|{security_max}|{security_violation}|{portfast}|{bpduguard}|{disable_logging}|{nac_enable}"

            interfaces_by_switch[switch_num].append({
                'interface_string': interface_string,
                'name': name  # For sorting
            })

        # Create flat list of all access interfaces (sorted by switch, module, port)
        all_interface_strings = []
        for switch_num in sorted(interfaces_by_switch.keys()):
            # Sort interfaces within each switch by module/port
            switch_interfaces = sorted(
                interfaces_by_switch[switch_num],
                key=lambda x: (int(x['name'].split('/')[1]), int(x['name'].split('/')[2]))
            )
            all_interface_strings.extend([intf['interface_string'] for intf in switch_interfaces])

        logger.debug(f"Generated {len(all_interface_strings)} access port configurations")

        # Join all interface strings with commas, but format for better YAML readability
        if all_interface_strings:
            # Create multi-line string with each interface on its own line
            interfaces_multiline = ',\n'.join(all_interface_strings)
            interfaces_formatted = QuotedString(interfaces_multiline)
        else:
            interfaces_formatted = QuotedString('')

        return [
            {'name': 'access_interfaces', 'value': interfaces_formatted}
        ]

def generate_devices_nac_yaml(device_config: Dict[str, Any]) -> Dict[str, Any]:
    """Generate complete devices.nac.yaml structure"""

    return {
        'catalyst_center': {
            'inventory': {
                'devices': [device_config]
            }
        }
    }

def retrieve_config_from_device(device_ip: str, username: str, password: str,
                                enable_password: Optional[str] = None,
                                port: int = 22) -> Tuple[str, str]:
    """SSH to a 3850 device and retrieve running configuration

    Args:
        device_ip: IP address of the device
        username: SSH username
        password: SSH password
        enable_password: Optional enable password
        port: SSH port (default 22)

    Returns:
        Tuple of (hostname, config_text)

    Raises:
        Exception: On connection or authentication failures
    """
    logger.info(f"Attempting SSH connection to {device_ip}:{port}")

    device_params = {
        'device_type': 'cisco_ios',
        'host': device_ip,
        'username': username,
        'password': password,
        'port': port,
        'timeout': 30,
        'session_timeout': 60,
        'banner_timeout': 20,
    }

    if enable_password:
        device_params['secret'] = enable_password

    if not NETMIKO_AVAILABLE or ConnectHandler is None:
        raise ImportError("netmiko is not installed. Please install it with 'pip install netmiko' to use this feature.")

    connection = None
    try:
        # Establish SSH connection
        connection = ConnectHandler(**device_params)
        logger.info("Successfully connected to device")

        # Enter enable mode if enable password provided
        if enable_password:
            connection.enable()
            logger.debug("Entered enable mode")

        # Get the hostname from the prompt
        prompt = connection.find_prompt()
        hostname = prompt.replace('#', '').replace('>', '').strip()
        logger.info(f"Detected hostname: {hostname}")

        # Retrieve running configuration
        logger.info("Retrieving running configuration (this may take a moment)...")
        config_text = str(connection.send_command('show running-config', read_timeout=90))

        if not config_text or len(config_text) < 100:
            raise Exception("Retrieved configuration appears to be empty or too short")

        logger.info(f"Successfully retrieved {len(config_text)} bytes of configuration")

        return hostname, config_text

    except Exception as e:
        error_msg = str(e)
        if "Authentication" in error_msg or "Login failed" in error_msg:
            logger.error("Authentication failed - check username/password")
        elif "timed out" in error_msg.lower():
            logger.error(f"Connection timeout - device {device_ip} may be unreachable")
        elif "Connection refused" in error_msg:
            logger.error(f"Connection refused - SSH may not be enabled on {device_ip}")
        else:
            logger.error(f"Failed to retrieve configuration: {error_msg}")
        raise

    finally:
        if connection:
            try:
                connection.disconnect()
                logger.debug("SSH connection closed")
            except:
                pass

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Migrate Cisco 3850 configurations to 9300 NAC Tool format')
    parser.add_argument('--config', help='Single 3850 configuration file')
    parser.add_argument('--input-dir', help='Directory containing multiple 3850 configuration files')
    parser.add_argument('--output-dir', help='Output directory for generated device configurations')
    parser.add_argument('--device-ip', help='IP address of live 3850 device to retrieve config from')
    parser.add_argument('--username', help='SSH username for device login')
    parser.add_argument('--password', help='SSH password for device login (will prompt if not provided)')
    parser.add_argument('--enable-password', help='Enable password if required (will prompt if needed)')
    parser.add_argument('--ssh-port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate arguments
    if not args.config and not args.input_dir and not args.device_ip:
        logger.error("Either --config, --input-dir, or --device-ip must be specified")
        return 1

    if not args.output_dir:
        logger.error("--output-dir must be specified")
        return 1

    # Check for conflicting options
    mode_count = sum([bool(args.config), bool(args.input_dir), bool(args.device_ip)])
    if mode_count > 1:
        logger.error("Only one of --config, --input-dir, or --device-ip can be specified")
        return 1

    # Validate netmiko availability for live device mode
    if args.device_ip and not NETMIKO_AVAILABLE:
        logger.error("netmiko library is required for live device retrieval. Install with: pip install netmiko")
        return 1

    try:
        # Create output directory
        output_path = Path(args.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        if args.device_ip:
            # Live device mode - get credentials
            username = args.username or input("Username: ")
            password = args.password or getpass("Password: ")

            # Optionally prompt for enable password
            enable_password = args.enable_password
            if not enable_password:
                enable_input = getpass("Enable Password (press Enter to skip): ")
                enable_password = enable_input if enable_input else None

            # Retrieve config from live device
            logger.info(f"Connecting to device {args.device_ip}...")
            hostname, config_text = retrieve_config_from_device(
                args.device_ip, username, password, enable_password, args.ssh_port
            )

            # Process the retrieved config
            process_config_text(config_text, hostname, args.output_dir)

        elif args.config:
            # Process single configuration
            process_single_config(args.config, args.output_dir)
        else:
            # Process directory of configurations
            process_config_directory(args.input_dir, args.output_dir)

        logger.info("Migration completed successfully")
        return 0

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return 1

def process_config_text(config_text: str, hostname: str, output_dir: str):
    """Process configuration text (from file or live device)"""
    # Parse 3850 configuration
    parser = Catalyst3850Parser(config_text)

    # Use provided hostname or extract from config
    if not hostname:
        hostname = parser.extract_hostname() or 'unknown-device'

    # Generate device configuration
    generator = DeviceConfigGenerator(parser)
    device_config = generator.generate_device_config()

    # Generate devices.nac.yaml structure
    devices_yaml = generate_devices_nac_yaml(device_config)

    # Generate output filename based on hostname
    output_path = Path(output_dir)
    output_file = output_path / f"{hostname}.yaml"

    # Write output
    with open(output_file, 'w') as f:
        yaml.dump(devices_yaml, f, default_flow_style=False, sort_keys=False, indent=2, allow_unicode=True)

    logger.info(f"Generated {output_file}")

def process_single_config(config_file: str, output_dir: str):
    """Process a single configuration file"""
    logger.info(f"Processing {config_file}")

    with open(config_file, 'r') as f:
        config_text = f.read()

    # Parse to get hostname
    parser = Catalyst3850Parser(config_text)
    hostname = parser.extract_hostname() or 'unknown-device'

    # Process the config
    process_config_text(config_text, hostname, output_dir)

def process_config_directory(input_dir: str, output_dir: str):
    """Process directory of configuration files"""
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    # Find all .txt and .cfg files
    config_files = list(input_path.glob('*.txt')) + list(input_path.glob('*.cfg'))

    if not config_files:
        logger.warning(f"No configuration files found in {input_dir}")
        return

    logger.info(f"Found {len(config_files)} configuration files")

    for config_file in config_files:
        try:
            process_single_config(str(config_file), output_dir)

        except Exception as e:
            logger.error(f"Failed to process {config_file}: {e}")

if __name__ == '__main__':
    sys.exit(main())
