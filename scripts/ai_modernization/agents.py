import os
import sys
import json
import logging
import importlib.util
import threading
import time
import re
from typing import Dict, Any, List, Optional
from datetime import datetime

# LangChain / LangGraph
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langgraph.graph import StateGraph, END
from dotenv import load_dotenv
import yaml
import yamale

# Local imports
try:
    from models import AgentState, ValidationResult, ValidationIssue
except ImportError:
    # If run as script
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from models import AgentState, ValidationResult, ValidationIssue

# --- Custom YAML Representer for Block Style ---
class ForceBlockStyle(str):
    """String subclass that forces Block Style (|) in PyYAML dumps."""
    pass

def block_style_representer(dumper, data):
    # Use block style '|' for clean multiline output
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

# Global Registration (SafeDumper + Standard Dumper)
yaml.add_representer(ForceBlockStyle, block_style_representer, Dumper=yaml.SafeDumper)
yaml.add_representer(ForceBlockStyle, block_style_representer, Dumper=yaml.Dumper)
# -----------------------------------------------

load_dotenv()

# Setup Logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Configuration & Setup ---

# LLM Setup
# When OPENAI_BASE_URL points to cxai-playground.cisco.com the corporate proxy
# (HTTPS_PROXY) intercepts the request and causes a timeout, even though
# *.cisco.com is listed in no_proxy.  Python's httpx does not support the
# *.cisco.com glob pattern; we clear the proxy vars so httpx uses the direct
# route that is available on Cisco internal hosts.
if os.getenv("OPENAI_BASE_URL", "").endswith("cisco.com"):
    for _pv in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        os.environ.pop(_pv, None)

try:
    _llm_kwargs: dict = {
        "model": os.getenv("OPENAI_MODEL", "gpt-4"),
        "temperature": float(os.getenv("LLM_TEMPERATURE", 0.1)),
    }
    _base_url = os.getenv("OPENAI_BASE_URL", "")
    if _base_url:
        _llm_kwargs["base_url"] = _base_url
    llm = ChatOpenAI(**_llm_kwargs)
except Exception as e:
    logger.error(f"Failed to init LLM: {e}")
    llm = None

# RAG Setup (lazy — initialized on first use to speed up startup)
current_dir = os.path.dirname(os.path.abspath(__file__))
rag_db_path = os.path.join(current_dir, "chroma_db")

retriever = None
RAG_AVAILABLE = False
_rag_initialized = False

def _get_retriever():
    """Lazy-initialize RAG retriever on first use."""
    global retriever, RAG_AVAILABLE, _rag_initialized
    if _rag_initialized:
        return retriever
    _rag_initialized = True
    try:
        from rag_setup import RAGSetup
        RAG_AVAILABLE = True
        rag_manager = RAGSetup(persist_directory=rag_db_path)
        retriever = rag_manager.get_retriever()
    except Exception as e:
        logger.warning(f"RAG initialization failed: {e}")
        RAG_AVAILABLE = False
    return retriever

# --- Helper Functions ---

def run_legacy_parser_logic(config_text: str) -> Dict[str, Any]:
    """Wraps the legacy python script logic."""
    try:
        # agents.py and 3850_parser.py are both in nac-transform/scripts/ai_modernization/
        script_path = os.path.join(current_dir, "3850_parser.py")
        script_path = os.path.abspath(script_path)

        if not os.path.exists(script_path):
            logger.error(f"Legacy script not found at {script_path}")
            return {}

        spec = importlib.util.spec_from_file_location("migrate_module", script_path)
        if not spec or not spec.loader:
            return {}

        module = importlib.util.module_from_spec(spec)
        sys.modules["migrate_module"] = module
        spec.loader.exec_module(module)

        parser = module.Catalyst3850Parser(config_text)

        # Extract Intermediate Model (Raw Parsed Data)
        # This aligns with what AdapterParser expects
        result = {
            "hostname": parser.extract_hostname(),
            "domain_name": parser.extract_domain_name(),
            "stack_info": parser.analyze_stack_config(),
            "pnp_config": parser.determine_pnp_vlan(),
            "vlans": parser.extract_all_vlans(),
            "acls": parser.extract_acls(),
            "uplinks": parser.determine_uplink_interfaces(),
            "snmp_config": parser.extract_snmp_config(),
            "aaa_config": parser.extract_aaa_config(),
            "access_interfaces": parser.extract_access_interfaces(),
            "ntp_servers": parser.extract_ntp_servers(),
            "ntp_auth_keys": parser.extract_ntp_auth_keys(),
            "dns_servers": parser.extract_dns_servers(),
            "logging_hosts": parser.extract_logging_hosts(),
            "timezone_config": parser.extract_timezone_config(),
            "daylight_savings": parser.extract_daylight_savings(),
            "enable_secret": parser.extract_enable_secret(),
            "stp_mode": parser.extract_spanning_tree_mode(),
            "errdisable_config": parser.extract_errdisable_config(),
            "local_users": parser.extract_local_users(),
            "vrf_config": parser.extract_vrf_config(),
            "vtp_domain": parser.extract_vtp_domain(),
            "vtp_mode": parser.extract_vtp_mode(),
            "has_ssh_source": parser.has_ssh_source_interface(),
            "has_snmp_source": parser.has_snmp_source_interface(),
            "has_ntp_source": parser.has_ntp_source_interface(),
            "has_tacacs_source": parser.has_tacacs_source_interface(),
            "has_radius_source": parser.has_radius_source_interface()
        }

        # Sanitize custom types
        def sanitize(obj):
            if hasattr(obj, '__class__') and obj.__class__.__name__ == 'QuotedString':
                return str(obj)
            if isinstance(obj, dict):
                return {k: sanitize(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [sanitize(i) for i in obj]
            return obj

        sanitized = sanitize(result)
        if isinstance(sanitized, dict):
            return sanitized
        return {}
    except Exception as e:
        logger.error(f"Legacy parser error: {e}")
        return {}

def append_trace(state: AgentState, step: str, status: str, details: str = ""):
    entry = {
        "step": step,
        "status": status,
        "details": details,
        "timestamp": datetime.now().isoformat()
    }
    # Initialize trace_log if not present (though it's in the TypedDict)
    log = state.get("trace_log", [])
    log.append(entry)
    # We return the key so LangGraph updates it
    return log

def _find_hostname(data: Dict[str, Any]) -> Optional[str]:
    """Extract hostname from a data dict, checking root and common nested paths."""
    if data.get("hostname"):
        return data["hostname"]
    if isinstance(data.get("system"), dict) and data["system"].get("hostname"):
        return data["system"]["hostname"]
    # LLM sometimes nests everything under a 'device' key
    if isinstance(data.get("device"), dict):
        dev = data["device"]
        if dev.get("hostname"):
            return dev["hostname"]
        if isinstance(dev.get("system"), dict) and dev["system"].get("hostname"):
            return dev["system"]["hostname"]
    return None


def _parse_ip_mask(ip_str):
    """Parse 'x.x.x.x/prefix' or 'x.x.x.x mask' into (address, netmask). Returns ('','') on failure."""
    if not ip_str or not isinstance(ip_str, str):
        return "", ""
    if "/" in ip_str:
        parts = ip_str.split("/")
        addr = parts[0]
        try:
            prefix = int(parts[1])
            mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            mask = f"{(mask_int >> 24) & 0xFF}.{(mask_int >> 16) & 0xFF}.{(mask_int >> 8) & 0xFF}.{mask_int & 0xFF}"
        except (ValueError, IndexError):
            mask = "255.255.255.0"
        return addr, mask
    if " " in ip_str:
        parts = ip_str.split()
        return parts[0], parts[1] if len(parts) > 1 else "255.255.255.0"
    return ip_str, "255.255.255.0"


def get_output_dir(state: AgentState) -> str:
    """Determine the device-specific output directory."""
    hostname = "unknown_device"

    # Check all state sources for hostname (including nested system.hostname)
    for key in ("legacy_parsed_data", "normalized_intent", "extracted_intent"):
        src = state.get(key)
        if src and isinstance(src, dict):
            found = _find_hostname(src)
            if found:
                hostname = found.lower()
                break

    base_output = os.path.join(current_dir, "..", "..", "output")
    device_output = os.path.join(base_output, hostname)
    os.makedirs(device_output, exist_ok=True)
    return device_output

def save_agent_output(state: AgentState, agent_name: str, data: Any, format: str = "json"):
    """Helper to save agent output to device specific folder."""
    try:
        output_dir = get_output_dir(state)
        filename = f"{agent_name}.{format}"
        file_path = os.path.join(output_dir, filename)

        with open(file_path, "w") as f:
            if format == "json":
                json.dump(data, f, indent=2, default=str)
            elif format == "yaml":
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            else:
                f.write(str(data))

        logger.info(f"Saved {agent_name} output to {file_path}")
    except Exception as e:
        logger.warning(f"Failed to save output for {agent_name}: {e}")

# --- Config Pre-Processor (reduces token count for LLM) ---

# Top-level section headers that can be safely stripped for NAC template generation.
# These are routing/overlay/telemetry features that the Catalyst Center templates don't consume.
_STRIP_SECTIONS_TOPLEVEL = re.compile(
    r'^(?:'
    r'router bgp|router ospf|router eigrp|router isis|router rip|router bfd|'
    r'route-map |ip prefix-list |ip community-list |ip as-path |'
    r'ip extcommunity-list |'
    r'router multicast|router igmp|router pim|'
    r'mpls |'
    r'daemon |'
    r'event-handler |'
    r'monitor |queue-monitor |'
    r'sflow |'
    r'patch panel |'
    r'dhcp server |'
    r'mac address-table |'
    r'mac security |'
    r'hardware |platform |'
    r'transceiver |'
    r'policy-map |class-map |'
    r'ip access-list.*?counter|'
    r'management cvx|management console|management telnet|'
    r'match-list |'
    r'peer-filter |'
    r'router-id |'
    r'service routing protocols|'
    r'load-interval |'
    r'switchport default |'
    r'vlan internal order|'
    r'banner |'
    r'system l1|'
    r'cdp'
    r')', re.IGNORECASE
)

# Simple one-liner commands to strip (not section starters)
_STRIP_LINES = re.compile(
    r'^(?:'
    r'!.*|'                 # comment lines
    r'boot system |'
    r'alias |'
    r'no schedule |'
    r'no ip icmp |'
    r'no ip http |'         # we detect http from management api section
    r'snmp-server enable traps |'
    r'no snmp-server enable traps |'
    r'no snmp-server vrf |'
    r'snmp-server user |'     # SNMPv3 user hashes are long and extracted separately
    r'snmp-server engineID |'
    r'snmp-server view |'
    r'snmp-server group |'
    r'service unsupported|'
    r'logging event |'
    r'logging format |'
    r'logging synchronous |'
    r'no logging monitor|'
    r'storm-control |'
    r'no logging event |'
    r'end$'
    r')', re.IGNORECASE
)


def _preprocess_config(raw_config: str) -> str:
    """Strip sections irrelevant to NAC Catalyst Center template generation.

    Removes routing protocols (BGP, OSPF), route-maps, prefix-lists,
    DHCP, sflow, daemon configs, policy-maps, hardware specifics, etc.
    Keeps: hostname, VLANs, VRFs, interfaces, ACLs, SNMP, AAA/TACACS,
    NTP, DNS, logging, spanning-tree, management, banners, users.
    """
    lines = raw_config.splitlines()
    out: list[str] = []
    skip_depth = False      # True while inside a block to strip

    for line in lines:
        stripped = line.rstrip()

        # If we're inside a section being skipped, wait for un-indented line to end block
        if skip_depth:
            # Arista/IOS section blocks end at the next un-indented non-empty line or '!'
            if stripped == '!' or stripped == '':
                skip_depth = False
                # Don't emit the closing '!' of a stripped block
                continue
            # Still indented → inside the stripped block
            if stripped.startswith(' ') or stripped.startswith('\t'):
                continue
            # New top-level command → block ended, stop skipping and fall through
            skip_depth = False

        # Check if this line starts a section to strip
        if _STRIP_SECTIONS_TOPLEVEL.match(stripped):
            skip_depth = True
            continue

        # Check if this is a simple line to strip
        if _STRIP_LINES.match(stripped):
            continue

        out.append(stripped)

    # ---- Interface deduplication ----
    # Group identical interface bodies; emit one representative + summary of others.
    # This is the biggest win for configs with 50-200 similar access ports.
    intf_re = re.compile(r'^interface\s+\S+')
    deduped: list[str] = []
    i = 0
    # First pass: extract interface blocks
    intf_blocks: list[tuple[str, list[str]]] = []  # (header, body_lines)
    non_intf: list[tuple[int, str]] = []  # (position, line)
    pos = 0
    while i < len(out):
        if intf_re.match(out[i]):
            header = out[i]
            body = []
            i += 1
            while i < len(out) and (out[i].startswith(' ') or out[i].startswith('\t') or out[i] == ''):
                body.append(out[i])
                i += 1
            intf_blocks.append((header, body))
        else:
            non_intf.append((pos, out[i]))
            pos += 1
            i += 1

    if intf_blocks:
        # Group by body content
        from collections import OrderedDict
        body_groups: OrderedDict[str, list[str]] = OrderedDict()
        for header, body in intf_blocks:
            # Normalize body for grouping (strip interface-specific lines like description)
            body_key = '\n'.join(line.strip() for line in body if line.strip())
            body_groups.setdefault(body_key, []).append(header)

        # Re-emit: one full block per unique config + list of interfaces sharing it
        intf_lines: list[str] = []
        for body_key, headers in body_groups.items():
            if len(headers) == 1:
                # Unique interface — emit as-is
                intf_lines.append(headers[0])
                for bl in body_key.split('\n'):
                    if bl:
                        intf_lines.append(f'  {bl}')
            else:
                # Multiple interfaces with same config — emit one + summary
                intf_lines.append(f'!! Identical config for {len(headers)} interfaces: {", ".join(h.replace("interface ", "") for h in headers)}')
                intf_lines.append(headers[0])
                for bl in body_key.split('\n'):
                    if bl:
                        intf_lines.append(f'  {bl}')
        # Re-assemble: non-intf lines first, then deduped interfaces
        deduped = [line for _, line in non_intf] + intf_lines
    else:
        deduped = out

    # Collapse multiple consecutive blank lines
    result: list[str] = []
    prev_blank = False
    for line in deduped:
        if line == '':
            if prev_blank:
                continue
            prev_blank = True
        else:
            prev_blank = False
        result.append(line)

    compressed = '\n'.join(result)
    ratio = len(compressed) / max(len(raw_config), 1) * 100
    logger.info(f"Config pre-processed: {len(lines)} -> {len(result)} lines "
                f"({len(raw_config)} -> {len(compressed)} chars, {ratio:.0f}%)")
    return compressed

# --- Agent Nodes ---

def agent_legacy_parser(state: AgentState):
    """Agent 1: Deterministic Parsing using legacy script."""
    logger.info("--- Agent 1: Legacy Parser ---")
    data = run_legacy_parser_logic(state["raw_config"])

    status = "success" if data else "warning_empty"
    new_trace = append_trace(state, "Legacy Parser", status, f"Extracted {len(data)} keys.")

    # Save output (need to manually update state wrapper for helper to work in first step)
    temp_state = state.copy()
    temp_state["legacy_parsed_data"] = data
    save_agent_output(temp_state, "1_legacy_parser", data, "json")

    return {"legacy_parsed_data": data, "trace_log": new_trace}

def agent_intent_mapper(state: AgentState):
    """Agent 2: Map Legacy Data + Raw Config -> Target Schema (LLM + RAG)."""
    logger.info("--- Agent 2: Intent Mapper ---")
    start_time = datetime.now()

    # 1. Prepare Prompt — pre-process config to reduce token count
    compressed_config = _preprocess_config(state["raw_config"])

    legacy_data = json.dumps(state.get("legacy_parsed_data", {}), indent=2, default=str)
    # Cap legacy data to avoid excessive tokens (the full data is merged back later anyway)
    if len(legacy_data) > 8000:
        legacy_data = json.dumps(state.get("legacy_parsed_data", {}), separators=(',', ':'), default=str)
        if len(legacy_data) > 12000:
            legacy_data = legacy_data[:12000] + '..."TRUNCATED"}'
    target_device = state.get("target_device_type", "Cisco Catalyst 9300")

    feedback = ""
    val_res = state.get("validation_result")
    if val_res and val_res.get("issues"):
         feedback = f"Previous validation failed. Fix these issues: {json.dumps(val_res['issues'])}"

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a Network Automation Architect. Map device config to structured Intent JSON for Cisco Catalyst Center (NAC) migration.

Inputs: Device Config (Cisco IOS or Arista EOS), Legacy Parser JSON (may be empty for Arista), Target Device: {target_device}

Extract ALL of these into JSON:
- hostname, domain_name, system (timezone, spanning-tree, errdisable, local_users, banners)
- management (OOB/inband interfaces, VRF, HTTP/HTTPS, SSH config)
- vlans (ALL with id+name), vrfs (ALL with name+description)
- interfaces (ALL: access, trunk, routed, sub-interfaces, SVIs, loopbacks, port-channels). Note: if there is a comment like "Identical config for N interfaces: Eth1,Eth2,...", create an entry for EACH listed interface with that config.
- routes (static), snmp (communities, location, contact, traps, ACLs)
- acls (ALL entries: sequence, action, source, wildcard, log — do NOT truncate)
- aaa (tacacs servers, groups, auth/authz/acct), logging (hosts, vrf, buffered)
- ntp (servers, vrf, prefer, auth keys), dns_servers, stack info

Interface naming: Map to target ({target_device}). Arista Ethernet1->GigabitEthernet1/0/1. Extract ALL interfaces, do not truncate.

IMPORTANT: Be concise. Use compact JSON. No extra whitespace. Omit null/empty fields. Keep metadata to max 5 entries (highest ambiguity only).

{feedback}

Return JSON: {{"intent": {{...}}, "metadata": [{{field, confidence, reason}}]}}
"""),
        ("human", "Device Config:\n{raw_config}\n\nLegacy Parser Output:\n{legacy_data}")])

    # 3. Call LLM
    result_intent = {}
    result_metadata = []

    if llm:
        try:
            # Start timer thread for progress updates
            stop_event = threading.Event()
            def log_progress():
                seconds = 0
                while not stop_event.wait(5):
                    seconds += 5
                    logger.info(f"LLM processing... ({seconds}s elapsed)")

            t = threading.Thread(target=log_progress, daemon=True)
            t.start()

            logger.info("Calling LLM for Intent Mapping...")
            try:
                chain = prompt | llm | JsonOutputParser()
                response = chain.invoke({
                    "feedback": feedback,
                    "target_device": target_device,
                    "raw_config": compressed_config,
                    "legacy_data": legacy_data
                })
            finally:
                stop_event.set()
                t.join(timeout=1)
            duration = (datetime.now() - start_time).seconds
            logger.info(f"LLM Response received in {duration}s.")

            # Handle both old (direct dict) and new (wrapper) formats
            if "intent" in response and "metadata" in response:
                result_intent = response["intent"]
                result_metadata = response["metadata"]
            else:
                # Fallback if LLM ignores instruction and returns just intent
                result_intent = response
                result_metadata = [{"field": "global", "confidence": 0.5, "reason": "Legacy format (no metadata returned)"}]

        except Exception as e:
            logger.error(f"Mapping failed: {e}")
            result_intent = state.get("legacy_parsed_data", {}) # Fallback
            result_metadata = [{"field": "global", "confidence": 0.0, "reason": f"Error: {str(e)}"}]
            append_trace(state, "Intent Mapper", "error", str(e))
    else:
        logger.warning("LLM not initialized, using legacy parser output directly.")
        result_intent = state.get("legacy_parsed_data", {})
        result_metadata = [{"field": "global", "confidence": 1.0, "reason": "Deterministic Parser (No LLM)"}]

    # --- Merge Logic: Ensure critical arrays from legacy parser are preserved if missing ---
    legacy_data = state.get("legacy_parsed_data", {})
    critical_arrays = [
        "access_interfaces", "uplinks", "vlans", "acls",
        "aaa_config", "snmp_config", "local_users", "logging_hosts",
        "ntp_servers", "ntp_auth_keys", "dns_servers", "vrf_config"
    ]

    for key in critical_arrays:
        if key in legacy_data and (key not in result_intent or not result_intent[key]):
            logger.info(f"Merging missing/empty key '{key}' from legacy parser")
            result_intent[key] = legacy_data[key]

    # Also merge simple scalar defaults if missing or placeholder
    for scalar in ["hostname", "domain_name"]:
        legacy_val = legacy_data.get(scalar)
        current_val = result_intent.get(scalar)

        # Overwrite if legacy has value AND (current is missing OR current is placeholder)
        if legacy_val and (not current_val or current_val == "need_input"):
            result_intent[scalar] = legacy_val

    # --- Filter out AutoQos ACLs (auto-generated, not relevant for migration) ---
    if isinstance(result_intent.get("acls"), list):
        before = len(result_intent["acls"])
        result_intent["acls"] = [
            acl for acl in result_intent["acls"]
            if not (isinstance(acl, dict) and "autoqos" in str(acl.get("name", "")).lower())
        ]
        filtered = before - len(result_intent["acls"])
        if filtered:
            logger.info(f"Filtered out {filtered} AutoQos ACLs")

    new_trace = append_trace(state, "Intent Mapper", "success", "Mapped intent with LLM (Merged legacy arrays).")

    # Save Output
    temp_state = state.copy()
    temp_state["extracted_intent"] = result_intent
    save_agent_output(temp_state, "2_intent_mapper", result_intent, "json")
    save_agent_output(temp_state, "2_intent_metadata", result_metadata, "json")

    return {
        "extracted_intent": result_intent,
        "decision_metadata": result_metadata,
        "rag_context": "",
        "iteration_count": state.get("iteration_count", 0) + 1,
        "trace_log": new_trace
    }

import re

def normalize_interface_name(name: str, target_type: str) -> str:
    """Standardize interface names for target device type."""
    normalized = name.strip()

    # 3850/9300 Canonicalization
    # Expand short names to full names
    if re.match(r'^Gi\d', normalized):
        normalized = normalized.replace("Gi", "GigabitEthernet", 1)
    elif re.match(r'^Te\d', normalized):
        normalized = normalized.replace("Te", "TenGigabitEthernet", 1)
    elif re.match(r'^Fa\d', normalized):
        normalized = normalized.replace("Fa", "FastEthernet", 1)
    elif re.match(r'^Twe\d', normalized):
        normalized = normalized.replace("Twe", "TwentyFiveGigE", 1)

    # Upgrade Logic for specific target types
    # e.g. Catalyst 9300 is all Gigabit (or MultiGig)
    if "9300" in target_type:
        # Upgrade FastEthernet to GigabitEthernet if moving to 9300
        if normalized.startswith("FastEthernet"):
            normalized = normalized.replace("FastEthernet", "GigabitEthernet", 1)

    return normalized

def agent_schema_normalizer(state: AgentState):
    """Agent 3: Normalize data types and structure."""
    logger.info("--- Agent 3: Schema Normalizer ---")
    intent = state.get("extracted_intent", {})
    target_device = state.get("target_device_type", "Cisco Catalyst 9300")

    # Basic normalization logic
    normalized = intent.copy()

    # Unwrap if LLM wrapped everything under a single 'device' key
    if list(normalized.keys()) == ["device"] and isinstance(normalized.get("device"), dict):
        logger.info("Unwrapping top-level 'device' envelope from LLM output")
        normalized = normalized["device"]

    # Promote hostname to root if not already present (check device.hostname, system.hostname)
    if "hostname" not in normalized:
        hostname_found = _find_hostname(normalized)
        if hostname_found:
            normalized["hostname"] = hostname_found

    # Preserve original hostname case (output dir uses lowercase separately)

    # ===================================================================
    #  Promote nested LLM fields to a CONSISTENT root-level schema.
    #  The generator expects these root keys regardless of vendor:
    #    domain_name, timezone_config, stp_mode, dns_servers, ntp_servers,
    #    logging_hosts, snmp_config, aaa_config, local_users, vrf_config,
    #    uplinks, acls, access_interfaces, routed_interfaces
    # ===================================================================
    system = normalized.get("system", {}) if isinstance(normalized.get("system"), dict) else {}
    mgmt = normalized.get("management", {}) if isinstance(normalized.get("management"), dict) else {}
    # Fallback: check device.management and device.system when data is nested under 'device'
    device_block = normalized.get("device", {}) if isinstance(normalized.get("device"), dict) else {}
    if not system and isinstance(device_block.get("system"), dict):
        system = device_block["system"]
    if not mgmt and isinstance(device_block.get("management"), dict):
        mgmt = device_block["management"]

    # --- domain_name ---
    if "domain_name" not in normalized:
        normalized["domain_name"] = (
            system.get("domain_name")
            or (system.get("dns", {}) or {}).get("domain")
            or (mgmt.get("dns", {}) or {}).get("domain")
            or normalized.get("dns_domain")
            or "need_input"
        )

    # --- timezone_config --- (handle string, dict, or nested shapes)
    if "timezone_config" not in normalized:
        tz_raw = system.get("timezone", {})
        # Also check device.platform.clock or root-level clock_timezone
        if not tz_raw:
            tz_raw = normalized.get("clock_timezone") or normalized.get("timezone") or {}
        if isinstance(tz_raw, str):
            normalized["timezone_config"] = {"timezone": tz_raw, "timezone_offset": None, "dst_minutes": None}
        elif isinstance(tz_raw, dict):
            dst = tz_raw.get("summer_time") or tz_raw.get("dst") or {}
            normalized["timezone_config"] = {
                "timezone": tz_raw.get("name", "need_input"),
                "timezone_offset": tz_raw.get("utc_offset_hours"),
                "dst_minutes": None,
            }
            if isinstance(dst, dict) and dst.get("name"):
                normalized.setdefault("daylight_savings", dst["name"])

    # --- stp_mode --- (handle both "spanning_tree" and "stp" keys)
    if "stp_mode" not in normalized:
        stp_obj = system.get("spanning_tree") or system.get("stp") or {}
        if isinstance(stp_obj, dict) and stp_obj.get("mode"):
            normalized["stp_mode"] = stp_obj["mode"]
        # Also check layer2.spanning_tree
        l2 = normalized.get("layer2", {}) or {}
        if not normalized.get("stp_mode") and isinstance(l2.get("spanning_tree"), dict):
            normalized["stp_mode"] = l2["spanning_tree"].get("mode", "rapid-pvst")

    # --- dns_servers --- (handle system.name_servers list-of-vrf-objects, system.dns.name_servers, flat list,
    #                        device.management.dns.name_servers [{vrf, ip}], root dns_servers list)
    if "dns_servers" not in normalized:
        all_dns = []
        # Shape 1: system.name_servers = [{vrf, servers: [ip]}]
        name_servers = system.get("name_servers", [])
        if isinstance(name_servers, list):
            for ns_entry in name_servers:
                if isinstance(ns_entry, dict) and "servers" in ns_entry:
                    all_dns.extend(ns_entry["servers"])
                elif isinstance(ns_entry, str):
                    all_dns.append(ns_entry)
        # Shape 2: system.dns.name_servers = {vrf: [ip]} or [ip]
        dns_obj = (system.get("dns", {}) or {}).get("name_servers", {})
        if isinstance(dns_obj, dict):
            for v in dns_obj.values():
                if isinstance(v, list):
                    all_dns.extend(v)
        elif isinstance(dns_obj, list):
            all_dns.extend(dns_obj)
        # Shape 3: services.dns (alternate LLM shape)
        svc_dns = (normalized.get("services", {}) or {}).get("dns", {}) or {}
        if isinstance(svc_dns.get("servers"), list):
            all_dns.extend(svc_dns["servers"])
        # Shape 4: management.dns.name_servers = [{vrf, ip}] (Arista LLM shape)
        mgmt_dns = (mgmt.get("dns", {}) or {}).get("name_servers", [])
        if isinstance(mgmt_dns, list):
            for ns in mgmt_dns:
                if isinstance(ns, dict) and ns.get("ip"):
                    all_dns.append(ns["ip"])
                elif isinstance(ns, str):
                    all_dns.append(ns)
        # Shape 5: management.dns_servers = [{vrf, servers: [ip]}]
        mgmt_dns_servers = mgmt.get("dns_servers", [])
        if isinstance(mgmt_dns_servers, list):
            for ns_entry in mgmt_dns_servers:
                if isinstance(ns_entry, dict) and "servers" in ns_entry:
                    all_dns.extend(ns_entry["servers"])
                elif isinstance(ns_entry, dict) and ns_entry.get("ip"):
                    all_dns.append(ns_entry["ip"])
                elif isinstance(ns_entry, str):
                    all_dns.append(ns_entry)
        if all_dns:
            normalized["dns_servers"] = list(dict.fromkeys(all_dns))  # dedupe, preserve order

    # Post-check: ensure dns_servers items are strings (LLM may return [{ip, vrf}] directly)
    if isinstance(normalized.get("dns_servers"), list):
        clean_dns = []
        for d in normalized["dns_servers"]:
            if isinstance(d, dict):
                clean_dns.append(d.get("ip") or d.get("address") or d.get("server", ""))
            elif isinstance(d, str):
                clean_dns.append(d)
        normalized["dns_servers"] = [x for x in clean_dns if x]

    # --- ntp_servers --- (handle management.ntp.servers, ntp.servers, services.ntp.servers,
    #                       management.ntp.servers [{vrf, ip, prefer}] Arista shape)
    if "ntp_servers" not in normalized:
        ntp_sources = [
            (mgmt.get("ntp", {}) or {}).get("servers", []),
            (normalized.get("ntp", {}) or {}).get("servers", []),
            (normalized.get("services", {}) or {}).get("ntp", {}).get("servers", []) if isinstance((normalized.get("services", {}) or {}).get("ntp"), dict) else [],
        ]
        ntp_out = []
        for srv_list in ntp_sources:
            if not isinstance(srv_list, list):
                continue
            for s in srv_list:
                if isinstance(s, dict):
                    addr = s.get("server") or s.get("address") or s.get("ip", "")
                    entry = addr
                    if s.get("prefer"):
                        entry += "|prefer"
                    if entry:
                        ntp_out.append(entry)
                elif isinstance(s, str):
                    ntp_out.append(s)
        if ntp_out:
            normalized["ntp_servers"] = list(dict.fromkeys(ntp_out))

    # --- logging_hosts --- (handle management.logging.remote, logging.hosts, services.logging.hosts,
    #                         root logging with hosts/servers list)
    if "logging_hosts" not in normalized:
        all_logs = []
        # Shape 1: management.logging.remote = [{host, vrf}]
        remote = (mgmt.get("logging", {}) or {}).get("remote", [])
        if isinstance(remote, list):
            for r in remote:
                if isinstance(r, dict) and r.get("host"):
                    all_logs.append(r["host"])
        # Shape 2: logging.hosts = [ip] or logging.servers = [{host}]
        log_cfg = normalized.get("logging", {}) or {}
        if isinstance(log_cfg, dict):
            if isinstance(log_cfg.get("hosts"), list):
                for h in log_cfg["hosts"]:
                    if isinstance(h, dict):
                        all_logs.append(h.get("address") or h.get("host") or h.get("ip", ""))
                    else:
                        all_logs.append(str(h))
            if isinstance(log_cfg.get("servers"), list):
                for h in log_cfg["servers"]:
                    if isinstance(h, dict):
                        all_logs.append(h.get("host") or h.get("ip") or h.get("address", ""))
                    elif isinstance(h, str):
                        all_logs.append(h)
        # Shape 3: services.logging.hosts
        svc_log = (normalized.get("services", {}) or {}).get("logging", {}) or {}
        if isinstance(svc_log.get("hosts"), list):
            for h in svc_log["hosts"]:
                all_logs.append(str(h))
        # Shape 4: management.logging.hosts (Arista LLM shape)
        mgmt_log_hosts = (mgmt.get("logging", {}) or {}).get("hosts", [])
        if isinstance(mgmt_log_hosts, list):
            for h in mgmt_log_hosts:
                if isinstance(h, dict):
                    all_logs.append(h.get("host") or h.get("ip", ""))
                elif isinstance(h, str):
                    all_logs.append(h)
        if all_logs:
            normalized["logging_hosts"] = list(dict.fromkeys(filter(None, all_logs)))

    # --- snmp_config --- (handle management.snmp, services.snmp, root snmp, or existing snmp_config)
    if "snmp_config" not in normalized:
        snmp_src = (mgmt.get("snmp", {}) or
                    (normalized.get("services", {}) or {}).get("snmp", {}) or
                    normalized.get("snmp", {}) or {})
        if isinstance(snmp_src, dict) and snmp_src:
            normalized["snmp_config"] = {
                "community_ro": snmp_src.get("community_ro", "need_input"),
                "community_rw": snmp_src.get("community_rw", "need_input"),
                "location": snmp_src.get("location", "need_input"),
                "contact": snmp_src.get("contact", "need_input"),
                "chassis_id": snmp_src.get("chassis_id", _find_hostname(normalized) or ""),
                "enable_traps": bool(snmp_src.get("traps_enabled", snmp_src.get("enable_traps", True))),
            }
            if snmp_src.get("acl_ro") or snmp_src.get("access_list"):
                normalized["snmp_config"]["acl_ro"] = snmp_src.get("acl_ro") or snmp_src.get("access_list", "")

    # --- aaa_config --- (handle management.tacacs, nac.tacacs_servers, nac.aaa.tacacs_groups,
    #                      root aaa with tacacs_servers/group)
    if "aaa_config" not in normalized:
        tacacs_servers = []
        tacacs_group_name = "need_input"
        # Shape 1: management.tacacs.servers = [{host, vrf}]
        mgmt_tacacs = mgmt.get("tacacs", {}) or {}
        if isinstance(mgmt_tacacs.get("servers"), list):
            for s in mgmt_tacacs["servers"]:
                if isinstance(s, dict):
                    tacacs_servers.append({
                        "name": s.get("name", s.get("host", "")),
                        "ip": s.get("ip") or s.get("ipv4") or s.get("host", ""),
                        "key": s.get("key", "need_input"),
                    })
        # Shape 2: nac.tacacs_servers
        nac_block = normalized.get("nac", {}) or {}
        if isinstance(nac_block.get("tacacs_servers"), list) and not tacacs_servers:
            for s in nac_block["tacacs_servers"]:
                if isinstance(s, dict):
                    tacacs_servers.append({
                        "name": s.get("name", ""),
                        "ip": s.get("ip") or s.get("ipv4", ""),
                        "key": s.get("key", "need_input"),
                    })
        # Shape 3: nac.aaa.tacacs_groups
        nac_aaa = nac_block.get("aaa", {}) or {}
        if isinstance(nac_aaa.get("tacacs_groups"), list):
            grps = nac_aaa["tacacs_groups"]
            if grps and isinstance(grps[0], dict):
                tacacs_group_name = grps[0].get("group_name", "need_input")
        # Shape 4: root-level aaa with tacacs_servers, aaa.tacacs.servers, or aaa.servers
        root_aaa = normalized.get("aaa", {}) or {}
        if isinstance(root_aaa, dict) and not tacacs_servers:
            # Try aaa.tacacs.servers first (Arista LLM shape)
            tacacs_block = root_aaa.get("tacacs", {}) or {}
            aaa_servers = (tacacs_block.get("servers", []) or
                          root_aaa.get("tacacs_servers", []) or
                          root_aaa.get("servers", []))
            if isinstance(aaa_servers, list):
                for s in aaa_servers:
                    if isinstance(s, dict):
                        tacacs_servers.append({
                            "name": s.get("name", s.get("host", "")),
                            "ip": s.get("ip") or s.get("ipv4") or s.get("host", ""),
                            "key": s.get("key", "need_input"),
                        })
            # Group name from aaa.tacacs.groups or aaa.group_name
            tacacs_groups = tacacs_block.get("groups", []) or root_aaa.get("groups", [])
            if isinstance(tacacs_groups, list) and tacacs_groups:
                if isinstance(tacacs_groups[0], dict):
                    tacacs_group_name = tacacs_groups[0].get("name") or tacacs_groups[0].get("group_name", "need_input")
            if root_aaa.get("group_name") or root_aaa.get("tacacs_group_name"):
                tacacs_group_name = root_aaa.get("group_name") or root_aaa.get("tacacs_group_name", "need_input")
        if tacacs_servers:
            normalized["aaa_config"] = {
                "aaa_enabled": True,
                "tacacs_servers": tacacs_servers,
                "tacacs_group_name": tacacs_group_name,
            }

    # --- local_users ---
    if "local_users" not in normalized:
        users = system.get("local_users", [])
        if isinstance(users, list) and users:
            normalized["local_users"] = users

    # --- vrf_config --- (management VRF for mgmt template)
    if "vrf_config" not in normalized:
        vrf_name = None
        if isinstance(mgmt.get("oob"), dict):
            vrf_name = mgmt["oob"].get("vrf")
        if not vrf_name:
            vrf_name = mgmt.get("vrf")
        # Also check inband management for VRF
        if not vrf_name and isinstance(mgmt.get("inband"), dict):
            vrf_name = mgmt["inband"].get("vrf")
        if vrf_name:
            normalized["vrf_config"] = {"name": vrf_name, "rd": "", "rt_export": "", "rt_import": ""}

    # --- uplinks --- (handle interfaces.port_channels with trunk mode)
    if "uplinks" not in normalized:
        pc_list = []
        intfs = normalized.get("interfaces", {})
        if isinstance(intfs, dict):
            pcs = intfs.get("port_channels", [])
        elif isinstance(intfs, list):
            pcs = [i for i in intfs if isinstance(i, dict) and "port-channel" in (i.get("type", "") or i.get("name", "")).lower()]
        else:
            pcs = []
        for pc in pcs:
            if not isinstance(pc, dict):
                continue
            sw = pc.get("switchport", {}) or {}
            if isinstance(sw, dict) and sw.get("mode") == "trunk":
                allowed = sw.get("allowed_vlans", [])
                if isinstance(allowed, list):
                    allowed_str = ','.join(str(v) for v in allowed)
                else:
                    allowed_str = str(allowed) if allowed else ""
                members = pc.get("members", [])
                member_intfs = []
                for m in members if isinstance(members, list) else []:
                    if isinstance(m, dict):
                        member_intfs.append(m)
                pc_list.append({
                    "type": "port-channel",
                    "port_channel_id": pc.get("name", "").replace("Port-channel", "").replace("port-channel", ""),
                    "description": pc.get("description", "UPSTREAM-TRUNK"),
                    "allowed_vlans": allowed,
                    "native_vlan": sw.get("native_vlan"),
                    "root_guard": pc.get("root_guard", True),
                    "member_interfaces": member_intfs,
                })
        if pc_list:
            normalized["uplinks"] = pc_list

    # --- routed_interfaces --- (handle interfaces.routed_physical with subinterfaces, interfaces.svis,
    #                              AND flat interfaces list with SVIs/routed/sub-interfaces)
    if "routed_interfaces" not in normalized:
        routed = []
        intfs = normalized.get("interfaces", {})
        if isinstance(intfs, dict):
            # routed_physical with potential subinterfaces
            for ri in intfs.get("routed_physical", []):
                if not isinstance(ri, dict):
                    continue
                # Parent interface
                ip_raw = ri.get("ip_address")
                ip_addr, mask = _parse_ip_mask(ip_raw)
                routed.append({
                    "name": ri.get("name", ""),
                    "description": ri.get("description", ""),
                    "vrf": ri.get("vrf") or "",
                    "ipv4": {"address": ip_addr, "netmask": mask} if ip_addr else {},
                    "mtu": ri.get("mtu"),
                    "shutdown": not ri.get("enabled", True),
                    "pim_sparse": ri.get("pim_sparse", False),
                })
                # Subinterfaces
                for sub in ri.get("subinterfaces", []):
                    if not isinstance(sub, dict):
                        continue
                    sub_ip, sub_mask = _parse_ip_mask(sub.get("ip_address"))
                    routed.append({
                        "name": sub.get("name", ""),
                        "description": sub.get("description", ""),
                        "vrf": sub.get("vrf") or "",
                        "ipv4": {"address": sub_ip, "netmask": sub_mask} if sub_ip else {},
                        "mtu": sub.get("mtu"),
                        "shutdown": False,
                        "pim_sparse": sub.get("pim_sparse", False),
                        "dot1q_vlan": sub.get("encapsulation_dot1q_vlan"),
                        "helper_addresses": sub.get("helper_addresses", []),
                    })
            # SVIs as routed interfaces
            for svi in intfs.get("svis", []):
                if not isinstance(svi, dict):
                    continue
                svi_ip, svi_mask = _parse_ip_mask(svi.get("ip_address"))
                if svi_ip:
                    routed.append({
                        "name": svi.get("name", ""),
                        "description": svi.get("description", ""),
                        "vrf": svi.get("vrf") or "",
                        "ipv4": {"address": svi_ip, "netmask": svi_mask},
                        "mtu": svi.get("mtu"),
                        "shutdown": svi.get("shutdown", False),
                    })
        # Handle flat interfaces list (Arista LLM shape): SVIs, routed physical, sub-interfaces
        elif isinstance(intfs, list):
            for intf in intfs:
                if not isinstance(intf, dict):
                    continue
                name = str(intf.get("name", ""))
                # LLM may use ip_address, ipv4, or ip for the IP field
                ip_raw = intf.get("ip_address") or intf.get("ipv4") or intf.get("ip")
                # Identify routed interfaces: SVIs (Vlan*), Loopbacks, sub-interfaces (.), no-switchport physical
                is_svi = name.startswith("Vlan")
                is_loopback = name.startswith("Loopback")
                is_subif = "." in name
                is_routed = (is_svi or is_loopback or is_subif or
                             intf.get("switchport") == False or
                             intf.get("type") in ("routed", "svi", "loopback"))
                if not is_routed:
                    continue
                if not ip_raw:
                    continue  # skip routed interfaces without IP
                ip_addr, mask = _parse_ip_mask(ip_raw)
                if not ip_addr:
                    continue
                entry = {
                    "name": name,
                    "description": intf.get("description", ""),
                    "vrf": intf.get("vrf") or "",
                    "ipv4": {"address": ip_addr, "netmask": mask},
                    "mtu": intf.get("mtu"),
                    "shutdown": intf.get("admin_state") == "down" or intf.get("shutdown", False),
                    "pim_sparse": intf.get("pim_sparse", False),
                }
                # Sub-interface dot1q from encapsulation or name
                if is_subif:
                    enc = intf.get("encapsulation_dot1q_vlan") or intf.get("dot1q_vlan")
                    if not enc:
                        # Extract from name like Ethernet23.11 -> vlan 11
                        try:
                            enc = int(name.split(".")[-1])
                        except (ValueError, IndexError):
                            pass
                    entry["dot1q_vlan"] = enc
                    entry["helper_addresses"] = intf.get("helper_addresses", [])
                routed.append(entry)
        if routed:
            normalized["routed_interfaces"] = routed

    # --- VTP (layer2.vtp) ---
    if not system.get("vtp"):
        l2 = normalized.get("layer2", {}) or {}
        if isinstance(l2.get("vtp"), dict):
            if "system" not in normalized:
                normalized["system"] = {}
            if isinstance(normalized["system"], dict):
                normalized["system"]["vtp"] = l2["vtp"]

    # Normalize Interface Names in Lists
    logger.info(f"Keys in normalized: {list(normalized.keys())}")
    # access_interfaces is a list of strings "Name|Mode|..."
    if "access_interfaces" in normalized and isinstance(normalized["access_interfaces"], list):
        new_interfaces = []
        for item in normalized["access_interfaces"]:
            if isinstance(item, str) and "|" in item:
                parts = item.split("|")
                # Normalize the interface name (first part)
                parts[0] = normalize_interface_name(parts[0], target_device)
                new_interfaces.append("|".join(parts))
            else:
                new_interfaces.append(item)
        normalized["access_interfaces"] = new_interfaces

    # Merge 'access_ports' (LLM rich data) into 'access_interfaces' (Legacy structure)
    # This ensures NAC data extracted by LLM is available in the normalized schema

    # Locate access_ports data (could be at root or under 'interfaces')
    access_ports_data = None
    if "access_ports" in normalized:
        access_ports_data = normalized["access_ports"]
    elif "interfaces" in normalized and isinstance(normalized["interfaces"], dict) and "access_ports" in normalized["interfaces"]:
        access_ports_data = normalized["interfaces"]["access_ports"]

    if access_ports_data and "access_interfaces" in normalized:
        # Create a map of existing interfaces by name
        intf_map = {i.get("name"): i for i in normalized["access_interfaces"] if isinstance(i, dict)}

        # Handle access_ports whether it's a list or a dict with "ports" key
        port_list = []
        if isinstance(access_ports_data, dict) and "ports" in access_ports_data:
            port_list = access_ports_data["ports"]
        elif isinstance(access_ports_data, list):
            port_list = access_ports_data

        logger.info(f"Merging {len(port_list)} LLM ports into {len(intf_map)} legacy interfaces")

        for port in port_list:
            if not isinstance(port, dict): continue

            name = port.get("name")
            # Normalize name to match map keys
            if name:
                norm_name = normalize_interface_name(name, target_device)
                if norm_name in intf_map:
                    target = intf_map[norm_name]
                    # Copy NAC data directly to target root
                    if "nac" in port:
                        target["nac"] = port["nac"]
                    # Copy switchport data to config (Legacy structure)
                    if "switchport" in port:
                         if "config" not in target: target["config"] = {}
                         if "access_vlan" in port["switchport"]:
                             target["config"]["access_vlan"] = port["switchport"]["access_vlan"]
                         if "voice_vlan" in port["switchport"]:
                             target["config"]["voice_vlan"] = port["switchport"]["voice_vlan"]

    # --- Bridge ALL interface sources to legacy access_interfaces format ---
    # Handles: interfaces.ethernet, interfaces list, AND access_ports (Arista shape)
    if "access_interfaces" not in normalized or not normalized["access_interfaces"]:
        converted = []
        port_num = 1

        # Source 1: interfaces.ethernet or flat interfaces list
        intf_source = None
        if isinstance(normalized.get("interfaces"), dict):
            intf_source = normalized["interfaces"].get("ethernet", [])
        elif isinstance(normalized.get("interfaces"), list):
            intf_source = normalized["interfaces"]

        if intf_source:
            for intf in intf_source:
                if not isinstance(intf, dict):
                    continue
                sw = intf.get("switchport", {})
                if not isinstance(sw, dict):
                    sw = {}
                mode = sw.get("mode", "")
                if mode != "access":
                    continue
                features = intf.get("features", {})
                if not isinstance(features, dict):
                    features = {}
                config = {
                    "description": intf.get("description", "Access Port"),
                    "access_vlan": sw.get("access_vlan", 1),
                    "shutdown": not intf.get("enabled", True),
                    "portfast": features.get("stp_portfast", False),
                    "bpduguard": features.get("bpduguard", False),
                }
                if sw.get("voice_vlan"):
                    config["voice_vlan"] = sw["voice_vlan"]
                nac = intf.get("nac", {})
                if nac and isinstance(nac, dict):
                    dot1x_val = nac.get("dot1x", False)
                    mab_val = nac.get("mab", False)
                    dot1x_enabled = dot1x_val.get("enabled", False) if isinstance(dot1x_val, dict) else bool(dot1x_val)
                    mab_enabled = mab_val.get("enabled", False) if isinstance(mab_val, dict) else bool(mab_val)
                    if dot1x_enabled:
                        config["dot1x"] = True
                    if mab_enabled:
                        config["mab"] = True
                    if dot1x_enabled or mab_enabled:
                        config["nac_enable"] = True
                converted.append({
                    "name": intf.get("name", f"GigabitEthernet1/0/{port_num}"),
                    "switch": 1, "module": 0, "port": port_num,
                    "config": config,
                })
                port_num += 1

        # Source 2: access_ports (Arista shape with switchport_mode, vlan, stp.portfast)
        if not converted and access_ports_data:
            ap_list = access_ports_data if isinstance(access_ports_data, list) else access_ports_data.get("ports", []) if isinstance(access_ports_data, dict) else []
            for ap in ap_list:
                if not isinstance(ap, dict):
                    continue
                mode = ap.get("switchport_mode") or ap.get("mode", "access")
                if mode != "access":
                    continue
                stp = ap.get("stp", {}) or {}
                nac = ap.get("nac", {}) or {}
                config = {
                    "description": ap.get("description", "Access Port"),
                    "access_vlan": ap.get("vlan") or ap.get("access_vlan", 1),
                    "shutdown": ap.get("shutdown", False),
                    "portfast": stp.get("portfast", ap.get("stp_portfast", True)),
                    "bpduguard": stp.get("bpduguard", ap.get("stp_bpduguard", True)),
                }
                if ap.get("voice_vlan"):
                    config["voice_vlan"] = ap["voice_vlan"]
                # NAC handling for all shapes
                if isinstance(nac, dict) and nac:
                    dot1x_val = nac.get("dot1x", False)
                    mab_val = nac.get("mab", False)
                    dot1x_enabled = dot1x_val.get("enabled", False) if isinstance(dot1x_val, dict) else bool(dot1x_val)
                    mab_enabled = mab_val.get("enabled", False) if isinstance(mab_val, dict) else bool(mab_val)
                    if dot1x_enabled:
                        config["dot1x"] = True
                    if mab_enabled:
                        config["mab"] = True
                    if dot1x_enabled or mab_enabled:
                        config["nac_enable"] = True
                elif nac is True or (isinstance(nac, dict) and nac.get("enabled")):
                    config["nac_enable"] = True
                converted.append({
                    "name": ap.get("name", f"GigabitEthernet1/0/{port_num}"),
                    "switch": 1, "module": 0, "port": port_num,
                    "config": config,
                })
                port_num += 1

        if converted:
            normalized["access_interfaces"] = converted
            logger.info(f"Converted {len(converted)} interfaces to legacy access_interfaces format")

    # Ensure critical sections exist
    if "catalyst_center" not in normalized:
        normalized["catalyst_center"] = {}

    new_trace = append_trace(state, "Schema Normalizer", "success", "Normalized data structure.")

    # Save Output
    temp_state = state.copy()
    temp_state["normalized_intent"] = normalized
    save_agent_output(temp_state, "3_schema_normalizer", normalized, "json")

    return {"normalized_intent": normalized, "trace_log": new_trace}

def validate_semantics(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    """Dynamically loads and runs semantic validation rules from the validation/rules directory."""
    issues = []
    try:
        # Determine path to rules directory (2 levels up from scripts/ai_modernization)
        # scripts/ai_modernization -> scripts -> repo_root -> validation/rules
        root_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))
        rules_dir = os.path.join(root_dir, "validation", "rules")

        if not os.path.exists(rules_dir):
            logger.warning(f"Validation rules directory not found at {rules_dir}")
            return []

        # List all python files starting with meant for rules (e.g. 101_...)
        rule_files = [f for f in os.listdir(rules_dir) if f.endswith(".py") and f[0].isdigit()]

        # Add rules dir to sys.path temporarily
        sys.path.append(rules_dir)

        for rf in rule_files:
            module_name = rf[:-3]
            try:
                # Import the rule module
                if module_name in sys.modules:
                    module = importlib.reload(sys.modules[module_name])
                else:
                    module = importlib.import_module(module_name)

                # Assume the rule is implemented as a class named 'Rule' or similar pattern
                # Based on 101_unique_keys.py, it uses `class Rule:`
                if hasattr(module, "Rule"):
                    rule_class = getattr(module, "Rule")
                    if hasattr(rule_class, "match"):
                        # Execute match()
                        results = rule_class.match(intent)
                        # Results are list of strings describing the issue
                        for r in results:
                            issues.append({
                                "field": f"Rule {rule_class.id} ({rule_class.description})",
                                "message": str(r),
                                "severity": rule_class.severity.lower() if hasattr(rule_class, "severity") else "error"
                            })
            except Exception as e:
                logger.warning(f"Failed to run rule {rf}: {e}")

        # Clean up path
        sys.path.remove(rules_dir)

    except Exception as e:
        logger.error(f"Semantic validation error: {e}")

    return issues

def _auto_correct_intent(intent: dict) -> tuple[dict, list[str]]:
    """
    Apply deterministic auto-corrections for rules 121 and 122.

    Rule 121 — System completeness:
      If dns_servers, ntp_servers, stp_mode, logging_hosts, or
      errdisable_config.causes are missing/empty, insert a ['need_input']
      / 'need_input' placeholder so downstream templates render a safe value
      rather than silently omitting the field.

    Rule 122 — Uplink stack convention:
      For stacked devices, remove any port-channel member_interface whose
      switch number is not the first or last in the stack, or whose port
      index is not 1.

    Returns the (possibly modified) intent dict and a list of correction
    descriptions for trace logging.
    """
    import re as _re
    corrections: list[str] = []

    # --- Rule 121: system completeness ---
    if not intent.get("dns_servers"):
        intent["dns_servers"] = ["need_input"]
        corrections.append("rule121: inserted dns_servers=['need_input']")

    if not intent.get("ntp_servers"):
        intent["ntp_servers"] = ["need_input"]
        corrections.append("rule121: inserted ntp_servers=['need_input']")

    if not intent.get("stp_mode") or str(intent.get("stp_mode", "")).strip() == "":
        intent["stp_mode"] = "need_input"
        corrections.append("rule121: inserted stp_mode='need_input'")

    if not intent.get("logging_hosts"):
        intent["logging_hosts"] = ["need_input"]
        corrections.append("rule121: inserted logging_hosts=['need_input']")

    errdis = intent.get("errdisable_config")
    if not isinstance(errdis, dict):
        intent["errdisable_config"] = {"causes": ["need_input"]}
        corrections.append("rule121: inserted errdisable_config.causes=['need_input']")
    elif not errdis.get("causes"):
        errdis["causes"] = ["need_input"]
        corrections.append("rule121: inserted errdisable_config.causes=['need_input']")

    # --- Rule 122: uplink stack convention ---
    _INTF_RE = _re.compile(r'(?:TenGigabitEthernet|Te)(\d+)/(\d+)/(\d+)', _re.IGNORECASE)
    stack_info = intent.get("stack_info") or {}
    if isinstance(stack_info, dict) and stack_info.get("is_stack"):
        member_count = stack_info.get("member_count", 1)
        if member_count >= 2:
            switches_raw = stack_info.get("switches", [])
            if switches_raw:
                first = switches_raw[0]
                if isinstance(first, (list, tuple)):
                    sw_nums = sorted(int(s[0]) for s in switches_raw)
                else:
                    sw_nums = sorted(int(s) for s in switches_raw)
            else:
                sw_nums = list(range(1, member_count + 1))
            first_sw = sw_nums[0]
            last_sw = sw_nums[-1]

            for ul in intent.get("uplinks", []):
                if not isinstance(ul, dict) or ul.get("type") != "port-channel":
                    continue
                members = ul.get("member_interfaces", [])
                if not members:
                    continue
                kept = []
                removed = []
                for m in members:
                    name = m.get("name", "") if isinstance(m, dict) else str(m)
                    match = _INTF_RE.search(name)
                    if match:
                        sw, _mod, port = int(match.group(1)), int(match.group(2)), int(match.group(3))
                        if sw in (first_sw, last_sw) and port == 1:
                            kept.append(m)
                        else:
                            removed.append(name)
                    else:
                        kept.append(m)  # non-TenGig member, keep as-is
                if removed:
                    ul["member_interfaces"] = kept
                    pc_id = ul.get("port_channel_id") or ul.get("name") or "?"
                    corrections.append(
                        f"rule122: Port-channel{pc_id} removed extra members {removed}"
                    )

    return intent, corrections


def agent_validator(state: AgentState):
    """Agent 4: Validate against rules, then auto-correct for rules 121+122."""
    logger.info("--- Agent 4: Validator ---")
    intent = state.get("normalized_intent", {})
    issues = []

    # 1. Structural / Basic Validation
    hostname = intent.get("hostname") or (intent.get("system", {}).get("hostname") if isinstance(intent.get("system"), dict) else None)
    if not hostname:
        issues.append({"field": "hostname", "message": "Hostname is missing", "severity": "error"})

    # 2. Auto-correct intent (rules 121 + 122) before semantic validation
    intent, corrections = _auto_correct_intent(intent)
    if corrections:
        logger.info(f"Auto-corrections applied: {corrections}")
        # Persist corrected intent as 3_schema_normalizer.json so compute_f1
        # picks up the Approach C corrected output, not the raw normalizer output.
        save_agent_output(state, "3_schema_normalizer", intent, "json")

    # 3. Semantic Validation (Dynamic Rules) — on the corrected intent
    semantic_issues = validate_semantics(intent)
    issues.extend(semantic_issues)

    # 3. Schema structural validation (yamale)
    try:
        _schema_path = os.path.join(os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "..")), "schema.yaml")
        if os.path.exists(_schema_path):
            _schema = yamale.make_schema(_schema_path)
            _data = yamale.make_data(content=yaml.dump(intent))
            yamale.validate(_schema, _data, strict=False)
    except yamale.YamaleError as _ye:
        for _line in str(_ye).splitlines():
            _line = _line.strip()
            if _line and "Error validating" not in _line:
                issues.append({"field": "schema", "message": _line, "severity": "warning"})
    except Exception as _e:
        logger.warning(f"yamale schema check skipped: {_e}")

    # Basic score
    error_count = len([i for i in issues if i['severity'] == "error"])
    valid = error_count == 0

    # Score penalty logic
    score = 1.0 - (error_count * 0.2) - (len(semantic_issues) * 0.1)
    score = max(0.0, score)

    result = {"valid": valid, "score": score, "issues": issues}

    status = "success" if valid else "failed"
    new_trace = append_trace(state, "Validator", status, f"Found {len(issues)} issues.")

    # Save output
    save_agent_output(state, "4_validator", result, "json")

    # Return corrected intent so the generator uses the auto-corrected version
    return {"validation_result": result, "normalized_intent": intent, "trace_log": new_trace}

# ---------------------------------------------------------------------------
#  Template-based Generator – maps normalized schema data → Jinja template
#  variables and builds the Catalyst Center YAML directly (no legacy module).
# ---------------------------------------------------------------------------

def _var(name: str, value: str) -> Dict[str, str]:
    """Helper: create a template variable dict."""
    return {'name': name, 'value': value}


def _block(value: str) -> str:
    """Wrap a multi-entry string in ForceBlockStyle for YAML literal block output."""
    clean = "\n".join(line.rstrip() for line in value.splitlines() if line.strip())
    return ForceBlockStyle(clean + "\n") if clean else ""


def _safe(value, default: str = 'need_input') -> str:
    """Return *value* as a string, falling back to *default*."""
    if value is None or value == '':
        return default
    return str(value)


def _determine_model(access_count: int) -> str:
    """Pick a C9300 PID based on the number of access interfaces."""
    if access_count <= 24:
        return 'C9300-24P'
    return 'C9300-48P'


# ---- Per-template variable builders ----------------------------------------

def _extract_mgmt_ip_info(intent: Dict[str, Any]):
    """Extract management IP, mask, gateway, vlan_id from multiple management shapes."""
    mgmt = intent.get("management", {}) or {}
    pnp = intent.get("pnp_config", {}) or {}

    # Shape 1: flat management keys (Cisco QTS)
    mgmt_ip = mgmt.get("management_ip") or pnp.get("pnp_vlan_network_add", "")
    mgmt_mask = mgmt.get("management_mask") or pnp.get("pnp_vlan_network_mask", "")
    mgmt_gw = mgmt.get("default_gateway") or pnp.get("pnp_vlan_default_gateway", "")
    mgmt_svi = mgmt.get("management_svi", "")

    # Shape 2: management.inband (Arista)
    inband = mgmt.get("inband", {}) or {}
    if isinstance(inband, list):
        inband = inband[0] if inband else {}
    if not mgmt_ip and inband.get("ip_address"):
        ip, mask = _parse_ip_mask(inband["ip_address"])
        mgmt_ip = ip
        mgmt_mask = mask
        mgmt_svi = inband.get("svi", "")

    # Shape 3: management.oob (Arista)
    oob = mgmt.get("oob", {}) or {}
    if isinstance(oob, list):
        oob = oob[0] if oob else {}
    if not mgmt_ip and oob.get("ip_address"):
        ip, mask = _parse_ip_mask(oob["ip_address"])
        mgmt_ip = ip
        mgmt_mask = mask

    # Shape 4: management.pnp_vlan (Cisco FR_1)
    pnp_vlan = mgmt.get("pnp_vlan", {}) or {}
    if not mgmt_ip and pnp_vlan.get("svi_ipv4"):
        ip, mask = _parse_ip_mask(pnp_vlan["svi_ipv4"])
        mgmt_ip = ip
        mgmt_mask = mask
        mgmt_gw = mgmt_gw or pnp_vlan.get("default_gateway", "")
        mgmt_svi = mgmt_svi or f"Vlan{pnp_vlan.get('id', '')}"

    # Default gateway from oob default_route
    if not mgmt_gw and isinstance(oob.get("default_route"), dict):
        mgmt_gw = oob["default_route"].get("next_hop", "")

    # Derive vlan_id from SVI
    vlan_id = mgmt_svi.replace("Vlan", "") if mgmt_svi else pnp.get("pnp_vlan_id", "1")

    return mgmt_ip or "need_input", mgmt_mask or "255.255.255.0", mgmt_gw or "need_input", str(vlan_id)


def _gen_pnp_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    hostname = _find_hostname(intent) or 'PNP-DEVICE'
    domain = intent.get("domain_name") or (intent.get("system", {}) or {}).get("domain_name", "need_input")
    snmp = intent.get("snmp_config", {}) or {}
    pnp = intent.get("pnp_config", {}) or {}

    # Logging hosts - handle both list and string
    logging_hosts = intent.get("logging_hosts", [])
    if isinstance(logging_hosts, str):
        logging_hosts = [logging_hosts]
    log_server = logging_hosts[0] if logging_hosts else '192.168.1.100'

    # Stack info — check stack_info, device.stack, and root-level stack
    stack_info = intent.get("stack_info", {}) or {}
    device_block = intent.get("device", {}) or {}
    stack_block = device_block.get("stack", {}) or intent.get("stack", {}) or {}
    is_stack = stack_info.get("is_stack", stack_block.get("enabled", False))
    member_count = stack_info.get("member_count", stack_block.get("member_count", 1))

    mgmt_ip, mgmt_mask, mgmt_gw, vlan_id = _extract_mgmt_ip_info(intent)

    return [
        _var('device_host_name', hostname),
        _var('domain_name', _safe(domain)),
        _var('pnp_vlan_id', _safe(pnp.get("pnp_vlan_id") or vlan_id, "1")),
        _var('pnp_vlan_name', pnp.get('pnp_vlan_name', 'MGMT')),
        _var('pnp_vlan_network_add', mgmt_ip),
        _var('pnp_vlan_network_mask', mgmt_mask),
        _var('pnp_vlan_default_gateway', mgmt_gw),
        _var('pnp_interface', 'GigabitEthernet1/0/1'),
        _var('snmp_community_ro', snmp.get('community_ro', 'need_input')),
        _var('log_server', log_server),
        _var('is_stack', str(is_stack).lower()),
        _var('stack_members', str(member_count)),
    ]


def _gen_system_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    hostname = _find_hostname(intent) or 'need_input'
    domain = intent.get("domain_name") or (intent.get("system", {}) or {}).get("domain_name", "need_input")

    # Timezone – handle timezone_config.timezone as string OR dict
    system = intent.get("system", {}) or {}
    tz_cfg = intent.get("timezone_config", {}) or {}
    tz_block = system.get("timezone", {}) or {}
    # tz_cfg["timezone"] may be a string ("CDT") or a dict ({"name": "CDT", ...})
    tz_val = tz_cfg.get("timezone")
    if isinstance(tz_val, dict):
        timezone_name = tz_val.get("name", "need_input")
        tz_offset_from_val = tz_val.get("utc_offset_hours")
        dst_block = tz_val.get("dst") or tz_val.get("summer_time") or {}
    elif isinstance(tz_val, str) and tz_val:
        timezone_name = tz_val
        tz_offset_from_val = None
        dst_block = {}
    else:
        timezone_name = "need_input"
        tz_offset_from_val = None
        dst_block = {}
    # Fallback to system.timezone block if timezone_config didn't provide a name
    if timezone_name == "need_input" and isinstance(tz_block, dict):
        timezone_name = tz_block.get("name", "need_input")
    timezone_offset = _safe(tz_cfg.get("timezone_offset") or tz_offset_from_val or (tz_block.get("utc_offset_hours") if isinstance(tz_block, dict) else None), "need_input")
    # Daylight savings name — check multiple sources
    if not dst_block and isinstance(tz_block, dict):
        dst_block = tz_block.get("summer_time", {}) or tz_block.get("dst", {}) or {}
    daylight_name = intent.get("daylight_savings") or (dst_block.get("name") if isinstance(dst_block, dict) else None) or "need_input"

    # DNS servers
    dns = intent.get("dns_servers", [])
    if isinstance(dns, str):
        dns = [dns] if dns else []
    dns_str = ','.join(dns) if dns else 'need_input'

    # NTP servers
    ntp_list = intent.get("ntp_servers", [])
    if isinstance(ntp_list, str):
        ntp_list = [ntp_list] if ntp_list else []
    # Each entry may be a plain IP or a pipe-delimited string "ip|prefer"
    # Also handle dict form: {"server": "x", "prefer": true}
    ntp_strings = []
    for n in ntp_list:
        if isinstance(n, dict):
            s = n.get("server") or n.get("address", "")
            if n.get("prefer"):
                s += "|prefer"
            ntp_strings.append(s)
        else:
            ntp_strings.append(str(n))
    ntp_val = ','.join(ntp_strings) if ntp_strings else 'false'

    stp_mode = intent.get("stp_mode") or system.get("stp", {}).get("mode", "rapid-pvst")

    # Logging
    log_hosts = intent.get("logging_hosts", [])
    if isinstance(log_hosts, str):
        log_hosts = [log_hosts] if log_hosts else []

    # NTP auth
    ntp_auth_keys = intent.get("ntp_auth_keys", [])
    if isinstance(ntp_auth_keys, str):
        ntp_auth_keys = [ntp_auth_keys] if ntp_auth_keys else []

    # Local users
    local_users = intent.get("local_users", [])
    if isinstance(local_users, str):
        local_users = []

    variables = [
        _var('enable_secret', _safe(intent.get("enable_secret"), 'need_input')),
        _var('hostname', hostname),
        _var('domain_name', _safe(domain)),
        _var('timezone', _safe(timezone_name)),
        _var('timezone_offset', _safe(timezone_offset)),
        _var('daylight_savings_name', _safe(daylight_name)),
        _var('dns_servers', _block(dns_str) if ',' in dns_str else dns_str),
        _var('ntp_servers', _block(ntp_val) if ',' in ntp_val else ntp_val),
        _var('license_level', 'network-advantage'),
        _var('stp_mode', stp_mode),
        _var('ntp_authenticate', 'true' if ntp_auth_keys else 'false'),
    ]

    if ntp_auth_keys:
        variables.append(_var('ntp_auth_keys', _block(','.join(ntp_auth_keys))))
    variables.append(_var('ntp_master', 'false'))

    if log_hosts:
        variables.append(_var('logging_servers', _block(','.join(log_hosts))))
    variables.append(_var('log_severity_level', 'informational'))

    # Errdisable
    errdisable = intent.get("errdisable_config", {}) or {}
    if errdisable.get("causes"):
        variables.append(_var('errdisable_causes', _block(','.join(errdisable['causes']))))
    if errdisable.get("recovery_interval"):
        variables.append(_var('recovery_interval', str(errdisable['recovery_interval'])))

    # Local users → "user:password,user2:password2"
    if local_users:
        user_strs = []
        for u in local_users:
            if isinstance(u, dict):
                user_strs.append(f"{u.get('name', 'admin')}:{u.get('password', 'need_input')}")
        if user_strs:
            variables.append(_var('local_users', _block(','.join(user_strs))))

    return variables


def _gen_vlan_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    vlans = intent.get("vlans", [])
    system = intent.get("system", {}) or {}
    vtp = system.get("vtp", {}) or {}

    vlan_entries = []
    for v in vlans:
        if isinstance(v, dict):
            vid = str(v.get("id", ""))
            vname = v.get("name", "")
            vlan_entries.append(f"{vid}|{vname}" if vname else vid)

    return [
        _var('vlans', ','.join(vlan_entries)),
        _var('vtp_domain', vtp.get("domain") or intent.get("vtp_domain", "CWAN")),
        _var('vtp_mode', vtp.get("mode") or intent.get("vtp_mode", "transparent")),
    ]


def _gen_mgmt_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    mgmt = intent.get("management", {}) or {}
    vrf_cfg_raw = intent.get("vrf_config", {}) or {}
    # vrf_config can be a dict or a list — normalize to a single dict for mgmt VRF
    if isinstance(vrf_cfg_raw, list):
        vrf_cfg = vrf_cfg_raw[0] if vrf_cfg_raw and isinstance(vrf_cfg_raw[0], dict) else {}
    else:
        vrf_cfg = vrf_cfg_raw if isinstance(vrf_cfg_raw, dict) else {}
    pnp = intent.get("pnp_config", {}) or {}

    mgmt_ip, mgmt_mask, mgmt_gw, vlan_id = _extract_mgmt_ip_info(intent)

    has_mgmt = bool(mgmt_ip and mgmt_ip != "need_input")

    variables = [
        _var('enable_management', str(has_mgmt).lower()),
        _var('http_server', 'true'),
        _var('https_server', 'true'),
    ]

    # VRF config – pipe format: name|rd|rt_export|rt_import
    if vrf_cfg and vrf_cfg.get("name"):
        vrf_str = f"{vrf_cfg['name']}|{vrf_cfg.get('rd', '')}|{vrf_cfg.get('rt_export', '')}|{vrf_cfg.get('rt_import', '')}"
        variables.append(_var('mgmt_vrf_config', _block(vrf_str)))
    elif mgmt.get("vrf"):
        vrf_str = f"{mgmt['vrf']}|||"
        variables.append(_var('mgmt_vrf_config', _block(vrf_str)))
    elif (mgmt.get("oob", {}) or {}).get("vrf"):
        vrf_str = f"{mgmt['oob']['vrf']}|||"
        variables.append(_var('mgmt_vrf_config', _block(vrf_str)))

    # Source interface flags
    for src_key in ['ssh_source_interface', 'snmp_source_interface', 'ntp_source_interface',
                    'tacacs_source_interface', 'radius_source_interface']:
        flag_key = f"has_{src_key.replace('_interface', '').replace('_source', '_source')}"
        if intent.get(flag_key) or intent.get(src_key):
            variables.append(_var(src_key, 'true'))

    variables.extend([
        _var('mgmt_interface_type', 'vlan'),
        _var('mgmt_vlan_id', _safe(vlan_id)),
        _var('mgmt_ip_address', _safe(mgmt_ip)),
        _var('mgmt_subnet_mask', _safe(mgmt_mask)),
        _var('mgmt_default_gateway', _safe(mgmt_gw)),
        _var('mgmt_vlan_name', pnp.get('pnp_vlan_name', 'MGMT')),
    ])

    return variables


def _gen_acl_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    acls = intent.get("acls", [])
    std_strs, ext_strs = [], []

    for acl in acls:
        if not isinstance(acl, dict):
            continue
        acl_name = acl.get("name", "")
        acl_type = acl.get("type", "standard")

        for entry in acl.get("entries", []):
            seq = str(entry.get("sequence", ""))
            action = entry.get("action", "permit")
            log_flag = 'true' if entry.get("log") else 'false'

            # Skip remark entries (no source/destination)
            if action == "remark":
                continue

            if acl_type == "standard":
                source = entry.get("source") or "any"
                # Determine source format
                if source == "any":
                    src_addr, wildcard = "any", ""
                elif " " in source:
                    parts = source.split(" ", 1)
                    src_addr, wildcard = parts[0], parts[1]
                else:
                    src_addr, wildcard = f"host {source}", ""
                std_strs.append(f"{acl_name}|{seq}|{action}|{src_addr}|{wildcard}|{log_flag}")

            elif acl_type == "extended":
                protocol = entry.get("protocol", "ip")
                source = entry.get("source") or "any"
                src_fmt = source if source == "any" or " " in source else f"host {source}"
                source_op = entry.get("source_port_operator", "")
                if source_op and entry.get("source_port"):
                    source_op = f"{source_op} {entry['source_port']}"
                dest = entry.get("destination") or "any"
                dest_fmt = dest if dest == "any" or " " in dest else f"host {dest}"
                dest_op = entry.get("dest_port_operator", "") or entry.get("port_operator", "")
                if dest_op == "range":
                    start = entry.get("dest_port_start", entry.get("port_start", ""))
                    end = entry.get("dest_port_end", entry.get("port_end", ""))
                    if start and end:
                        dest_op = f"{dest_op} {start} {end}"
                elif dest_op:
                    port = entry.get("dest_port", entry.get("port", ""))
                    if port:
                        dest_op = f"{dest_op} {port}"
                ext_strs.append(f"{acl_name}|{seq}|{action}|{protocol}|{src_fmt}|{source_op}|{dest_fmt}|{dest_op}|{log_flag}")

    variables = []
    variables.append(_var('standard_acls', _block(',\n'.join(std_strs)) if std_strs else ''))
    variables.append(_var('extended_acls', _block(',\n'.join(ext_strs)) if ext_strs else ''))
    return variables


def _gen_uplink_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    uplinks = intent.get("uplinks", [])
    uplink_strs = []

    for ul in uplinks:
        if not isinstance(ul, dict):
            continue
        ul_type = ul.get("type", "trunk")
        ul_name = ul.get("name", "")
        desc = ul.get("description", "UPSTREAM-TRUNK")
        pc_id = str(ul.get("port_channel_id", "")) if ul.get("port_channel_id") else ""
        allowed = ul.get("allowed_vlans", [])
        if isinstance(allowed, list):
            allowed_str = ','.join(str(v) for v in allowed)
        else:
            allowed_str = str(allowed)
        native = str(ul.get("native_vlan", "")) if ul.get("native_vlan") else ""
        root_guard = "true" if ul.get("root_guard", True) else "false"
        load_interval = str(ul.get("load_interval", "")) if ul.get("load_interval") else ""

        # Member interfaces
        members = ul.get("member_interfaces", [])
        # Also check lacp.members (alternate LLM format)
        if not members and isinstance(ul.get("lacp"), dict):
            members = ul["lacp"].get("members", [])
        member_strs = []
        for m in members:
            if isinstance(m, dict):
                m_name = m.get("name", "")
                m_mode = m.get("lacp_mode") or m.get("mode", "active")
                m_desc = m.get("description", "PORT-CHANNEL MEMBER")
                member_strs.append(f"{m_name}:{m_mode}:{m_desc}")
        members_str = ';'.join(member_strs)

        uplink_strs.append(
            f"{ul_type}|{ul_name}|{desc}|{pc_id}|{allowed_str}|{native}|{root_guard}|{load_interval}|{members_str}"
        )

    val = _block(',\n'.join(uplink_strs)) if uplink_strs else ''
    return [_var('uplinks', val)]


def _gen_snmp_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    snmp = intent.get("snmp_config", {}) or {}
    # Also check services.snmp (alternate LLM format)
    if not snmp:
        snmp = (intent.get("services", {}) or {}).get("snmp", {}) or {}

    variables = [
        _var('snmp_community_ro', snmp.get('community_ro', 'need_input')),
        _var('snmp_community_rw', snmp.get('community_rw', 'need_input')),
        _var('snmp_location', snmp.get('location', 'need_input')),
        _var('snmp_contact', snmp.get('contact', 'need_input')),
    ]
    if snmp.get('chassis_id'):
        variables.append(_var('chassis_id', snmp['chassis_id']))
    if snmp.get('acl_ro'):
        variables.append(_var('snmp_acl_ro', str(snmp['acl_ro'])))
    if snmp.get('acl_rw'):
        variables.append(_var('snmp_acl_rw', str(snmp['acl_rw'])))
    variables.append(_var('enable_traps', str(snmp.get('enable_traps', True)).lower()))
    return variables


def _gen_aaa_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    aaa = intent.get("aaa_config", {}) or {}
    # Also check nac.aaa (alternate LLM format)
    nac_block = intent.get("nac", {}) or {}
    tacacs_servers = aaa.get("tacacs_servers", [])
    if not tacacs_servers and isinstance(nac_block.get("tacacs_servers"), list):
        tacacs_servers = nac_block["tacacs_servers"]

    tacacs_group = aaa.get("tacacs_group_name", "need_input")
    # Try to find group name from nac.aaa.tacacs_groups
    if tacacs_group == "need_input" and isinstance(nac_block.get("aaa"), dict):
        tac_groups = nac_block["aaa"].get("tacacs_groups", [])
        if tac_groups and isinstance(tac_groups[0], dict):
            tacacs_group = tac_groups[0].get("group_name", "need_input")

    variables = [_var('tacacs_group_name', tacacs_group)]

    if tacacs_servers:
        srv_strs = []
        for s in tacacs_servers:
            if isinstance(s, dict):
                srv_strs.append(f"{s.get('name', '')}|{s.get('ip') or s.get('ipv4', '')}|{s.get('key', 'need_input')}")
        variables.append(_var('tacacs_servers', _block(','.join(srv_strs)) if srv_strs else 'need_input'))
    else:
        variables.append(_var('tacacs_servers', 'need_input'))

    if aaa.get("tacacs_timeout"):
        variables.append(_var('tacacs_timeout', str(aaa['tacacs_timeout'])))

    return variables


def _gen_nac_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    """Generate variables for the EDGE_NAC_template (RADIUS/dot1x/CoA)."""
    nac = intent.get("nac_config", {})
    if not nac:
        return []

    variables = [
        _var('radius_group_name', nac.get('radius_group_name', 'RADIUS_GROUP')),
    ]

    # RADIUS servers: name|ip|auth_port|acct_port|key
    radius_servers = nac.get("radius_servers", [])
    if radius_servers:
        srv_strs = []
        for s in radius_servers:
            if isinstance(s, dict):
                srv_strs.append(
                    f"{s.get('name', '')}|{s.get('ip', '')}|"
                    f"{s.get('auth_port', '1645')}|{s.get('acct_port', '1646')}|"
                    f"{s.get('key', 'need_input')}"
                )
        variables.append(_var('radius_servers', _block(','.join(srv_strs)) if srv_strs else 'need_input'))
    else:
        variables.append(_var('radius_servers', 'need_input'))

    if nac.get("radius_deadtime"):
        variables.append(_var('radius_deadtime', str(nac['radius_deadtime'])))

    # CoA clients: ip|key
    coa_clients = nac.get("coa_clients", [])
    if coa_clients:
        coa_strs = []
        for c in coa_clients:
            if isinstance(c, dict):
                coa_strs.append(f"{c.get('ip', '')}|{c.get('key', 'need_input')}")
        variables.append(_var('coa_clients', _block(','.join(coa_strs)) if coa_strs else ''))
    if nac.get("coa_port"):
        variables.append(_var('coa_port', str(nac['coa_port'])))
    if nac.get("coa_auth_type"):
        variables.append(_var('coa_auth_type', nac['coa_auth_type']))

    # dot1x interface-level defaults (informational for access port template)
    if nac.get("dot1x_timeout_server"):
        variables.append(_var('dot1x_timeout_server', nac['dot1x_timeout_server']))
    if nac.get("dot1x_timeout_tx_period"):
        variables.append(_var('dot1x_timeout_tx_period', nac['dot1x_timeout_tx_period']))
    if nac.get("dot1x_max_req"):
        variables.append(_var('dot1x_max_req', nac['dot1x_max_req']))
    if nac.get("dot1x_max_reauth_req"):
        variables.append(_var('dot1x_max_reauth_req', nac['dot1x_max_reauth_req']))

    return variables


def _enrich_storm_control(access_intfs: list, raw_config: str) -> None:
    """Parse storm-control settings per interface from raw config and inject into access_interfaces."""
    if not raw_config or not access_intfs:
        return
    # Build a lookup: interface name -> storm-control values
    sc_map: Dict[str, Dict[str, str]] = {}
    current_intf = None
    for line in raw_config.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface "):
            current_intf = stripped[len("interface "):]
        elif stripped == "!":
            current_intf = None
        elif current_intf and stripped.startswith("storm-control "):
            m = re.match(r'storm-control\s+(broadcast|multicast)\s+level\s+(\S+)(?:\s+(\S+))?', stripped)
            if m:
                sc_map.setdefault(current_intf, {})
                sc_map[current_intf][f"storm_control_{m.group(1)}"] = f"{m.group(2)} {m.group(3)}" if m.group(3) else m.group(2)
    # Merge into access interface config dicts
    for intf in access_intfs:
        if not isinstance(intf, dict):
            continue
        name = intf.get("name", "")
        if name in sc_map:
            cfg = intf.setdefault("config", {})
            cfg.update(sc_map[name])


def _gen_access_port_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    """Convert access_interfaces (legacy format) to pipe-delimited strings."""
    access_intfs = intent.get("access_interfaces", [])
    port_strs = []

    for intf in access_intfs:
        if not isinstance(intf, dict):
            continue
        name = intf.get("name", "")
        cfg = intf.get("config", {}) or {}
        nac_data = intf.get("nac", {}) or {}

        desc = cfg.get("description", "Access Port")
        access_vlan = str(cfg.get("access_vlan", "1"))
        voice_vlan = str(cfg.get("voice_vlan", "")) if cfg.get("voice_vlan") else ""
        port_security = 'true' if cfg.get("port_security") else 'false'
        sec_max = str(cfg.get("port_security_max", "2"))
        sec_violation = cfg.get("port_security_violation", "restrict")
        portfast = 'false' if cfg.get("shutdown") else ('true' if cfg.get("portfast", True) else 'false')
        bpduguard = 'true' if cfg.get("bpduguard", True) else 'false'
        disable_logging = 'true'

        # NAC enable from either config or nac block
        dot1x = nac_data.get("dot1x", False) if isinstance(nac_data, dict) else False
        mab = nac_data.get("mab", False) if isinstance(nac_data, dict) else False
        if isinstance(dot1x, dict):
            dot1x = dot1x.get("enabled", False)
        if isinstance(mab, dict):
            mab = mab.get("enabled", False)
        nac_enable = 'true' if (cfg.get("nac_enable") or cfg.get("dot1x") or cfg.get("mab") or dot1x or mab) else 'false'
        storm_bcast = cfg.get("storm_control_broadcast", "")
        storm_mcast = cfg.get("storm_control_multicast", "")

        port_strs.append(
            f"{name}|{desc}|{access_vlan}|{voice_vlan}|{port_security}|{sec_max}|{sec_violation}|{portfast}|{bpduguard}|{disable_logging}|{nac_enable}|{storm_bcast}|{storm_mcast}"
        )

    val = _block(',\n'.join(port_strs)) if port_strs else ''
    return [_var('access_interfaces', val)]


def _gen_routed_port_variables(intent: Dict[str, Any]) -> List[Dict[str, str]]:
    """Convert routed_interfaces to pipe-delimited strings for EDGE_ROUTED_PORT_template."""
    routed = intent.get("routed_interfaces", [])
    if not routed:
        return []

    port_strs = []
    for ri in routed:
        if not isinstance(ri, dict):
            continue
        name = ri.get("name", "")
        desc = ri.get("description", "")
        # Physical routed interfaces get switchport=false; sub-interfaces leave it empty
        is_subinterface = '.' in name
        switchport = 'false' if not is_subinterface else ''
        vrf = ri.get("vrf", "") or ""
        ipv4 = ri.get("ipv4", {}) or {}
        ip_addr = ipv4.get("address", "") if isinstance(ipv4, dict) else ""
        subnet = ipv4.get("netmask") or ipv4.get("mask", "255.255.255.0") if isinstance(ipv4, dict) else ""
        # Fallback: check flat ip_address/subnet_mask keys (Cisco deterministic mapper)
        if not ip_addr:
            ip_addr = ri.get("ip_address", "")
        if not subnet:
            subnet = ri.get("subnet_mask", "")
        mtu = str(ri.get("mtu", "")) if ri.get("mtu") else ""
        shutdown = 'true' if ri.get("shutdown") else 'false'
        pim = 'true' if ri.get("pim_sparse") else 'false'
        dot1q = str(ri.get("dot1q_vlan", "")) if ri.get("dot1q_vlan") else ""
        helpers = ri.get("helper_addresses", []) or ri.get("ip_helper_addresses", [])
        helpers_str = ';'.join(helpers) if isinstance(helpers, list) else str(helpers) if helpers else ""

        port_strs.append(
            f"{name}|{desc}|{switchport}|{vrf}|{ip_addr}|{subnet}|{mtu}|{shutdown}|{pim}|{dot1q}|{helpers_str}"
        )

    val = _block(',\n'.join(port_strs)) if port_strs else ''
    return [_var('routed_interfaces', val)]


# ---- Main generator entry point --------------------------------------------

def agent_generator(state: AgentState):
    """Agent 5: Generate Final YAML from normalized schema data using Jinja templates."""
    logger.info("--- Agent 5: Generator ---")
    intent = state.get("normalized_intent", {})

    try:
        hostname = _find_hostname(intent) or 'MIGRATED-DEVICE'
        domain = intent.get("domain_name") or (intent.get("system", {}) or {}).get("domain_name", "need_input")
        access_intfs = intent.get("access_interfaces", [])
        mgmt_ip, _, _, _ = _extract_mgmt_ip_info(intent)

        # Build device_config in Catalyst Center structure
        device_config = {
            'name': hostname,
            'fqdn_name': f"{hostname}.{domain}",
            'device_ip': mgmt_ip,
            'pid': _determine_model(len(access_intfs)),
            'serial_number': 'TBD-MIGRATION',
            'state': 'PNP',
            'device_role': 'ACCESS',
            'site': 'need_input',
            'onboarding_template': {
                'name': 'EDGE_PNP_template',
                'variables': _gen_pnp_variables(intent),
            },
            'dayn_templates': {
                'regular': [],
            },
        }

        dayn = device_config['dayn_templates']['regular']

        # System template (always)
        dayn.append({'name': 'EDGE_SYSTEM_template', 'variables': _gen_system_variables(intent), 'redeploy_template': 'ON_CHANGE'})

        # VLAN template (if VLANs exist)
        vlans = intent.get("vlans", [])
        if vlans:
            dayn.append({'name': 'EDGE_VLAN_template', 'variables': _gen_vlan_variables(intent), 'redeploy_template': 'ON_CHANGE'})

        # Management template
        dayn.append({'name': 'EDGE_MGMT_template', 'variables': _gen_mgmt_variables(intent), 'redeploy_template': 'ON_CHANGE'})

        # ACL template (if ACLs exist)
        acls = intent.get("acls", [])
        if acls:
            dayn.append({'name': 'EDGE_ACL_template', 'variables': _gen_acl_variables(intent), 'redeploy_template': 'ON_CHANGE'})

        # Uplink template (if uplinks exist)
        uplinks = intent.get("uplinks", [])
        if uplinks:
            dayn.append({'name': 'EDGE_UPLINK_template', 'variables': _gen_uplink_variables(intent), 'redeploy_template': 'ON_CHANGE'})

        # SNMP template (if snmp configured)
        snmp = intent.get("snmp_config", {}) or (intent.get("services", {}) or {}).get("snmp", {})
        if snmp:
            dayn.append({'name': 'EDGE_SNMP_template', 'variables': _gen_snmp_variables(intent), 'redeploy_template': 'ON_CHANGE'})

        # AAA template (if AAA enabled)
        aaa = intent.get("aaa_config", {}) or {}
        nac_aaa = (intent.get("nac", {}) or {}).get("aaa", {}) or {}
        has_tacacs = aaa.get("aaa_enabled") and aaa.get("tacacs_servers")
        has_nac_tacacs = nac_aaa.get("tacacs_groups")
        if has_tacacs or has_nac_tacacs:
            dayn.append({'name': 'EDGE_AAA_template', 'variables': _gen_aaa_variables(intent), 'redeploy_template': 'ON_CHANGE'})

        # NAC template (if RADIUS/dot1x configured)
        nac_cfg = intent.get("nac_config", {})
        if nac_cfg and (nac_cfg.get("radius_servers") or nac_cfg.get("dot1x_enabled")):
            dayn.append({'name': 'EDGE_NAC_template', 'variables': _gen_nac_variables(intent), 'redeploy_template': 'ON_CHANGE'})

        # Access port template (if access interfaces exist)
        if access_intfs:
            dayn.append({'name': 'EDGE_ACCESS_PORT_template', 'variables': _gen_access_port_variables(intent), 'redeploy_template': 'ON_CHANGE'})

        # Routed port template (if routed interfaces exist)
        routed = intent.get("routed_interfaces", [])
        if routed:
            dayn.append({'name': 'EDGE_ROUTED_PORT_template', 'variables': _gen_routed_port_variables(intent), 'redeploy_template': 'ON_CHANGE'})

        # Wrap in Catalyst Center structure
        final_config = {
            'catalyst_center': {
                'inventory': {
                    'devices': [device_config]
                }
            }
        }

        yaml_output = yaml.safe_dump(final_config, default_flow_style=False, sort_keys=False, width=float("inf"))
        status = "success"
        details = f"Generated using schema-driven template mapping ({len(dayn)} day-N templates)"

    except Exception as e:
        import traceback
        logger.warning(f"Generator error, falling back to simple dump: {e}\n{traceback.format_exc()}")
        yaml_output = yaml.dump(intent, default_flow_style=False, sort_keys=False)
        status = "warning"
        details = f"Fallback dump (generator failed: {str(e)})"

    # Save to device-specific folder
    output_dir = get_output_dir(state)
    filename = (intent.get("hostname") or intent.get("name") or "output") + ".yaml"
    path = os.path.join(output_dir, filename)

    try:
        with open(path, "w") as f:
            f.write(yaml_output)
        # Also save a copy to the base nac-transform/output/ folder
        base_output = os.path.join(current_dir, "..", "..", "output")
        base_path = os.path.join(base_output, filename)
        with open(base_path, "w") as f:
            f.write(yaml_output)
        save_agent_output(state, "5_generator", yaml_output, "yaml")
        if status != "warning":
            status = "success"
    except Exception as e:
        status = "error"
        details = str(e)
        path = ""

    new_trace = append_trace(state, "Generator", status, details)
    return {"final_yaml_output": yaml_output, "final_output_path": path, "trace_log": new_trace}

def agent_reporter(state: AgentState):
    """Agent 6: Generate Markdown Report."""
    logger.info("--- Agent 6: Reporter ---")
    trace = state.get("trace_log", [])

    report_lines = ["# AI Modernization Report", "", f"Date: {datetime.now()}", ""]

    # 1. Decision Metadata & Ambiguity check
    decisions = state.get("decision_metadata", [])
    low_confidence = [d for d in decisions if d.get("confidence", 1.0) < 0.8]

    if decisions:
        report_lines.append("## AI Decision Confidence")
        report_lines.append("| Field | Confidence | Reason |")
        report_lines.append("|---|---|---|")
        for d in decisions:
            report_lines.append(f"| `{d.get('field')}` | **{d.get('confidence')}** | {d.get('reason')} |")
        report_lines.append("")

    if low_confidence:
        report_lines.append("### ⚠️ Ambiguity Report (Humans Review Required)")
        for d in low_confidence:
             report_lines.append(f"- **{d.get('field')}**: Confidence {d.get('confidence')} < 0.8. Reason: {d.get('reason')}")
        report_lines.append("")

    # 2. Execution Trace
    report_lines.append("## Execution Trace")
    for entry in trace:
        report_lines.append(f"- **{entry['step']}**: {entry['status']} ({entry.get('details')})")

    report_lines.append("")
    report_lines.append("## Final Validation Status")
    val = state.get("validation_result") or {}
    report_lines.append(f"- Valid: {val.get('valid')}")
    report_lines.append(f"- Score: {val.get('score')}")
    if val.get("issues"):
         report_lines.append("- Issues:")
         for i in val["issues"]:
             report_lines.append(f"  - [{i['severity']}] {i.get('field', 'General')}: {i['message']}")

    report_content = "\n".join(report_lines)

    # Save report
    output_dir = get_output_dir(state)
    report_path = os.path.join(output_dir, "6_report.md")
    try:
        with open(report_path, "w") as f:
            f.write(report_content)
    except Exception:
        pass

    # We update the state, but Reporter is the end usually
    return {"report_path": report_path}

# --- Graph Wiring ---

def check_validation(state: AgentState):
    """Conditional edge logic."""
    val = state.get("validation_result") or {}
    if val.get("valid", False):
        return "continue"

    if state.get("iteration_count", 0) >= 3:
        logger.warning("Max iterations reached, proceeding to report with errors.")
        return "abort"

    # Route retry to the LLM mapper when on the LLM path so that validation
    # issues are injected as feedback into the next prompt.  Deterministic
    # paths (cisco / arista) fall back to cisco_mapper as before.
    vendor = state.get("source_vendor", "cisco").lower()
    if vendor not in ("cisco", "arista"):
        return "retry_llm"
    return "retry"

def _extract_svi_interfaces(raw_config: str) -> list:
    """Extract SVI (interface Vlan) details from Cisco IOS-XE config."""
    svis = []
    blocks = re.split(r'\n(?=interface )', raw_config)
    for block in blocks:
        m = re.match(r'interface (Vlan\d+)', block)
        if not m:
            continue
        name = m.group(1)
        if re.search(r'^\s*shutdown', block, re.MULTILINE):
            continue  # skip shutdown SVIs
        ip_m = re.search(r'^\s*ip address (\S+)\s+(\S+)', block, re.MULTILINE)
        if not ip_m:
            continue  # skip SVIs without IP
        desc_m = re.search(r'^\s*description (.+)', block, re.MULTILINE)
        vrf_m = re.search(r'^\s*(?:ip )?vrf forwarding (\S+)', block, re.MULTILINE)
        helper_addrs = re.findall(r'^\s*ip helper-address (\S+)', block, re.MULTILINE)
        svis.append({
            "name": name,
            "description": desc_m.group(1).strip() if desc_m else name,
            "ip_address": ip_m.group(1),
            "subnet_mask": ip_m.group(2),
            "vrf": vrf_m.group(1) if vrf_m else "",
            "shutdown": False,
            "ip_helper_addresses": helper_addrs,
        })
    return svis


def _extract_loopback_interfaces(raw_config: str) -> list:
    """Extract Loopback interfaces from Cisco IOS-XE config."""
    loopbacks = []
    blocks = re.split(r'\n(?=interface )', raw_config)
    for block in blocks:
        m = re.match(r'interface (Loopback\d+)', block)
        if not m:
            continue
        name = m.group(1)
        ip_m = re.search(r'^\s*ip address (\S+)\s+(\S+)', block, re.MULTILINE)
        desc_m = re.search(r'^\s*description (.+)', block, re.MULTILINE)
        vrf_m = re.search(r'^\s*(?:ip )?vrf forwarding (\S+)', block, re.MULTILINE)
        loopbacks.append({
            "name": name,
            "description": desc_m.group(1).strip() if desc_m else name,
            "ip_address": ip_m.group(1) if ip_m else "",
            "subnet_mask": ip_m.group(2) if ip_m else "",
            "vrf": vrf_m.group(1) if vrf_m else "",
            "shutdown": False,
        })
    return loopbacks


def _extract_banner(raw_config: str) -> str:
    """Extract banner motd text from Cisco IOS-XE config."""
    m = re.search(r'^banner motd (\S)(.*?)\1', raw_config, re.MULTILINE | re.DOTALL)
    if m:
        return m.group(2).strip()
    return ""


def _extract_default_gateway(raw_config: str) -> str:
    """Extract ip default-gateway from config."""
    m = re.search(r'^ip default-gateway (\S+)', raw_config, re.MULTILINE)
    return m.group(1) if m else ""


def _extract_dns_servers_from_config(raw_config: str) -> list:
    """Extract DNS servers from ip name-server lines."""
    servers = []
    for m in re.finditer(r'^ip name-server (\S+)', raw_config, re.MULTILINE):
        servers.append(m.group(1))
    return servers


def _extract_nac_config(raw_config: str) -> dict:
    """Extract NAC/802.1X/RADIUS configuration from Cisco IOS-XE config.

    Returns a dict with:
      - radius_group_name: str
      - radius_servers: list of {name, ip, auth_port, acct_port, key}
      - radius_deadtime: str
      - dot1x_enabled: bool
      - coa_clients: list of {ip, key}
      - coa_port: str
      - coa_auth_type: str
      - dot1x_timeout_server: str
      - dot1x_timeout_tx_period: str
      - dot1x_max_req: str
      - dot1x_max_reauth_req: str
    """
    nac: dict = {}

    # --- RADIUS group ---
    grp_m = re.search(r'^aaa group server radius (\S+)\n((?:\s+.+\n)*)', raw_config, re.MULTILINE)
    if grp_m:
        nac["radius_group_name"] = grp_m.group(1)
        grp_body = grp_m.group(2)
        # deadtime inside group
        dt_m = re.search(r'deadtime\s+(\d+)', grp_body)
        if dt_m:
            nac["radius_deadtime"] = dt_m.group(1)

    # --- dot1x global ---
    if re.search(r'^dot1x system-auth-control', raw_config, re.MULTILINE):
        nac["dot1x_enabled"] = True

    # --- RADIUS server definitions ---
    radius_servers = []
    for srv_m in re.finditer(
        r'^radius server (\S+)\n((?:\s+.+\n)*)', raw_config, re.MULTILINE
    ):
        srv_name = srv_m.group(1)
        srv_body = srv_m.group(2)
        srv: dict = {"name": srv_name, "ip": "", "auth_port": "1645", "acct_port": "1646", "key": "need_input"}
        addr_m = re.search(r'address ipv4 (\S+)(?:\s+auth-port\s+(\d+))?(?:\s+acct-port\s+(\d+))?', srv_body)
        if addr_m:
            srv["ip"] = addr_m.group(1)
            if addr_m.group(2):
                srv["auth_port"] = addr_m.group(2)
            if addr_m.group(3):
                srv["acct_port"] = addr_m.group(3)
        key_m = re.search(r'key\s+\d+\s+(\S+)', srv_body)
        if key_m:
            srv["key"] = key_m.group(1)
        radius_servers.append(srv)
    nac["radius_servers"] = radius_servers

    # --- CoA / Dynamic Authorization ---
    coa_m = re.search(r'^aaa server radius dynamic-author\n((?:\s+.+\n)*)', raw_config, re.MULTILINE)
    if coa_m:
        coa_body = coa_m.group(1)
        coa_clients = []
        for client_m in re.finditer(r'client (\S+)(?:\s+server-key\s+\d+\s+(\S+))?', coa_body):
            coa_clients.append({"ip": client_m.group(1), "key": client_m.group(2) or "need_input"})
        nac["coa_clients"] = coa_clients
        port_m = re.search(r'port\s+(\d+)', coa_body)
        nac["coa_port"] = port_m.group(1) if port_m else "3799"
        auth_m = re.search(r'auth-type\s+(\S+)', coa_body)
        nac["coa_auth_type"] = auth_m.group(1) if auth_m else "all"

    # --- Interface-level dot1x defaults (extract from first NAC-enabled interface) ---
    intf_m = re.search(
        r'(?:dot1x timeout server-timeout\s+(\d+))',
        raw_config, re.MULTILINE
    )
    if intf_m:
        nac["dot1x_timeout_server"] = intf_m.group(1)

    tx_m = re.search(r'dot1x timeout tx-period\s+(\d+)', raw_config, re.MULTILINE)
    if tx_m:
        nac["dot1x_timeout_tx_period"] = tx_m.group(1)

    mr_m = re.search(r'dot1x max-req\s+(\d+)', raw_config, re.MULTILINE)
    if mr_m:
        nac["dot1x_max_req"] = mr_m.group(1)

    mra_m = re.search(r'dot1x max-reauth-req\s+(\d+)', raw_config, re.MULTILINE)
    if mra_m:
        nac["dot1x_max_reauth_req"] = mra_m.group(1)

    return nac if nac.get("radius_servers") or nac.get("dot1x_enabled") else {}


def agent_cisco_mapper(state: AgentState):
    """Deterministic Cisco Intent Mapper — converts legacy parser output to intent
    format, extracting SVIs, banners, and management info from raw config.
    Completely bypasses the LLM for maximum speed."""
    logger.info("--- Agent 2: Cisco Deterministic Mapper (No LLM) ---")

    legacy = state.get("legacy_parsed_data", {})
    raw_config = state.get("raw_config", "")

    # Start with the legacy parser output as the base intent
    intent = dict(legacy)

    # Extract SVIs and loopbacks from raw config (legacy parser doesn't do this)
    svis = _extract_svi_interfaces(raw_config)
    loopbacks = _extract_loopback_interfaces(raw_config)
    routed_interfaces = svis + loopbacks
    if routed_interfaces:
        intent["routed_interfaces"] = routed_interfaces

    # Extract default gateway
    default_gw = _extract_default_gateway(raw_config)
    if default_gw:
        intent["default_gateway"] = default_gw

    # Extract banner
    banner = _extract_banner(raw_config)
    if banner:
        intent["banners"] = {"motd": banner}

    # Extract DNS servers from raw config if legacy parser missed them
    if not intent.get("dns_servers"):
        dns = _extract_dns_servers_from_config(raw_config)
        if dns:
            intent["dns_servers"] = dns

    # Normalize VRF config: legacy parser may return a dict instead of a list
    vrf = intent.get("vrf_config")
    if isinstance(vrf, dict):
        intent["vrf_config"] = [vrf]

    # Filter out AutoQos ACLs — these are auto-generated by IOS and not migrated
    acls = intent.get("acls", [])
    if acls:
        filtered = [a for a in acls if not (isinstance(a, dict) and
                    str(a.get("name", "")).startswith("AutoQos"))]
        if len(filtered) < len(acls):
            logger.info(f"Filtered {len(acls) - len(filtered)} AutoQos ACLs")
        intent["acls"] = filtered

    # Enrich access interfaces with storm-control from raw config
    _enrich_storm_control(intent.get("access_interfaces", []), raw_config)

    # Extract NAC/802.1X/RADIUS config from raw config
    nac_config = _extract_nac_config(raw_config)
    if nac_config:
        intent["nac_config"] = nac_config

    # Save debug outputs
    temp_state = state.copy()
    temp_state["extracted_intent"] = intent
    save_agent_output(temp_state, "2_intent_mapper", intent, "json")
    save_agent_output(temp_state, "2_intent_metadata",
                      [{"field": "global", "confidence": 1.0, "reason": "Deterministic mapper (no LLM)"}], "json")

    n_svis = len(svis)
    n_lb = len(loopbacks)
    new_trace = append_trace(state, "Cisco Mapper", "success",
                             f"Deterministic map: {len(intent.get('vlans', []))} VLANs, "
                             f"{len(intent.get('access_interfaces', []))} access intfs, "
                             f"{n_svis} SVIs, {n_lb} loopbacks, "
                             f"{len(intent.get('acls', []))} ACLs")

    return {
        "extracted_intent": intent,
        "decision_metadata": [{"field": "global", "confidence": 1.0, "reason": "Deterministic mapper"}],
        "rag_context": "",
        "iteration_count": state.get("iteration_count", 0) + 1,
        "trace_log": new_trace,
    }


def route_by_vendor(state: AgentState):
    """Route to the correct starting agent based on source vendor.

    - Cisco devices use Legacy Parser -> Deterministic Mapper (no LLM).
    - Arista devices use a deterministic Arista parser and skip the LLM entirely.
    - Unknown vendors fall back to Legacy Parser -> LLM Intent Mapper.
    """
    vendor = state.get("source_vendor", "cisco").lower()
    if vendor == "arista":
        logger.info("Arista vendor detected — using deterministic Arista parser (skipping LLM).")
        return "arista_parser"
    elif vendor == "cisco":
        logger.info("Cisco vendor detected — using Legacy Parser + Deterministic Mapper (no LLM).")
        return "parser"
    else:
        logger.info(f"Unknown vendor '{vendor}' — using Legacy Parser + LLM Intent Mapper (fallback).")
        return "llm_parser"


def agent_arista_parser(state: AgentState):
    """Deterministic Arista EOS parser — replaces LLM for Arista devices."""
    logger.info("--- Agent 1+2: Arista Deterministic Parser ---")
    try:
        from arista_parser import AristaEOSParser
    except ImportError:
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from arista_parser import AristaEOSParser

    parser = AristaEOSParser(state["raw_config"])
    parsed = parser.parse_all()

    # Save intermediate outputs for debugging
    temp_state = state.copy()
    temp_state["extracted_intent"] = parsed
    save_agent_output(temp_state, "1_legacy_parser", parsed, "json")
    save_agent_output(temp_state, "2_intent_mapper", parsed, "json")
    save_agent_output(temp_state, "2_intent_metadata",
                      [{"field": "global", "confidence": 1.0, "reason": "Deterministic parser (no LLM)"}], "json")

    new_trace = append_trace(state, "Arista Parser", "success",
                             f"Deterministic parse: {len(parsed.get('vlans', []))} VLANs, "
                             f"{len(parsed.get('access_interfaces', []))} access intfs, "
                             f"{len(parsed.get('acls', []))} ACLs")

    return {
        "legacy_parsed_data": parsed,
        "extracted_intent": parsed,
        "decision_metadata": [{"field": "global", "confidence": 1.0, "reason": "Deterministic parser"}],
        "rag_context": "",
        "iteration_count": 1,
        "trace_log": new_trace,
    }


workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("router", lambda state: state)  # Pass-through routing node
workflow.add_node("parser", agent_legacy_parser)
workflow.add_node("llm_parser", agent_legacy_parser)  # Same parser, separate node for LLM fallback path
workflow.add_node("cisco_mapper", agent_cisco_mapper)
workflow.add_node("cisco_mapper_retry", agent_cisco_mapper)  # Same fn, different outgoing edge (→ llm_mapper)
workflow.add_node("llm_mapper", agent_intent_mapper)  # LLM-based mapper for unknown vendors
workflow.add_node("arista_parser", agent_arista_parser)
workflow.add_node("normalizer", agent_schema_normalizer)
workflow.add_node("validator", agent_validator)
workflow.add_node("generator", agent_generator)
workflow.add_node("reporter", agent_reporter)

# Set Entry to the router node
workflow.set_entry_point("router")

# Conditional routing based on vendor
workflow.add_conditional_edges(
    "router",
    route_by_vendor,
    {
        "parser": "parser",
        "arista_parser": "arista_parser",
        "llm_parser": "llm_parser",
    }
)

# Add Edges — Cisco: parser -> cisco_mapper -> normalizer (no LLM)
workflow.add_edge("parser", "cisco_mapper")
workflow.add_edge("cisco_mapper", "llm_mapper")
workflow.add_edge("arista_parser", "normalizer")  # Arista skips LLM, goes straight to normalizer
# LLM fallback: llm_parser -> llm_mapper -> normalizer
workflow.add_edge("llm_parser", "llm_mapper")
workflow.add_edge("llm_mapper", "normalizer")
# Cisco retry path: cisco_mapper_retry -> llm_mapper (LLM sees validation issues as feedback)
workflow.add_edge("cisco_mapper_retry", "llm_mapper")
workflow.add_edge("normalizer", "validator")

# Conditional Edge
workflow.add_conditional_edges(
    "validator",
    check_validation,
    {
        "continue": "generator",
        "retry": "cisco_mapper_retry",  # Cisco: re-run deterministic base then LLM refinement with feedback
        "retry_llm": "llm_mapper",      # pure LLM path — injects validation issues as feedback
        "abort": "reporter"
    }
)

# Note: retry_llm routes to llm_mapper which reads state["validation_result"].issues
# and injects them into the LLM prompt for self-correction (see agent_intent_mapper).

workflow.add_edge("generator", "reporter")
workflow.add_edge("reporter", END)

app = workflow.compile()
