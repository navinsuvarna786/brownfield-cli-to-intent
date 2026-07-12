import os
import logging
from typing import Optional, Any
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

logging.getLogger("netmiko").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

def fetch_config_from_device(
    ip: str, 
    username: str, 
    password: str, 
    secret: Optional[str] = None, 
    device_type: str = "cisco_ios",
    port: int = 22
) -> str:
    """
    Connects to a network device via SSH using Netmiko and retrieves the running configuration.
    
    Args:
        ip (str): Device IP address or hostname.
        username (str): SSH username.
        password (str): SSH password.
        secret (str, optional): Enable secret. Defaults to password if not provided.
        device_type (str, optional): Netmiko device type (e.g., 'cisco_ios', 'cisco_nxos'). Defaults to 'cisco_ios'.
        port (int, optional): SSH port. Defaults to 22.

    Returns:
        str: The full running configuration of the device.

    Raises:
        ConnectionError: If connection fails or authentication fails.
    """
    
    device_params = {
        'device_type': device_type,
        'ip': ip,
        'username': username,
        'password': password,
        'secret': secret if secret else password,
        'port': port,
        'timeout': 30  # Connection timeout
    }
    
    logger.info(f"Connecting to {ip} ({device_type})...")
    
    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            logger.info(f"Connected to {ip}. Fetching running config...")
            
            result: Any = None
            # Consider specific commands for different OS if needed, but 'show run' is standard for IOS/NExus
            if "juniper" in device_type:
                 result = net_connect.send_command("show configuration", read_timeout=60)
            else:
                 result = net_connect.send_command("show running-config", read_timeout=60)
            
            # Ensure result is a string (Netmiko usually returns str, but typing might be vague)
            if isinstance(result, str):
                return result
            if result is None:
                raise ValueError("No configuration returned")
            return str(result)
            
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        error_msg = f"Failed to connect to {ip}: {str(e)}"
        logger.error(error_msg)
        raise ConnectionError(error_msg)
    except Exception as e:
        error_msg = f"Error fetching config from {ip}: {str(e)}"
        logger.error(error_msg)
        raise ConnectionError(error_msg)
