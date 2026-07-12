class Rule:
    id = "101"
    description = "Verify unique keys"
    severity = "HIGH"

    paths = [
        "catalyst_center.inventory.devices.name",
        "catalyst_center.fabric.transits.name",
        "catalyst_center.fabric.fabric_sites.name",
        "catalyst_center.fabric.l3_virtual_networks.name",
        "catalyst_center.fabric.fabric_sites.anycast_gateways.ip_pool_name",
        "catalyst_center.fabric.border_devices.name",
        "catalyst_center.fabric.border_devices.l3_handoffs.name",
        "catalyst_center.fabric.border_devices.l2_handoffs.name",
        "catalyst_center.lan_automation.name",
        "catalyst_center.network_profiles.switching.name",
        "catalyst_center.network_profiles.wireless.name",
        "catalyst_center.network_settings.network.name",
        "catalyst_center.network_settings.device_credentials.cli_credentials.name",
        "catalyst_center.network_settings.device_credentials.snmpv2_read_credentials.name",
        "catalyst_center.network_settings.device_credentials.snmpv2_write_credentials.name",
        "catalyst_center.network_settings.device_credentials.snmpv3.name",
        "catalyst_center.network_settings.ip_pools.name",
        "catalyst_center.network_settings.ip_pools.ip_pools_reservations.name",
        "catalyst_center.templates.tags.name",
        "catalyst_center.templates.projects.name",
        "catalyst_center.templates.projects.onboarding_templates.name",
        "catalyst_center.templates.projects.dayn_templates.name",
    ]

    @classmethod
    def match_path(cls, inventory, full_path, search_path):
        results = []
        path_elements = search_path.split(".")
        inv_element = inventory
        for idx, path_element in enumerate(path_elements[:-1]):
            if isinstance(inv_element, dict):
                inv_element = inv_element.get(path_element)
            elif isinstance(inv_element, list):
                for i in inv_element:
                    r = cls.match_path(i, full_path, ".".join(path_elements[idx:]))
                    results.extend(r)
                return results
            if inv_element is None:
                return results
        values = []
        if isinstance(inv_element, list):
            for i in inv_element:
                if not isinstance(i, dict):
                    continue
                value = i.get(path_elements[-1])
                if isinstance(value, list):
                    values = []
                    for v in value:
                        if v not in values:
                            values.append(v)
                        else:
                            results.append(full_path + " - " + str(v))
                elif value:
                    if value not in values:
                        values.append(value)
                    else:
                        results.append(full_path + " - " + str(value))
        elif isinstance(inv_element, dict):
            list_element = inv_element.get(path_elements[-1])
            if isinstance(list_element, list):
                for value in list_element:
                    if value:
                        if value not in values:
                            values.append(value)
                        else:
                            results.append(full_path + " - " + str(value))
        return results

    @classmethod
    def match(cls, inventory):
        results = []
        for path in cls.paths:
            r = cls.match_path(inventory, path, path)
            results.extend(r)
        return results
