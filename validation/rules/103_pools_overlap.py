import ipaddress

class Rule:
    id = "103"
    description = "Verify IP Pool subnet overlap"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            pools_subnets = []
            for pool in data["catalyst_center"]["network_settings"]["ip_pools"]:
                pools_subnets.append(ipaddress.ip_network(pool["ip_pool_cidr"], strict=False))
            for idx, subnet in enumerate(pools_subnets):
                if idx + 1 >= len(pools_subnets):
                    break
                for other_subnet in pools_subnets[idx + 1 :]:
                    if subnet.overlaps(other_subnet):
                        results.append("catalyst_center.network_settings.ip_pools.ip_pool_cidr: {} - {}".format(subnet, pool['name']))  # type: ignore
        except KeyError:
            pass
        return results