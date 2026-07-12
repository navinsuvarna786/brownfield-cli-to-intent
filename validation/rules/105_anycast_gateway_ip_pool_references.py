class Rule:
    id = "105"
    description = "Verify if name of anycast gateway is matching name of IP pool"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            ip_pools = []
            for pool in data["catalyst_center"].get("network_settings", {}).get("ip_pools", {}):
                for subpool in pool.get("ip_pools_reservations", []):
                    ip_pools.append(subpool["name"])
            for site in data["catalyst_center"].get("fabric", {}).get("fabric_sites", {}):
                for anycast_gateway in site.get("anycast_gateways", []):
                    if anycast_gateway["ip_pool_name"] not in ip_pools:
                        results.append("catalyst_center.fabric.fabric_sites.anycast_gateways.ip_pool_name: {} not matching any of pool names defined under network_settings.ip_pools.ip_pools_reservations".format(anycast_gateway["ip_pool_name"]))
        except KeyError as e:
            print(f"KeyError: {e}")
        return results
    

# UNCOMMENT TO TEST RULE LOCALLY
# import os
# from yaml.loader import SafeLoader
# import yaml
# from collections import defaultdict

# data = defaultdict(dict)
# directory = "../../tests/integration/fixtures/catalystcenter/standard"
# a = Rule()

# for filename in os.listdir(directory):
#     if filename.endswith(".yaml"):      
#         with open(os.path.join(directory, filename)) as file:
#             file_data = yaml.load(file, Loader=SafeLoader)
#             if file_data is not None:
#                 for key, value in file_data.items():
#                     data[key].update(value)

# print(a.match(dict(data)))
