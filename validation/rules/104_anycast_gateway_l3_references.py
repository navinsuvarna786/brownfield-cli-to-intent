class Rule:
    id = "104"
    description = "Verify if layer3 vn assigned under anycast gateway is defined under fabric sites l3_virtual_networks data model"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            for site in data["catalyst_center"].get("fabric", {}).get("fabric_sites", {}):
                l3_vns = []
                anycast_gateways = {}
                for anycast_gateway in site.get("anycast_gateways", []):
                    anycast_gateways[anycast_gateway["ip_pool_name"]] = anycast_gateway["l3_virtual_network"]
                for l3_vn in site.get("l3_virtual_networks", []):
                    l3_vns.append(l3_vn)
                for anycast_gateway, l3_vn in anycast_gateways.items():
                    if l3_vn not in l3_vns:
                        results.append("catalyst_center.fabric.fabric_sites.anycast_gateways.l3_virtual_network: {} in anycast_gateway - {} not defined under {} fabric site".format(l3_vn, anycast_gateway, site["name"]))
        except KeyError as e:
            print(f"KeyError: {e}")
        return results
    

## UNCOMMENT TO TEST RULE LOCALLY
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
