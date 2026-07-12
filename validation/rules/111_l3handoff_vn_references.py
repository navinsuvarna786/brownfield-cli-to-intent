class Rule:
    id = "111"
    description = "Verify if Virtual Network referenced in L3 Handoff is defined under fabric_sites -> l3_virtual_networks data model"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            all_l3_vns = []
            for site in data["catalyst_center"].get("fabric", {}).get("fabric_sites", {}):
                for l3_vn in site.get("l3_virtual_networks", []):
                    all_l3_vns.append(l3_vn)
           
            for border in data["catalyst_center"].get("fabric",{}).get("border_devices",{}): 
                for l3handoff in border.get("l3_handoffs", []):
                    for interface in l3handoff.get("interfaces", []):
                        for vn in interface.get("virtual_networks", []):
                            if vn["name"] not in all_l3_vns:
                                results.append(f"catalyst_center.fabric.border_devices.l3_handoffs.interfaces.virtual_networks: {vn['name']} under handoff: {l3handoff['name']} on border: {border['name']} not defined under catalyst_center.fabric.fabric_sites.l3_virtual_networks")
        except KeyError as e:
            print(f"KeyError: {e}")
        return results
    

## UNCOMMENT TO TEST RULE LOCALLY
# import os
# from yaml.loader import SafeLoader
# import yaml
# from collections import defaultdict

# data = defaultdict(dict)
# directory = "../data"
# #directory = "../../tests/integration/fixtures/catalystcenter/standard"
# a = Rule()

# for filename in os.listdir(directory):
#     if filename.endswith(".yaml"):      
#         with open(os.path.join(directory, filename)) as file:
#             file_data = yaml.load(file, Loader=SafeLoader)
#             if file_data is not None:
#                 for key, value in file_data.items():
#                     data[key].update(value)

# print(a.match(dict(data)))
