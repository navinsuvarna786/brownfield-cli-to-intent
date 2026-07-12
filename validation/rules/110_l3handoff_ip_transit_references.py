class Rule:
    id = "110"
    description = "Verify if transit referenced in L3 Handoff is defined under transit data model"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            all_transits = []
            for transit in data["catalyst_center"].get("fabric",{}).get("transits",{}): 
                all_transits.append(transit["name"])
           
            for border in data["catalyst_center"].get("fabric",{}).get("border_devices",{}): 
               for l3handoff in border.get("l3_handoffs", []):
                    if l3handoff["name"] not in all_transits:
                        results.append(f"catalyst_center.fabric.border_devices.l3_handoffs: {l3handoff['name']} under {border['name']} not defined under catalyst_center.fabric.transits")
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
