class Rule:
    id = "113"
    description = "Verify if referred SDA-Transit is configured as part of Fabric Transit data model"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            all_sda_transits_defined = []


            for sda_transits_defined in data["catalyst_center"].get("fabric", {}).get("transits", {}):
                if (sda_transits_defined.get("type") == "SDA_LISP_PUB_SUB_TRANSIT") or (sda_transits_defined.get("type") == "SDA_LISP_BGP_TRANSIT"):
                    all_sda_transits_defined.append(sda_transits_defined.get("name"))


            for border_device in data["catalyst_center"].get("fabric", {}).get("border_devices", {}):
                if border_device.get("sda_transit") is not None:
                    if border_device['sda_transit'] not in all_sda_transits_defined:
                        results.append(f"catalyst_center.fabric.border_devices.sda_transit: {border_device['sda_transit']} under border_device: {border_device['name']} is not defined under catalyst_center.fabric.transits")

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
