class Rule:
    id = "108"
    description = "Verify if template deployed to device is defined under templates data model"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            all_templates = []
            for template in data["catalyst_center"].get("templates",{}).get("projects",{}): 
                if template.get("dayn_templates", []):
                    for dayn_template in template["dayn_templates"]:
                        all_templates.append(dayn_template["name"])
                if template.get("onboarding_templates", []):   
                    for onboarding_template in template["onboarding_templates"]:
                        all_templates.append(onboarding_template["name"])
        
            for device in data["catalyst_center"].get("inventory",{}).get("devices",{}):
                if device.get("dayn_templates", {}).get("regular", []):
                    for dayn_template in device["dayn_templates"]["regular"]:
                        if dayn_template["name"] not in all_templates:
                            results.append(f"catalyst_center.inventory.devices.dayn_templates.regular: {dayn_template['name']} under {device['name']} not defined under catalyst_center.templates.projects.dayn_templates")
                if device.get("dayn_templates", {}).get("composite", []):
                    for dayn_template in device["dayn_templates"]["composite"]:
                        if dayn_template["name"] not in all_templates:
                            results.append(f"catalyst_center.inventory.devices.dayn_templates.composite: {dayn_template['name']} under {device['name']} not defined under catalyst_center.templates.projects.dayn_templates")
                if device.get("onboarding_template", {}):
                    if device["onboarding_template"]["name"] not in all_templates:
                        results.append(f"catalyst_center.inventory.devices.onboarding_template: {device['onboarding_template']['name']} under {device['name']} not defined under catalyst_center.templates.projects.onboarding_templates")
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
