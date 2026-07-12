class Rule:
    id = "107"
    description = "Verify if parent_name attribute has site hierarchy name which was already defined"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            all_sites_hierarchy = ["Global"]
            for area in data["catalyst_center"].get("sites",{}).get("areas",{}): 
                if area["name"] == "Global":
                    all_sites_hierarchy.append(area["name"])
                else:
                    if area.get("parent_name"):
                        all_sites_hierarchy.append(area["parent_name"] + "/" + area["name"])
            for building in data["catalyst_center"].get("sites",{}).get("buildings",{}):  
                if building.get("parent_name"):
                    all_sites_hierarchy.append(building["parent_name"] + "/" + building["name"])
            for floor in data["catalyst_center"].get("sites",{}).get("floors",{}):  
                if floor.get("parent_name"):
                    all_sites_hierarchy.append(floor["parent_name"] + "/" + floor["name"])
            for area in data["catalyst_center"].get("sites",{}).get("areas",{}): 
                if area.get("parent_name", {}) and area["parent_name"] not in all_sites_hierarchy:
                    results.append(f"catalyst_center.sites.areas.parent_name: {area['parent_name']} not defined under sites hierarchy")
            for building in data["catalyst_center"].get("sites",{}).get("buildings",{}):
                if building.get("parent_name", {}) and building["parent_name"] not in all_sites_hierarchy:
                    results.append(f"catalyst_center.sites.buildings.parent_name: {building['parent_name']} not defined under sites hierarchy")
            for floor in data["catalyst_center"].get("sites",{}).get("floors",{}):
                if floor.get("parent_name", {}) and floor["parent_name"] not in all_sites_hierarchy:
                    results.append(f"catalyst_center.sites.floors.parent_name: {floor['parent_name']} not defined under sites hierarchy")             
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
