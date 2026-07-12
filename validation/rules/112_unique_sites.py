class Rule:
    id = "112"
    description = "Verify unique site names"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            all_floors = []
            for floor in data["catalyst_center"].get("sites",{}).get("floors",{}):  
                if floor.get("parent_name"):
                    all_floors.append(floor["parent_name"] + "/" + floor["name"])

            duplicated_floors = list(set([item for item in all_floors if all_floors.count(item) > 1]))

            for i in duplicated_floors:
                results.append(f"catalyst_center.sites.floors.name: {i} is duplicated") 

            all_buildings = []
            for building in data["catalyst_center"].get("sites",{}).get("buildings",{}):  
                if building.get("parent_name"):
                    all_buildings.append(building["parent_name"] + "/" + building["name"])

            duplicated_buildings = list(set([item for item in all_buildings if all_buildings.count(item) > 1]))

            for i in duplicated_buildings:
                results.append(f"catalyst_center.sites.buildings.name: {i} is duplicated")

            all_areas = []
            for area in data["catalyst_center"].get("sites",{}).get("areas",{}):  
                if area.get("parent_name"):
                    all_areas.append(area["parent_name"] + "/" + area["name"])

            duplicated_areas = list(set([item for item in all_areas if all_areas.count(item) > 1]))

            for i in duplicated_areas:
                results.append(f"catalyst_center.sites.areas.name: {i} is duplicated")

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
