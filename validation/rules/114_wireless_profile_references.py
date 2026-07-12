class Rule:
    id = "114"
    description = "Verify if Wireless Profile has all references defined in data model"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            all_ssids = []
            for ssid in data["catalyst_center"].get("wireless", {}).get("ssids", []):
                all_ssids.append(ssid["name"])
            
            all_floors = []
            for floor in data["catalyst_center"].get("sites",{}).get("floors",{}):  
                if floor.get("parent_name"):
                    all_floors.append(floor["parent_name"] + "/" + floor["name"])
            
            all_buildings = []
            for building in data["catalyst_center"].get("sites",{}).get("buildings",{}):  
                if building.get("parent_name"):
                    all_buildings.append(building["parent_name"] + "/" + building["name"])
            
            all_areas = []
            for area in data["catalyst_center"].get("sites",{}).get("areas",{}):  
                if area.get("parent_name"):
                    all_areas.append(area["parent_name"] + "/" + area["name"])
            
            all_sites = all_floors + all_buildings + all_areas
                    
            all_interfaces = []
            for interface in data["catalyst_center"].get("wireless", {}).get("interfaces", []):
                all_interfaces.append(interface["name"])

            all_rf_profiles = []
            for rf_profile in data["catalyst_center"].get("wireless", {}).get("rf_profiles", []):
                all_rf_profiles.append(rf_profile["name"])
            
            for profile in data["catalyst_center"].get("network_profiles", {}).get("wireless", []):
                for ap_zone in profile.get("ap_zones", []):
                    if ap_zone["rf_profile_name"] not in all_rf_profiles:
                        results.append(f"catalyst_center.network_profiles.wireless.ap_zones.rf_profile_name: {ap_zone['rf_profile_name']} not defined under catalyst_center.wireless.rf_profiles")
                    for ssid in ap_zone.get("ssids", []):
                        if ssid not in all_ssids:
                            results.append(f"catalyst_center.network_profiles.wireless.ap_zones.ssids: {ssid} not defined under catalyst_center.wireless.ssids")
                for interface in profile.get("additional_interfaces", []):
                    if interface not in all_interfaces:
                        results.append(f"catalyst_center.network_profiles.wireless.additional_interfaces: {interface} not defined under catalyst_center.wireless.interfaces")
                for site in profile.get("sites", []):
                    if site not in all_sites:
                        results.append(f"catalyst_center.network_profiles.wireless.sites: {site} not defined under catalyst_center.sites")
                for ssid in profile.get("ssid_details", []):
                    if ssid["name"] not in all_ssids:
                        results.append(f"catalyst_center.network_profiles.wireless.ssid_details: {ssid['name']} not defined under catalyst_center.wireless.ssids")
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
