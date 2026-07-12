class Rule:
    id = "106"
    description = "Verify if network_settings assigned to site are defined under network_settings data model"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            def extract_names(key):
                return [item["name"] for item in data["catalyst_center"].get("network_settings", {}).get(key, [])]

            # Reference lists
            aaa_servers_list = extract_names("aaa_servers")
            telemetry_settings_list = extract_names("telemetry")
            network_settings_list = extract_names("network")

            def check_settings(scope, obj, results):
                settings = obj.get("network_settings")
                if settings:
                    network_settings = settings.get("network", [])
                    aaa_servers = settings.get("aaa_servers", [])
                    telemetry_settings = settings.get("telemetry", [])

                    if network_settings and network_settings not in network_settings_list:
                        results.append(f"catalyst_center.sites.{scope}.network_settings.network: {network_settings} not defined under catalyst_center.network_settings.network")
                    if aaa_servers and aaa_servers not in aaa_servers_list:
                        results.append(f"catalyst_center.sites.{scope}.network_settings.aaa_servers: {aaa_servers} not defined under catalyst_center.network_settings.aaa_servers")
                    if telemetry_settings and telemetry_settings not in telemetry_settings_list:
                        results.append(f"catalyst_center.sites.{scope}.network_settings.telemetry: {telemetry_settings} not defined under catalyst_center.network_settings.telemetry")

            # Check each site type
            for scope in ["areas", "buildings", "floors"]:
                for obj in data["catalyst_center"]["sites"].get(scope, []):
                    check_settings(scope, obj, results)
        except KeyError as e:
            print(f"KeyError: {e}")
        return results
    

# UNCOMMENT TO TEST RULE LOCALLY
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
