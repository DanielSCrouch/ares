
import csv
import glob

# load in nessus plugin to service csv translation
translation_tb_path = glob.glob("nessus_scan_plugin_to_service.csv")
with open(translation_tb_path[0]) as f:
    list_of_dicts = [{pid:val for pid,val in row.items()} \
                   for row in csv.DictReader(f, skipinitialspace=True)]
translation = {}
for i in range(len(list_of_dicts)):
    translation[list_of_dicts[i]["Plugin"]] = list_of_dicts[i]["Service"]


def get_service(plugin):
    """
    Get service name from plugin id, return None if no match found
    """
    plugin = str(plugin)
    if plugin in translation.keys():
        return translation[plugin]
    else:
        return None
