import json

with open('./abi.json') as json_file:
	data = json.load(json_file)


with open('./final_abi.json') as final_json_file:
	fData = json.load(final_json_file);