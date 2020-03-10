import json


cleanedData = []
cleanedValidationData = []
unlabelledDesc = []

for i in range(2002,2020):
    with open('ExtractedData/nvdcve-1.1-%s.json' % i, 'r') as f:
        rawData = json.load(f)
    for cvssData in rawData["CVE_Items"]:
        if "baseMetricV3" in cvssData["impact"]:
            validData = {}
            validData['description'] = cvssData["cve"]["description"]["description_data"][0]["value"]
            validData['cvssV3'] = cvssData["impact"]["baseMetricV3"]["cvssV3"]
            cleanedData.append(validData)
        else:
            unlabelledDesc.append(cvssData["cve"]["description"]["description_data"][0]["value"])
            
    print(len(cleanedData))
    print(len(unlabelledDesc))
    print("__________________")
with open('ExtractedData/nvdcve-1.1-modified.json', 'r') as f:
    rawData = json.load(f)
for cvssData in rawData["CVE_Items"]:
    if "baseMetricV3" in cvssData["impact"]:
        validData = {}
        validData['description'] = cvssData["cve"]["description"]["description_data"][0]["value"]
        validData['cvssV3'] = cvssData["impact"]["baseMetricV3"]["cvssV3"]
        cleanedValidationData.append(validData)
    else:
        unlabelledDesc.append(cvssData["cve"]["description"]["description_data"][0]["value"])
            
with open('ExtractedData/nvdcve-1.1-recent.json', 'r') as f:
    rawData = json.load(f)
for cvssData in rawData["CVE_Items"]:
    if "baseMetricV3" in cvssData["impact"]:
        validData = {}
        validData['description'] = cvssData["cve"]["description"]["description_data"][0]["value"]
        validData['cvssV3'] = cvssData["impact"]["baseMetricV3"]["cvssV3"]
        cleanedValidationData.append(validData)
    else:
        unlabelledDesc.append(cvssData["cve"]["description"]["description_data"][0]["value"])
            
jsonOutput = {"data": cleanedData}

with open('cleanedData.json', 'w') as outfile:
    json.dump(jsonOutput, outfile)

jsonOutput = {"data": cleanedValidationData}
with open('cleanedValidationData.json', 'w') as outfile:
    json.dump(jsonOutput, outfile)

jsonOutput = {"data": unlabelledDesc}
with open('unlabelledDesc.json', 'w') as outfile:
    json.dump(jsonOutput, outfile)

