# -*- coding: utf-8 -*-

import pandas as pd
import xml.etree.ElementTree as ET
from extract_suoan import get_key_aspect_suoan
from guohan_extarct import key_extract
import pickle

# Parse the XML file containing CVE information
tree = ET.parse("allitems.xml")
root = tree.getroot()

# Define XML namespaces
namespaces = {
    'xmlns': 'http://cve.mitre.org/cve/downloads/1.0',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
}

# Store CVE data
all_data_cve = []

# Iterate through each <item> element in the XML
for item in root.findall(".//xmlns:item", namespaces):
    name = item.get("name")
    desc = item.find(".//xmlns:desc", namespaces).text
    # Include only data from the year 2023
    if '2023-' in name:
        all_data_cve.append([name, desc])

# Store key aspects extracted from vulnerability descriptions
key_aspect = []
s = 0

# Iterate through CVE data
for i in all_data_cve:
    s += 1
    try:
        print('================================================')
        # Extract key aspects using two different methods
        suoan = get_key_aspect_suoan(i[1])
        guohao = key_extract(i[1])
        
        # Fill in missing aspects using information from both methods
        for j in suoan:
            if suoan[j] == '':
                suoan[j] = guohao[j]
        
        suoan['id'] = i[0]
        key_aspect.append(suoan)
        
        # Save key aspects every 100 iterations
        if s % 100 == 1:
            with open('key_aspect_2023.data', 'wb') as f:
                pickle.dump(key_aspect, f)
        print('================================================')
    except Exception as e:
        print('Error:', e)

# Processed data for testing
all_data = []

# Iterate through key aspects
for i in key_aspect:
    desc = i['vulnerability_description']
    vulnerability_type = i['vulnerability_type']
    attacker_type = i['attacker_type']
    attack_vector = i['attack_vector']
    root_cause = i['root_cause']
    impact = i['impact']
    
    temp = {}

    # Replace specific terms in descriptions with corresponding labels
    if vulnerability_type != '':
        temp['vulnerability_type'] = desc.replace(vulnerability_type, 'unknown vulnerability type')
        temp['vulnerability_type_answer'] = vulnerability_type
    else:
        temp['vulnerability_type'] = ''
        temp['vulnerability_type_answer'] = ''
    
    if attacker_type != '':
        temp['attacker_type'] = desc.replace(attacker_type, 'unknown attacker type')
        temp['attacker_type_answer'] = attacker_type
    else:
        temp['attacker_type'] = ''
        temp['attacker_type_answer'] = ''
    
    if attack_vector != '':
        temp['attack_vector'] = desc.replace(attack_vector, 'unknown attack vector')
        temp['attack_vector_answer'] = attack_vector
    else:
        temp['attack_vector'] = ''
        temp['attack_vector_answer'] = ''
    
    if root_cause != '':
        temp['root_cause'] = desc.replace(root_cause, 'unknown root_cause')
        temp['root_cause_answer'] = root_cause
    else:
        temp['root_cause'] = ''
        temp['root_cause_answer'] = ''
    
    if impact != '':
        temp['impact'] = desc.replace(impact, 'unknown impact')
        temp['impact_answer'] = impact
    else:
        temp['impact'] = ''
        temp['impact_answer'] = ''
    
    all_data.append(temp)

# Save the processed data for testing
with open('2023_test_data_CVE.data', 'wb') as f:
    pickle.dump(all_data, f)

# Read NVD data from CSV file
nvd_data = pd.read_csv('NVDanalysis.csv', header=None)
cveid = nvd_data[0].tolist()
desc_analysis = nvd_data[1].tolist()

# Store NVD data
data = []

# Create a dataset for NVD testing
for i in range(len(desc_analysis)):
    if type(desc_analysis[i]) != float:
        data.append([cveid[i], desc_analysis[i].replace('Analysis Description\n', '')])

# Store modified data
id_list = [i[0] for i in all_data_cve]
desc_list = [i[1] for i in all_data_cve]
id_analysis_midify = []

# Create a list of modified data
for i in data:
    id_analysis_midify.append([i[0], i[1], desc_list[id_list.index(i[0])]])

# Store NVD test data
nvd_test_data = []
tt = []

# Process NVD test data
for i in id_analysis_midify:
    label = {}
    old = i[1]
    new = i[2]
    suoan = get_key_aspect_suoan(old)
    guohao = key_extract(old)
    
    # Fill in missing aspects using information from both methods
    for j in suoan:
        if suoan[j] == '':
            suoan[j] = guohao[j]
    
    old_key_aspect = suoan
    suoan = get_key_aspect_suoan(new)
    guohao = key_extract(new)
    
    # Fill in missing aspects using information from both methods
    for j in suoan:
        if suoan[j] == '':
            suoan[j] = guohao[j]
    
    new_key_aspect = suoan
    
    # Label differences between old and new descriptions
    if old_key_aspect['vulnerability_type'] == '' and new_key_aspect['vulnerability_type'] != '':
        label['vulnerability_type'] = new_key_aspect['vulnerability_type']
    if old_key_aspect['attacker_type'] == '' and new_key_aspect['attacker_type'] != '':
        label['attacker_type'] = new_key_aspect['attacker_type']
    if old_key_aspect['attack_vector'] == '' and new_key_aspect['attack_vector'] != '':
        label['attack_vector'] = new_key_aspect['attack_vector']
    if old_key_aspect['root_cause'] == '' and new_key_aspect['root_cause'] != '':
        label['root_cause'] = new_key_aspect['root_cause']
    if old_key_aspect['impact'] == '' and new_key_aspect['impact'] != '':
        label['impact'] = new_key_aspect['impact']
    
    nvd_test_data.append([i[0], i[1], label, old_key_aspect, new_key_aspect])

# Collect instances with labeled differences
for i in nvd_test_data:
    if i[2] != {}:
        tt.append(i)
