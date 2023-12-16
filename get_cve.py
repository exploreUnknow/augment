# -*- coding: utf-8 -*-

import pandas as pd

import xml.etree.ElementTree as ET
from suoan_extract.extract_suoan import get_key_aspect_suoan

# Parse XML file
tree = ET.parse("allitems.xml")
root = tree.getroot()

# Define namespaces and namespace prefixes
namespaces = {
    'xmlns': 'http://cve.mitre.org/cve/downloads/1.0',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
}

all_data_cve = []

# Traverse each <item> element and check its node name
for item in root.findall(".//xmlns:item", namespaces):
    # Extract CVE name and description from each <item>
    name = item.get("name")
    desc = item.find(".//xmlns:desc", namespaces).text
    
    # Filter CVEs for the year 2023
    if '2023-' in name:
        all_data_cve.append([name, desc])

# List to store key aspects for each CVE
key_aspect = []

# Extract key aspects for each CVE using the get_key_aspect_suoan function
for i in all_data_cve:
    key_aspect.append(get_key_aspect_suoan(i[1]))
