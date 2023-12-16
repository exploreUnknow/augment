# Importing necessary library
import re

# Function to extract specific information from a given text using regular expressions
def guohao_extract(row):
    # Check if the row contains information about allowing something to another entity
    if len(re.findall('allow[^ ]* .*? to ', row[1])):
        # Extracting relevant information using regular expressions
        aat = re.findall('allow[^ ]* (.*?) to ', row[1])[0]
        pd = row[1].split(aat)[0]
        a1 = row[1].split(aat)[1]
        rootc = ''
        vt = ''
        # Checking for additional details in the text
        if len(re.findall('(?:(?: via .*)|(?: by [a-z]+ing .*)|(?: uses? .*))', a1)):
            at = re.findall('(?:(?: via .*)|(?: by [a-z]+ing .*)|(?: uses? .*))', a1)[0]
            im = a1.replace(at, '')
        else:
            im = a1
            at = ''
        if len(re.findall('(?:(?:(?:(?:uffer)|(?:teger)) overflow)|(?:vulnerability?(?:ies)?)) in (.*) allow', pd,
                          re.DOTALL)):
            vt = re.findall('(?:((?:(?:uffer)|(?:teger)) overflow)|(?:vulnerability?(?:ies)?)) in (?:.*) allow', pd,
                            re.DOTALL)[0]
            pd = re.findall('(?:(?:(?:(?:uffer)|(?:teger)) overflow)|(?:vulnerability?(?:ies)?)) in (.*) allow', pd,
                            re.DOTALL)[0]
        if len(re.findall(
                '(?:(?: fails? to )|(?: automatically )|(?: when )|(?: have )|(?: has )|(?: does )|(?: do )|(?: uses? )|(?: returns? )|(?: creates? )|(?: provides? )|(?: relies? )|(?: places? )|(?: generates? )|(?: advertises )|(?: mishandles )|(?: store SSH )|(?: lets? )|(?: handles )|(?: using )|(?: lets? )).*',
                pd)):
            rootc = re.findall(
                '(?:(?: fails? to )|(?: automatically )|(?: when )|(?: have )|(?: has )|(?: does )|(?: do )|(?: uses? )|(?: returns? )|(?: creates? )|(?: provides? )|(?: relies? )|(?: places? )|(?: generates? )|(?: advertises )|(?: mishandles )|(?: store SSH )|(?: lets? )|(?: handles )|(?: using )|(?: lets? )).*',
                pd)[0]
            pd = pd.split(rootc)[0]
        if at == '':
            if len(re.findall(
                    '\A(?:(?:use )|(?:send )|(?:supply )|(?:specially )|(?:upload )|(?:create )|(?:construct )|(?:compromise )).*? to',
                    im)):
                at = re.findall(
                    '\A(?:(?:use )|(?:send )|(?:supply )|(?:specially )|(?:upload )|(?:create )|(?:construct )|(?:compromise )).*? to',
                    im)[0]
                im = im.split(at)[-1]
    
        dt = []
        dt.append(row[0])
        dt.append(pd)
        dt.append(aat)
        dt.append(rootc)
        dt.append(im)
        dt.append(at)
        return dt
    else:
        return []

# Function to extract key aspects from a given text
def key_extract(t):
    # Initialize a text list for processing
    text = ['1', t]
    # Use guohao_extract function to extract information
    a = guohao_extract(text)
    # Check if extraction was successful
    if a == []:
        return {'vulnerability description': t}
    else:
        # Extracted information from the result
        vulner = a[1]
        attacker_type = a[2]
        root_cause = a[3]
        impact = a[4]
        attack_vector = a[5]
        # Create a dictionary to store the extracted information
        res = {'vulnerability description': t}
        if vulner != '':
            res['vulnerability_type'] = vulner
        if attacker_type != '':
            res['attacker_type'] = attacker_type
        if root_cause != '':
            res['root_cause'] = root_cause
        if impact != '':
            res['impact'] = impact
        if attack_vector != '':
            res['attack_vector'] = attack_vector
        return res
