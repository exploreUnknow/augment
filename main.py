# -*- coding: utf-8 -*-

import pickle
# from predict_fun import predict_vulnerability_type, predict_attack_vector, predict_root_cause,\
#     predict_impact, check_vulnerability_type, check_attack_vector,check_root_cause,check_impact,\
#         check_attacker_type
from predict_fun1 import predict_vulnerability_type, predict_attack_vector, predict_root_cause,\
    predict_impact, check_vulnerability_type, check_attack_vector,check_root_cause,check_impact,\
        check_attacker_type
import random
from extract_suoan1 import get_key_aspect_suoan

from guohao_extract import key_extract      
       

# Load CVE data from a pickle file
with open('2023_test_data_CVE.data', 'rb') as f:
    data = pickle.load(f)

# Shuffle the data randomly
random.shuffle(data)

# Initialize lists to store vulnerability data and answers
vulner_x = []  # List to store vulnerability descriptions
vulner_y = []  # List to store corresponding vulnerability type answers

# Collect vulnerability data and answers
for i in data:
    if i['vulnerability_type'] != '':
        vulner_x.append(i['vulnerability_type'])
        vulner_y.append(i['vulnerability_type_answer'])

# Initialize variables for storing results
ans = []  # List to store results
s = 0    # Counter for successful processing

# Process each vulnerability entry
for i in vulner_x:
    s += 1
    suoan = get_key_aspect_suoan(i)  # Extract key aspects using suoan
    guohao = key_extract(i)         # Extract key aspects using guohao

    # Check for new aspects in guohao and add them to suoan
    new_list = [item for item in guohao if item not in suoan]
    for j in new_list:
        suoan[j] = guohao[j]

    # Remove 'vulnerability_type' from suoan if present
    if 'vulnerability_type' in suoan:
        suoan.pop('vulnerability_type')

    # Check the accuracy of predicting vulnerability types
    res, number, cot = check_vulnerability_type(suoan)  # Custom function to check accuracy

    # Append results to the ans list
    ans.append([i, res, number, cot])

    # Print success message for each processed entry
    print('成功：', s)

# Initialize lists to store attacker type data and answers
vulner_x = []  # List to store attacker type descriptions
vulner_y = []  # List to store corresponding attacker type answers

# Collect attacker type data and answers
for i in data:
    if i['attacker_type'] != '':
        vulner_x.append(i['attacker_type'])
        vulner_y.append(i['attacker_type_answer'])

# Initialize variables for storing results
ans = []  # List to store results
s = 0    # Counter for successful processing

# Process each attacker type entry
for i in vulner_x:
    s += 1
    suoan = get_key_aspect_suoan(i)  # Extract key aspects using suoan
    guohao = key_extract(i)         # Extract key aspects using guohao

    # Check for new aspects in guohao and add them to suoan
    new_list = [item for item in guohao if item not in suoan]
    for j in new_list:
        suoan[j] = guohao[j]

    # Remove 'attacker_type' from suoan if present
    if 'attacker_type' in suoan:
        suoan.pop('attacker_type')

    # Check the accuracy of predicting attacker types
    res, number, cot = check_attacker_type(suoan)  # Custom function to check accuracy

    # Append results to the ans list
    ans.append([i, res, number, cot])

    # Print success message for each processed entry
    print('成功：', s)


# Initialize lists to store attack vector data and answers
vulner_x = []  # List to store attack vector descriptions
vulner_y = []  # List to store corresponding attack vector answers

# Collect attack vector data and answers
for i in data:
    if i['attack_vector'] != '':
        vulner_x.append(i['attack_vector'])
        vulner_y.append(i['attack_vector_answer'])

# Initialize variables for storing results
ans = []  # List to store results
s = 0    # Counter for successful processing

# Process each attack vector entry
for i in vulner_x:
    s += 1
    suoan = get_key_aspect_suoan(i)  # Extract key aspects using suoan
    guohao = key_extract(i)         # Extract key aspects using guohao

    # Check for new aspects in guohao and add them to suoan
    new_list = [item for item in guohao if item not in suoan]
    for j in new_list:
        suoan[j] = guohao[j]

    # Remove 'attack_vector' from suoan if present
    if 'attack_vector' in suoan:       
        suoan.pop('attack_vector')

    # Check the accuracy of predicting attack vectors
    res, number, cot = check_attack_vector(suoan)  # Custom function to check accuracy

    # Append results to the ans list
    ans.append([i, res, number, cot])

    # Print success message for each processed entry
    print('成功：', s)
# Initialize lists to store root cause data and answers
vulner_x = []  # List to store root cause descriptions
vulner_y = []  # List to store corresponding root cause answers

# Collect root cause data and answers
for i in data:
    if i['root_cause'] != '':
        vulner_x.append(i['root_cause'])
        vulner_y.append(i['root_cause_answer'])

# Initialize variables for storing results
ans = []  # List to store results
s = 0    # Counter for successful processing

# Process each root cause entry
for i in vulner_x:
    s += 1
    suoan = get_key_aspect_suoan(i)  # Extract key aspects using suoan
    guohao = key_extract(i)         # Extract key aspects using guohao

    # Check for new aspects in guohao and add them to suoan
    new_list = [item for item in guohao if item not in suoan]
    for j in new_list:
        suoan[j] = guohao[j]

    # Remove 'root_cause' from suoan if present
    if 'root_cause' in suoan:      
        suoan.pop('root_cause')

    # Check the accuracy of predicting root causes
    res, number, cot = check_root_cause(suoan)  # Custom function to check accuracy

    # Append results to the ans list
    ans.append([i, res, number, cot])

    # Print success message for each processed entry
    print('成功：', s)
# Initialize lists to store impact data and answers
vulner_x = []  # List to store impact descriptions
vulner_y = []  # List to store corresponding impact answers

# Collect impact data and answers
for i in data:
    if i['impact'] != '':
        vulner_x.append(i['impact'])
        vulner_y.append(i['impact_answer'])

# Initialize variables for storing results
ans = []  # List to store results
s = 0    # Counter for successful processing

# Process each impact entry
for i in vulner_x:
    s += 1
    suoan = get_key_aspect_suoan(i)  # Extract key aspects using suoan
    guohao = key_extract(i)         # Extract key aspects using guohao

    # Check for new aspects in guohao and add them to suoan
    new_list = [item for item in guohao if item not in suoan]
    for j in new_list:
        suoan[j] = guohao[j]

    # Remove 'impact' from suoan if present
    if 'impact' in suoan: 
        suoan.pop('impact')

    # Check the accuracy of predicting impacts
    res, number, cot = check_root_cause(suoan)  # Custom function to check accuracy

    # Append results to the ans list
    ans.append([i, res, number, cot])

    # Print success message for each processed entry
    print('成功：', s)
