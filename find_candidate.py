# -*- coding: utf-8 -*-

import numpy as np
import spacy
import os
import openai
import re
from guohan_extarct import guohao_extract
openai.api_key = "sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
import numpy as np

def euclideanDist(A, B):
    """Calculate the Euclidean distance between points A and B."""
    return np.sqrt(sum((A - B) ** 2))

def RandomCenters(dataSet, k):
    """Initialize k random centers from the dataset."""
    n = dataSet.shape[0]
    centerIndex = np.random.choice(range(n), size=k, replace=False)
    centers = dataSet[centerIndex]
    return centers

def KMeans(dataSet, k):
    """Perform K-Means clustering on the dataset."""
    Centers = RandomCenters(dataSet, k)
    n, m = dataSet.shape
    DistMatrix = np.zeros((n, 2))  # n*2 matrix to store cluster indices
    centerChanged = True
    
    while centerChanged:
        centerChanged = False
        for i in range(n):
            minDist = np.inf
            minIndex = -1
            for j in range(k):
                dist = euclideanDist(dataSet[i, :], Centers[j, :])
                if dist < minDist:    # Update the closest cluster center
                    minDist = dist
                    minIndex = j
            if DistMatrix[i, 0] != minIndex:
                centerChanged = True
            DistMatrix[i, 0] = minIndex   # Store the index
            DistMatrix[i, 1] = minDist    # Store the distance

        if centerChanged:  # If cluster centers have changed, update them
            for i in range(k):
                dataMean = dataSet[DistMatrix[:, 0] == i]
                Centers[i] = np.mean(dataMean, axis=0)
    
    return Centers, DistMatrix

def PointSelection(DistMatrix, k, n):
    """Select one point from each cluster based on minimum distance."""
    points = []
    for i in range(k):
        minDist = np.inf
        closeIndex = -1
        for j in range(n):
            if DistMatrix[j, 0] == i:
                if DistMatrix[j, 1] < minDist:
                    minDist = DistMatrix[j, 1]
                    closeIndex = j
        points.append(closeIndex)
    return points

def condidate(sentence, data_des, all_aspect, target_key_aspect):
    scout = 0
    cve_example = sentence
    number = {}
    des_aspect = {}

    # Calculate the number of matching aspects for each CVE description
    for i in range(len(all_aspect)):
        n = 0
        temp = [j[0] for j in all_aspect[i]]
        for j in temp:
            if j in cve_example:
                n += 1
        number[data_des[i]] = n
        des_aspect[data_des[i]] = all_aspect[i]

    cve_example_similary = []
    max_number = max(number.values())

    # Select CVE examples with similar aspects
    for i in number:
        if number[i] >= max_number - 1:
            if target_key_aspect in [d[1] for d in des_aspect[i]]:
                cve_example_similary.append([i, des_aspect[i]])

    c = 0
    temp_c = []

    # Adjust the number of selected examples for a balanced range
    while len(cve_example_similary) < 10 or len(cve_example_similary) > 3000:
        temp_c.append(len(cve_example_similary))
        if c > max_number:
            scout = 1
            break
        else:
            cve_example_similary = []
            max_number = max(number.values())
            for i in number:
                if number[i] >= max_number - c:
                    if target_key_aspect in [d[1] for d in des_aspect[i]]:
                        cve_example_similary.append([i, des_aspect[i]])

            c += 1

    if scout == 1:
        return {"resCode": "1", "message": "success", "data": '找不到跟它相似的，跳过'}

    # Convert selected CVE examples to dictionaries for better readability
    cve_example_similary_dic = []
    for i in cve_example_similary:
        temp = {}
        for j in i[1]:
            temp[j[1]] = j[0]
        cve_example_similary_dic.append([i[0], temp])

    # Use spaCy for text embeddings
    data = [i[0] for i in cve_example_similary_dic]
    nlp = spacy.load("en_core_web_lg")
    emb_data = [nlp(i).vector for i in data]

    X = emb_data
    n = len(X)
    k = 10

    # Apply K-Means clustering
    Center, DistMat = KMeans(np.array(emb_data), k)
    Points = PointSelection(DistMat, k, n)
    sentences = [cve_example_similary_dic[i] for i in Points]

    return sentences

def condidate_v1(sentence, all_aspect_dic):
    cve_example = sentence

    cve_example_similary = []

    # Check for matching aspects (affected_product and vulnerability_type) in the provided dictionary
    for i in range(len(all_aspect_dic)):
        if 'affected_product' in all_aspect_dic[i] and 'vulnerability_type' in all_aspect_dic[i]:
            product = all_aspect_dic[i]['affected_product']
            vulnerability_type = all_aspect_dic[i]['vulnerability_type']
            if product in cve_example and vulnerability_type in cve_example:
                cve_example_similary.append(all_aspect_dic[i])

    return cve_example_similary

product_names = []
with open('CPE_DICT_PRODUCT.txt', 'r') as f:
    for i in f.readlines():
        product_names.append(i.replace('\n',''))    
def condidate_v2(sentence, data_des, all_aspect, target_key_aspect, target_key_aspect1):
    if target_key_aspect == 'affected_product':
        cve_example = sentence.lower()
        match_name = ''

        # Find the best matching product name from the provided list
        for name in product_names:
            if name in cve_example and len(name) > len(match_name):
                match_name = name

        des_aspect = {}
        cve_example_similary = []

        # Check for matching aspects in the provided list
        for i in range(len(all_aspect)):
            for j in all_aspect[i]:
                if j[1] == 'affected_product':
                    if j[0].lower() in match_name and target_key_aspect1 in [a[1] for a in all_aspect[i]]:
                        cve_example_similary.append([data_des[i], all_aspect[i]])

        if len(cve_example_similary) == 0:
            return {"resCode": "1", "message": "success", "data": '找不到跟它相似的，跳过'}
        else:
            # Convert selected CVE examples to dictionaries for better readability
            cve_example_similary_dic = []
            for i in cve_example_similary:
                temp = {}
                for j in i[1]:
                    temp[j[1]] = j[0]
                cve_example_similary_dic.append([i[0], temp])

            if len(cve_example_similary) <= 10:
                return cve_example_similary_dic
            else:
                data = [i[0] for i in cve_example_similary_dic]
                nlp = spacy.load("en_core_web_lg")
                emb_data = [nlp(i).vector for i in data]

                X = emb_data
                n = len(X)
                k = 10

                # Apply K-Means clustering
                Center, DistMat = KMeans(np.array(emb_data), k)
                Points = PointSelection(DistMat, k, n)
                sentences = [cve_example_similary_dic[i] for i in Points]

                return sentences
    else:
        scout = 0
        cve_example = sentence
        number = {}
        des_aspect = {}

        # Calculate the number of matching aspects for each CVE description
        for i in range(len(all_aspect)):
            n = 0
            temp = [j[0] for j in all_aspect[i]]
            for j in temp:
                if j in cve_example:
                    n += 1
            number[data_des[i]] = n
            des_aspect[data_des[i]] = all_aspect[i]

        cve_example_similary = []
        max_number = max(number.values())

        # Select CVE examples with similar aspects
        for i in number:
            if number[i] >= max_number - 1:
                if target_key_aspect in [d[1] for d in des_aspect[i]]:
                    cve_example_similary.append([i, des_aspect[i]])

        c = 0

        while len(cve_example_similary) < 10 or len(cve_example_similary) > 3000:
            if c > max_number:
                scout = 1
                break
            else:
                cve_example_similary = []
                max_number = max(number.values())
                for i in number:
                    if number[i] >= max_number - c:
                        if target_key_aspect in [d[1] for d in des_aspect[i]]:
                            cve_example_similary.append([i, des_aspect[i]])

                c += 1

        if scout == 1:
            return {"resCode": "1", "message": "success", "data": '找不到跟它相似的，跳过'}

        # Convert selected CVE examples to dictionaries for better readability
        cve_example_similary_dic = []
        for i in cve_example_similary:
            temp = {}
            for j in i[1]:
                temp[j[1]] = j[0]
            cve_example_similary_dic.append([i[0], temp])

        data = [i[0] for i in cve_example_similary_dic]
        nlp = spacy.load("en_core_web_lg")
        emb_data = [nlp(i).vector for i in data]

        X = emb_data
        n = len(X)
        k = 3

        # Apply K-Means clustering
        Center, DistMat = KMeans(np.array(emb_data), k)
        Points = PointSelection(DistMat, k, n)
        sentences = [cve_example_similary_dic[i] for i in Points]

        return sentences
def condidate_v3(sentence, data_des, all_aspect, target_key_aspect='affected_product'):
    if target_key_aspect == 'affected_product':
        cve_example = sentence.lower()
        print(cve_example)
        des_aspect = {}
        cve_example_similary = []
        affected_product = ''

        # Check for matching aspects in the provided list
        for i in range(len(all_aspect)):
            for j in all_aspect[i]:
                if j[1] == 'affected_product':
                    if j[0].lower() in cve_example:
                        cve_example_similary.append([data_des[i], all_aspect[i]])

        if len(cve_example_similary) == 0:
            return {"resCode": "1", "message": "success", "data": '找不到跟它相似的，跳过'}
        else:
            # Convert selected CVE examples to dictionaries for better readability
            cve_example_similary_dic = []
            for i in cve_example_similary:
                temp = {}
                for j in i[1]:
                    temp[j[1]] = j[0]
                cve_example_similary_dic.append([i[0], temp])

            if len(cve_example_similary) <= 10:
                return cve_example_similary_dic
            else:
                data = [i[0] for i in cve_example_similary_dic]
                nlp = spacy.load("en_core_web_lg")
                emb_data = [nlp(i).vector for i in data]

                X = emb_data
                n = len(X)
                k = 10

                # Apply K-Means clustering
                Center, DistMat = KMeans(np.array(emb_data), k)
                Points = PointSelection(DistMat, k, n)
                sentences = [cve_example_similary_dic[i] for i in Points]

                return sentences
    else:
        scout = 0
        cve_example = sentence
        number = {}
        des_aspect = {}

        # Calculate the number of matching aspects for each CVE description
        for i in range(len(all_aspect)):
            n = 0
            temp = [j[0] for j in all_aspect[i]]
            for j in temp:
                if j in cve_example:
                    n += 1
            number[data_des[i]] = n
            des_aspect[data_des[i]] = all_aspect[i]

        cve_example_similary = []
        max_number = max(number.values())

        # Select CVE examples with similar aspects
        for i in number:
            if number[i] >= max_number - 1:
                if target_key_aspect in [d[1] for d in des_aspect[i]]:
                    cve_example_similary.append([i, des_aspect[i]])

        c = 0

        while len(cve_example_similary) < 10 or len(cve_example_similary) > 3000:
            if c > max_number:
                scout = 1
                break
            else:
                cve_example_similary = []
                max_number = max(number.values())
                for i in number:
                    if number[i] >= max_number - c:
                        if target_key_aspect in [d[1] for d in des_aspect[i]]:
                            cve_example_similary.append([i, des_aspect[i]])

                c += 1

        if scout == 1:
            return {"resCode": "1", "message": "success", "data": '找不到跟它相似的，跳过'}

        # Convert selected CVE examples to dictionaries for better readability
        cve_example_similary_dic = []
        for i in cve_example_similary:
            temp = {}
            for j in i[1]:
                temp[j[1]] = j[0]
            cve_example_similary_dic.append([i[0], temp])

        data = [i[0] for i in cve_example_similary_dic]
        nlp = spacy.load("en_core_web_lg")
        emb_data = [nlp(i).vector for i in data]

        X = emb_data
        n = len(X)
        k = 10

        # Apply K-Means clustering
        Center, DistMat = KMeans(np.array(emb_data), k)
        Points = PointSelection(DistMat, k, n)
        sentences = [cve_example_similary_dic[i] for i in Points]

        return sentences
# Function using OpenAI API to get a response from GPT-3.5 Turbo based on a user's prompt
def ask_chatgpt_beifen(prompt):
    a = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are an expert in the field of software vulnerability."},
            {"role": "user", "content": prompt}
        ]
    )
    return a['choices'][0].message['content'].strip()
import requests
# Function making a POST request to a local web service to get a response from GPT-3.5 Turbo
def ask_chatgpt(prompt):
    url = 'http://127.0.0.1:8000/new1'
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "senetence": prompt,
        "version": "ask_chatgpt"
    }
    response = requests.post(url, data=json.dumps(data), headers=headers)
    return json.loads(response.text)['data']

# Function using OpenAI API for an initial response and then a "Chain of Thought" (COT) request
def ask_chatgpt_v1_beifen(prompt):
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are an expert in the field of software vulnerability."},
            {"role": "user", "content": prompt}
        ]
    )
    answer = response['choices'][0]['message']['content'].strip()
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are an expert in the field of software vulnerability."},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": answer},
            {"role": "user", "content": "Please give your reason step by step.(1.just return chain of thought and not return other.2.not return conclusion and just return process.3.The step sequence number is indicated by 1.2.3.4)"}
        ]
    )
    cot = response['choices'][0]['message']['content'].strip()
    pattern = r"\d+\.\s.+"  # Regex pattern to match step sequence number
    matches = re.findall(pattern, cot)
    text_without_last_line = re.sub(matches[-1], "", cot)  # Remove the last line
    return answer, text_without_last_line, cot

# Function making a POST request to a local web service to get a response from GPT-3.5 Turbo with version "ask_chatgpt_v1"
def ask_chatgpt_v1(prompt):
    url = 'http://127.0.0.1:8000/new1'
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "senetence": prompt,
        "version": "ask_chatgpt_v1"
    }
    response = requests.post(url, data=json.dumps(data), headers=headers)
    # Splitting the response data based on "$$$" and returning three parts: answer, text without the last line, and complete COT response
    return json.loads(response.text)['data'].split('$$$')[0], json.loads(response.text)['data'].split('$$$')[1], json.loads(response.text)['data'].split('$$$')[2]

# Function using OpenAI API to get a response from GPT-3.5 Turbo based on a user's prompt and conversation history
def ask_chatgpt_history(history_prompt, answer, prompt):
    a = openai.ChatCompletion.create(
      model="gpt-3.5-turbo",
      messages=[
            {"role": "system", "content": "You are an expert in the field of software vulnerability."},
            {"role": "user", "content": history_prompt},
            {"role": "assistant", "content": answer},
            {"role": "user", "content": prompt},
        ]
    )
    return a['choices'][0].message['content'].strip()

# Function to add knowledge to each sentence based on the affected product using ChatGPT
def add_knowledge(sentences):
    temp = sentences
    # Loop through each sentence in the input list
    for i in temp:
        # Initialize the prompt with a default description about the characteristics of a product in the field of software vulnerability
        prompt = 'Give a description of about 30 words: In the field of software vulnerability, what are the characteristics of the product '
        # Check if 'affected_product' information is available in the sentence
        if 'affected_product' in i[1]:
            # Append the affected product information to the prompt
            prompt = prompt + i[1]['affected_product'] + '?'
            # Use ChatGPT to get knowledge based on the prompt
            i[1]['affected_product_knowledge'] = ask_chatgpt(prompt)
    return temp

# Function to extract key aspects of a sentence using guohao_extract method
def extract_key_aspect(sentence):
    # Initialize a dictionary to store the key aspects extracted from the sentence
    lack = {"vulnerability description": sentence}
    # Use guohao_extract to extract key aspects
    aspct = guohao_extract(['1', sentence])
    s = 0
    # Loop through each extracted aspect
    while s < len(aspct):
        # Check and assign each aspect to the corresponding key in the lack dictionary
        if aspct[s] != '' and s == 1:
            lack['vulnerability_type'] = aspct[s]
        if aspct[s] != '' and s == 2:
            lack['attacker_type'] = aspct[s]
        if aspct[s] != '' and s == 3:
            lack['root_cause'] = aspct[s]
        if aspct[s] != '' and s == 4:
            lack['impact'] = aspct[s]
        if aspct[s] != '' and s == 5:
            lack['attacker_vector'] = aspct[s]
        s += 1
    return lack
   
    
    
    
    
    
    
    
    