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

import numpy as np
from itertools import permutations
import random
import pickle
from pyserini.search.lucene import LuceneSearcher
import json

ssearcher = LuceneSearcher.from_prebuilt_index('wikipedia-dpr')

def information_retrieval(query, num_results=3):
    hits = ssearcher.search(query, num_results)
    paragraphs = []
    for i in range(len(hits)):
        doc = ssearcher.doc(hits[i].docid)
        json_doc = json.loads(doc.raw())
        paragraphs.append(json_doc['contents'])
    return paragraphs

def retrieve_wiki_records(query):
    num_results = 20
    paragraphs = information_retrieval(query, num_results)
    return paragraphs


knowledgeBase = np.load('db_new.npy', allow_pickle=True).item()

data_all = []
for i in knowledgeBase['aspect']:
    temp = [j[0] for j in i if j[1] != 'affected_product']
    t = list(permutations(temp, 2))
    data_all.extend(t)


concept_all = [i[0] for i in data_all]
concept_all1 = [i[1] for i in data_all]
concept_all2 = concept_all + concept_all1
concept_all3 = list(set(concept_all2))

n = 2
data_false = []
s = 0
for i in data_all:
    # print(s)
    s += 1
    t1 = i[0]
    t2 = i[1]
    temp = random.sample(concept_all3, n)
    while t2 in temp:
        print(s)
        temp = random.sample(concept_all3, n)
    for j in temp:
        data_false.append((t1,j))
        
# =============================================================================
# s = 0
# data_all_wiki = []
# for i in data_all:
#     t1 = i[0]
#     print(s)
#     s+=1
#     t2 = i[1]
#     query_string = t1
#     retrieved_records1 = retrieve_wiki_records(query_string)
#     query_string = t2
#     retrieved_records2 = retrieve_wiki_records(query_string)    
#     data_all_wiki.append((retrieved_records1,retrieved_records2))
#     
# s = 0
# data_false_wiki = []
# for i in data_false:
#     t1 = i[0]
#     t2 = i[1]
#     print(s)
#     s += 1
#     query_string = t1
#     retrieved_records1 = retrieve_wiki_records(query_string)
#     query_string = t2
#     retrieved_records2 = retrieve_wiki_records(query_string)    
#     data_false_wiki.append((retrieved_records1,retrieved_records2))
# =============================================================================
s = 0
data_set_all_wiki = []
for i in concept_all3:
    t1 = i
    print(s)
    s+=1

    query_string = t1
    retrieved_records1 = retrieve_wiki_records(query_string)
  
    data_set_all_wiki.append(retrieved_records1)

with open('nli1.data','wb') as f:
    pickle.dump({'data':data_all,'notdata':data_false,'wiki':data_set_all_wiki,'wiki_index':concept_all3},f)

concept_all3_wiki=data_set_all_wiki
data_all_wiki = []
wiki_n = 3
s = 0
for i in data_all:
    t1 = i[0]
    t2 = i[1]
    s+= 1
    print(s)
    t1_index = concept_all3.index(t1)
    t2_index = concept_all3.index(t2)
    data_all_wiki.append((concept_all3_wiki[t1_index],concept_all3_wiki[t2_index]))


data_false_wiki = []
wiki_n = 3
s = 0
for i in data_false:
    t1 = i[0]
    t2 = i[1]
    s+= 1
    print(s)
    t1_index = concept_all3.index(t1)
    t2_index = concept_all3.index(t2)
    data_false_wiki.append((concept_all3_wiki[t1_index],concept_all3_wiki[t2_index]))

with open('nli2.data','wb') as f:
    pickle.dump({'data_all_wiki':data_all_wiki,'data_false_wiki':data_false_wiki},f)
    
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
from transformers import BertTokenizer, BertModel
from sklearn.model_selection import train_test_split
import numpy as np

# Define the NLI model
class NLIModel(nn.Module):
    def __init__(self, bert_model):
        super(NLIModel, self).__init__()
        self.bert_model = bert_model
        self.fc = nn.Linear(bert_model.config.hidden_size * 2, 2)  # Assuming binary classification

    def forward(self, input_ids_1, attention_mask_1, input_ids_2, attention_mask_2):
        _, pooled_output_1 = self.bert_model(input_ids=input_ids_1, attention_mask=attention_mask_1)
        _, pooled_output_2 = self.bert_model(input_ids=input_ids_2, attention_mask=attention_mask_2)
        concatenated_output = torch.cat((pooled_output_1, pooled_output_2), dim=1)
        logits = self.fc(concatenated_output)
        return logits

# Load pre-trained BERT model and tokenizer
bert_model = BertModel.from_pretrained('bert-base-uncased')
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

# Prepare your dataset
# Assuming you have a dataset with pairs of sentences and corresponding labels

# Split dataset into train and validation
train_sentences, val_sentences, train_labels, val_labels = train_test_split([data_set_all_wiki,data_false_wiki], [data_set_all_wiki,data_false_wiki], test_size=0.2, random_state=42)

# Define a custom dataset class
class NLIDataset(Dataset):
    def __init__(self, sentences, labels):
        self.sentences = sentences
        self.labels = labels

    def __len__(self):
        return len(self.sentences)

    def __getitem__(self, idx):
        return self.sentences[idx], self.labels[idx]

# Define collate function to process batches
def collate_fn(batch):
    sentences, labels = zip(*batch)
    tokenized_batch = tokenizer(list(sentences), padding=True, truncation=True, return_tensors='pt')
    input_ids = tokenized_batch['input_ids']
    attention_masks = tokenized_batch['attention_mask']
    labels = torch.tensor(labels)
    return input_ids, attention_masks, labels

# Create DataLoader
train_dataset = NLIDataset(train_sentences, train_labels)
train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True, collate_fn=collate_fn)

# Initialize model, loss function, and optimizer
model = NLIModel(bert_model)
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=2e-5)

# Training loop
num_epochs = 5
for epoch in range(num_epochs):
    model.train()
    for batch in train_loader:
        input_ids, attention_masks, labels = batch
        optimizer.zero_grad()
        logits = model(*input_ids, *attention_masks)
        loss = criterion(logits, labels)
        loss.backward()
        optimizer.step()

# Save the trained model
torch.save(model.state_dict(), 'nli_model.pt')
