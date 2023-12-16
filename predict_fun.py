
from find_candidate import condidate_v2, add_knowledge, ask_chatgpt,ask_chatgpt_v1
import numpy as np
import time
from generate_prompt import vulnerability_gengerate_zhuguanti,vulnerability_gengerate_tiankongti,\
    vulnerability_gengerate_jianchadaan, attack_vector_gengerate_zhuguanti,\
    attack_vector_gengerate_tiankongti, attack_vector_gengerate_jianchadaan,\
        root_cause_gengerate_zhuguanti, root_cause_gengerate_tiankongti,\
            root_cause_gengerate_jianchadaan, impact_gengerate_zhuguanti,\
                impact_gengerate_tiankongti, impact_gengerate_jianchadaan,vulnerability_gengerate_check,\
                    vulnerability_gengerate_zhuguanti_v1, vulnerability_gengerate_tiankongti_v1,\
                        attack_vector_gengerate_zhuguanti_v1, attack_vector_gengerate_tiankongti_v1,\
                            attack_vector_gengerate_check, root_cause_gengerate_zhuguanti_v1,\
                                root_cause_gengerate_tiankongti_v1,root_cause_gengerate_check,\
                                    impact_gengerate_zhuguanti_v1,impact_gengerate_tiankongti_v1,\
                                        impact_gengerate_check,attacker_type_gengerate_zhuguanti,\
                                            attacker_type_gengerate_tiankongti,attacker_type_gengerate_jianchadaan,\
                                                attacker_type_gengerate_zhuguanti_v1,attacker_type_gengerate_tiankongti_v1,\
                                                    attacker_type_gengerate_jianchadaan,attacker_type_gengerate_check
                                            
                                
                
import spacy
# Load the spaCy model for English language
nlp = spacy.load("en_core_web_lg")

# Load the knowledge base from a saved file
knowledgeBase = np.load('知识库.npy', allow_pickle=True).item()
all_aspect = knowledgeBase['aspect']  # Extract aspects from the knowledge base
data_des = knowledgeBase['des']  # Extract descriptions from the knowledge base

all_aspect_dic = []  # List to store dictionaries with aspects and descriptions
s = 0

# Create dictionaries with aspects and descriptions
for i in all_aspect:
    temp = {'vulnerability description': data_des[s]}
    for j in i:
        temp[j[1]] = j[0]
    all_aspect_dic.append(temp)
    s += 1

# Function to predict vulnerability type given a sentence and key aspect
def predict_vulnerability_type(sentence, key_aspect):
    # Generate candidate sentences based on the provided sentence and knowledge base
    condidate_sentences = condidate_v2(sentence, data_des, all_aspect, 'affected_product', 'vulnerability_type')
    
    cve_example_similary = []
    cve_example = sentence
    
    # Identify similar examples based on the 'affected_product' aspect
    for i in range(len(all_aspect_dic)):
        if 'affected_product' in all_aspect_dic[i]:
            product = all_aspect_dic[i]['affected_product']
            
            if product in cve_example:
                cve_example_similary.append(all_aspect_dic[i])

    # If candidate sentences are not in dictionary format, return an empty dictionary
    if type(condidate_sentences) == dict:
        return {}

    try:
        # Introduce a delay before further processing
        time.sleep(1)
        
        # Enhance candidate sentences with additional knowledge
        condidate_sentences_knowledge = add_knowledge(condidate_sentences)
        
        # Prepare the key aspect that needs to be predicted
        lack = key_aspect
        
        # Generate prompts for different question types
        prompt_zhuguanti = vulnerability_gengerate_zhuguanti(condidate_sentences, lack)
        prompt_tiankongti = vulnerability_gengerate_tiankongti(condidate_sentences, lack)
        
        # Ask ChatGPT for answers using different prompts
        answerA, A, AA = ask_chatgpt_v1(prompt_zhuguanti)
        answerB, B, BB = ask_chatgpt_v1(prompt_tiankongti)
        
        # Generate a prompt for verification based on ChatGPT responses
        prompt_jianchadaan = vulnerability_gengerate_jianchadaan(condidate_sentences, lack, [answerA, answerB])
        
        # Ask ChatGPT for verification answer
        answerC = ask_chatgpt(prompt_jianchadaan)
        
        # Compare the similarity of answers and choose the final answer
        nlp_A = nlp(answerA)
        nlp_B = nlp(answerB)
        nlp_C = nlp(answerC)
        
        # Choose the final answer based on the similarity scores
        if nlp_C.similarity(nlp_A) > nlp_C.similarity(nlp_B):
            return {"final_answer": answerC, "promopt": prompt_zhuguanti, "prompt_answer": answerA, 
                    "another_answer": answerB, "COT": A, "cot": AA}
        else:
            return {"final_answer": answerC, "promopt": prompt_tiankongti, "prompt_answer": answerB, 
                    "another_answer": answerA, "COT": B, "cot": BB}
    except Exception as e:
        # Handle exceptions and print an error message
        print('============')
        print('请注意：出错了')
        print(e)
        time.sleep(60)  # Introduce a delay before returning
        return {}
# Function to predict vulnerability type with additional verification steps
def predict_vulnerability_type_v1(sentence, key_aspect, cot, ans):
    # Generate candidate sentences based on the provided sentence and knowledge base
    condidate_sentences = condidate_v2(sentence, data_des, all_aspect, 'affected_product', 'vulnerability_type')
    
    cve_example_similary = []
    cve_example = sentence
    
    # Identify similar examples based on the 'affected_product' aspect
    for i in range(len(all_aspect_dic)):
        if 'affected_product' in all_aspect_dic[i]:
            product = all_aspect_dic[i]['affected_product']
            
            if product in cve_example:
                cve_example_similary.append(all_aspect_dic[i])

    # If candidate sentences are not in dictionary format, return an empty dictionary
    if type(condidate_sentences) == dict:
        return {}

    try:
        # Introduce a delay before further processing
        time.sleep(1)
        
        # Enhance candidate sentences with additional knowledge
        condidate_sentences_knowledge = add_knowledge(condidate_sentences)
        
        # Prepare the key aspect that needs to be predicted
        lack = key_aspect
        
        # Generate prompts for different question types
        prompt_zhuguanti = vulnerability_gengerate_zhuguanti_v1(condidate_sentences, lack, cot, ans)
        prompt_tiankongti = vulnerability_gengerate_tiankongti_v1(condidate_sentences, lack, cot, ans)
        
        # Ask ChatGPT for answers using different prompts
        answerA, A, AA = ask_chatgpt_v1(prompt_zhuguanti)
        answerB, B, BB = ask_chatgpt_v1(prompt_tiankongti)
        
        # Generate a prompt for verification based on ChatGPT responses
        prompt_jianchadaan = vulnerability_gengerate_jianchadaan(condidate_sentences, lack, [answerA, answerB])
        
        # Ask ChatGPT for verification answer
        answerC = ask_chatgpt(prompt_jianchadaan)
        
        # Compare the similarity of answers and choose the final answer
        nlp_A = nlp(answerA)
        nlp_B = nlp(answerB)
        nlp_C = nlp(answerC)
        
        # Choose the final answer based on the similarity scores
        if nlp_C.similarity(nlp_A) > nlp_C.similarity(nlp_B):
            return {"final_answer": answerC, "promopt": prompt_zhuguanti, "prompt_answer": answerA, 
                    "another_answer": answerB, "COT": A, "cot": AA}
        else:
            return {"final_answer": answerC, "promopt": prompt_tiankongti, "prompt_answer": answerB, 
                    "another_answer": answerA, "COT": B, "cot": BB}
    except Exception as e:
        # Handle exceptions and print an error message
        print('============')
        print('请注意：出错了')
        print(e)
        time.sleep(60)  # Introduce a delay before returning
        return {}


# Function to check the predicted vulnerability type and perform additional checks if needed
def check_vulnerability_type(all_aspect):
    cot_list = []
    
    # Predict the vulnerability type
    res = predict_vulnerability_type(all_aspect['vulnerability description'], all_aspect)
    
    # If the prediction is empty, return empty results
    if res == {}:
        return {}, 0, cot_list

    cot = res['COT']
    cot1 = res['cot']
    vulnerability_type = res['final_answer']
    sentence = all_aspect['vulnerability description']

    # Generate a prompt for checking the prediction
    prompt_check = vulnerability_gengerate_check(sentence, cot)
    
    # Ask ChatGPT for feedback on the prediction
    feed_back = ask_chatgpt(prompt_check)
    
    nlp_A = nlp(vulnerability_type)
    nlp_B = nlp(feed_back)
    
    # Check the similarity of the predicted vulnerability type and ChatGPT feedback
    if nlp_B.similarity(nlp_A) > 0.6:
        cot_list.append([vulnerability_type, cot, feed_back, cot1])
        return vulnerability_type, 0, cot_list
    else:
        s = 0
        
        # Retry the prediction up to 3 times
        while s < 3:
            s += 1
            res = predict_vulnerability_type_v1(all_aspect['vulnerability description'], all_aspect, cot, vulnerability_type)
            
            # If the prediction is empty, return empty results
            if res == {}:
                return {}, s, cot_list

            cot = res['COT']
            cot1 = res['cot']
            vulnerability_type = res['final_answer']
            sentence = all_aspect['vulnerability description']
            
            # Generate a prompt for checking the updated prediction
            prompt_check = vulnerability_gengerate_check(sentence, cot)
            
            # Ask ChatGPT for feedback on the updated prediction
            feed_back = ask_chatgpt(prompt_check)
            nlp_A = nlp(vulnerability_type)
            nlp_B = nlp(feed_back)
            
            # Check the similarity of the predicted vulnerability type and ChatGPT feedback
            if nlp_B.similarity(nlp_A) > 0.6:
                cot_list.append([vulnerability_type, cot, feed_back, cot1])
                return vulnerability_type, s, cot_list  
            else:
                cot_list.append([vulnerability_type, cot, feed_back, cot1])
        
        return 'exceed time, failed!', 4, cot_list


# Function to predict attack vector with additional verification steps
def predict_attack_vector(sentence, key_aspect):
    # Generate candidate sentences based on the provided sentence and knowledge base
    condidate_sentences = condidate_v2(sentence, data_des, all_aspect, 'affected_product', 'attack_vector')
    
    cve_example_similary = []
    cve_example = sentence
    
    # Identify similar examples based on the 'affected_product' aspect
    for i in range(len(all_aspect_dic)):
        if 'affected_product' in all_aspect_dic[i]:
            product = all_aspect_dic[i]['affected_product']
            
            if product in cve_example:
                cve_example_similary.append(all_aspect_dic[i])

    # If candidate sentences are not in dictionary format, return an empty dictionary
    if type(condidate_sentences) == dict:
        return {}

    try:
        # Introduce a delay before further processing
        time.sleep(1)
        
        # Enhance candidate sentences with additional knowledge
        condidate_sentences_knowledge = add_knowledge(condidate_sentences)
        
        # Prepare the key aspect that needs to be predicted
        lack = key_aspect
        
        # Generate prompts for different question types
        prompt_zhuguanti = attack_vector_gengerate_zhuguanti(condidate_sentences, lack)
        prompt_tiankongti = attack_vector_gengerate_tiankongti(condidate_sentences, lack)
        
        # Ask ChatGPT for answers using different prompts
        answerA, A, AA = ask_chatgpt_v1(prompt_zhuguanti)
        answerB, B, BB = ask_chatgpt_v1(prompt_tiankongti)
        
        # Generate a prompt for verification based on ChatGPT responses
        prompt_jianchadaan = attack_vector_gengerate_jianchadaan(condidate_sentences, lack, [answerA, answerB])
        
        # Ask ChatGPT for verification answer
        answerC = ask_chatgpt(prompt_jianchadaan)
        
        # Compare the similarity of answers and choose the final answer
        nlp_A = nlp(answerA)
        nlp_B = nlp(answerB)
        nlp_C = nlp(answerC)
        
        # Choose the final answer based on the similarity scores
        if nlp_C.similarity(nlp_A) > nlp_C.similarity(nlp_B):
            return {"final_answer": answerC, "promopt": prompt_zhuguanti, "prompt_answer": answerA, 
                    "another_answer": answerB, "COT": A, "cot": AA}
        else:
            return {"final_answer": answerC, "promopt": prompt_tiankongti, "prompt_answer": answerB, 
                    "another_answer": answerA, "COT": B, "cot": BB}
    except Exception as e:
        # Handle exceptions and print an error message
        print('============')
        print('请注意：出错了')
        print(e)
        time.sleep(60)
        return {}


# Function to predict attack vector with additional verification steps
def predict_attack_vector_v1(sentence, key_aspect, cot, ans):
    # Generate candidate sentences based on the provided sentence and knowledge base
    condidate_sentences = condidate_v2(sentence, data_des, all_aspect, 'affected_product', 'attack_vector')
    
    cve_example_similary = []
    cve_example = sentence
    
    # Identify similar examples based on the 'affected_product' aspect
    for i in range(len(all_aspect_dic)):
        if 'affected_product' in all_aspect_dic[i]:
            product = all_aspect_dic[i]['affected_product']
            
            if product in cve_example:
                cve_example_similary.append(all_aspect_dic[i])

    # If candidate sentences are not in dictionary format, return an empty dictionary
    if type(condidate_sentences) == dict:
        return {}

    try:
        # Introduce a delay before further processing
        time.sleep(1)
        
        # Enhance candidate sentences with additional knowledge
        condidate_sentences_knowledge = add_knowledge(condidate_sentences)
        
        # Prepare the key aspect that needs to be predicted
        lack = key_aspect
        
        # Generate prompts for different question types
        prompt_zhuguanti = attack_vector_gengerate_zhuguanti_v1(condidate_sentences, lack, cot, ans)
        prompt_tiankongti = attack_vector_gengerate_tiankongti_v1(condidate_sentences, lack, cot, ans)
        
        # Ask ChatGPT for answers using different prompts
        answerA, A, AA = ask_chatgpt_v1(prompt_zhuguanti)
        answerB, B, BB = ask_chatgpt_v1(prompt_tiankongti)
        
        # Generate a prompt for verification based on ChatGPT responses
        prompt_jianchadaan = attack_vector_gengerate_jianchadaan(condidate_sentences, lack, [answerA, answerB])
        
        # Ask ChatGPT for verification answer
        answerC = ask_chatgpt(prompt_jianchadaan)
        
        # Compare the similarity of answers and choose the final answer
        nlp_A = nlp(answerA)
        nlp_B = nlp(answerB)
        nlp_C = nlp(answerC)
        
        # Choose the final answer based on the similarity scores
        if nlp_C.similarity(nlp_A) > nlp_C.similarity(nlp_B):
            return {"final_answer": answerC, "promopt": prompt_zhuguanti, "prompt_answer": answerA, 
                    "another_answer": answerB, "COT": A, "cot": AA}
        else:
            return {"final_answer": answerC, "promopt": prompt_tiankongti, "prompt_answer": answerB, 
                    "another_answer": answerA, "COT": B, "cot": BB}
    except Exception as e:
        # Handle exceptions and print an error message
        print('============')
        print('请注意：出错了')
        print(e)
        time.sleep(60)
        return {}


# Function to check the predicted attack vector and perform additional checks if needed
def check_attack_vector(all_aspect):
    cot_list = []
    
    # Predict the attack vector
    res = predict_attack_vector(all_aspect['vulnerability description'], all_aspect)
    
    # If the prediction is empty, return empty results
    if res == {}:
        return {}, 0, cot_list

    cot = res['COT']
    cot1 = res['cot']
    attack_vector = res['final_answer']
    sentence = all_aspect['vulnerability description']

    # Generate a prompt for checking the prediction
    prompt_check = attack_vector_gengerate_check(sentence, cot)
    
    # Ask ChatGPT for feedback on the prediction
    feed_back = ask_chatgpt(prompt_check)
    
    nlp_A = nlp(attack_vector)
    nlp_B = nlp(feed_back)
    
    # Check the similarity of the predicted attack vector and ChatGPT feedback
    if nlp_B.similarity(nlp_A) > 0.6:
        cot_list.append([attack_vector, cot, feed_back, cot1])
        return attack_vector, 0, cot_list
    else:
        s = 0
        
        # Retry the prediction up to 3 times
        while s < 3:
            s += 1
            res = predict_attack_vector_v1(all_aspect['vulnerability description'], all_aspect, cot, attack_vector)
            
            # If the prediction is empty, return empty results
            if res == {}:
                return {}, s, cot_list

            cot = res['COT']
            cot1 = res['cot']
            attack_vector = res['final_answer']
            sentence = all_aspect['vulnerability description']
            
            # Generate a prompt for checking the updated prediction
            prompt_check = attack_vector_gengerate_check(sentence, cot)
            
            # Ask ChatGPT for feedback on the updated prediction
            feed_back = ask_chatgpt(prompt_check)
            nlp_A = nlp(attack_vector)
            nlp_B = nlp(feed_back)
            
            # Check the similarity of the predicted attack vector and ChatGPT feedback
            if nlp_B.similarity(nlp_A) > 0.6:
                cot_list.append([attack_vector, cot, feed_back, cot1])
                return attack_vector, s, cot_list  
            else:
                cot_list.append([attack_vector, cot, feed_back, cot1])
        
        return 'exceed time, failed!', 4, cot_list


# Function to predict root cause with additional verification steps
def predict_root_cause(sentence, key_aspect):
    # Generate candidate sentences based on the provided sentence and knowledge base
    condidate_sentences = condidate_v2(sentence, data_des, all_aspect, 'affected_product', 'root_cause')
    
    cve_example_similary = []
    cve_example = sentence
    
    # Identify similar examples based on the 'affected_product' aspect
    for i in range(len(all_aspect_dic)):
        if 'affected_product' in all_aspect_dic[i]:
            product = all_aspect_dic[i]['affected_product']
            
            if product in cve_example:
                cve_example_similary.append(all_aspect_dic[i])

    # If candidate sentences are not in dictionary format, return an empty dictionary
    if type(condidate_sentences) == dict:
        return {}

    try:
        # Introduce a delay before further processing
        time.sleep(1)
        
        # Enhance candidate sentences with additional knowledge
        condidate_sentences_knowledge = add_knowledge(condidate_sentences)
        
        # Prepare the key aspect that needs to be predicted
        lack = key_aspect
        
        # Generate prompts for different question types
        prompt_zhuguanti = root_cause_gengerate_zhuguanti(condidate_sentences, lack)
        prompt_tiankongti = root_cause_gengerate_tiankongti(condidate_sentences, lack)
        
        # Ask ChatGPT for answers using different prompts
        answerA, A, AA = ask_chatgpt_v1(prompt_zhuguanti)
        answerB, B, BB = ask_chatgpt_v1(prompt_tiankongti)
        
        # Generate a prompt for verification based on ChatGPT responses
        prompt_jianchadaan = root_cause_gengerate_jianchadaan(condidate_sentences, lack, [answerA, answerB])
        
        # Ask ChatGPT for verification answer
        answerC = ask_chatgpt(prompt_jianchadaan)
        
        # Compare the similarity of answers and choose the final answer
        nlp_A = nlp(answerA)
        nlp_B = nlp(answerB)
        nlp_C = nlp(answerC)
        
        # Choose the final answer based on the similarity scores
        if nlp_C.similarity(nlp_A) > nlp_C.similarity(nlp_B):
            return {"final_answer": answerC, "promopt": prompt_zhuguanti, "prompt_answer": answerA, 
                    "another_answer": answerB, "COT": A, "cot": AA}
        else:
            return {"final_answer": answerC, "promopt": prompt_tiankongti, "prompt_answer": answerB, 
                    "another_answer": answerA, "COT": B, "cot": BB}
    except Exception as e:
        # Handle exceptions and print an error message
        print('============')
        print('请注意：出错了')
        print(e)
        time.sleep(60)
        return {}

def predict_root_cause_v1(sentence, key_aspect, cot, ans):
    # Generate candidate sentences based on the provided sentence and knowledge base
    condidate_sentences = condidate_v2(sentence, data_des, all_aspect, 'affected_product', 'root_cause')
    
    # List to store similar examples based on 'affected_product'
    cve_example_similary = []
    
    # Extract 'affected_product' from all_aspect_dic and check if it's in the given sentence
    for i in range(len(all_aspect_dic)):
        if 'affected_product' in all_aspect_dic[i]:
            product = all_aspect_dic[i]['affected_product']
            
            if product in sentence:
                cve_example_similary.append(all_aspect_dic[i])

    # If candidate sentences are not in dictionary format, return an empty dictionary
    if type(condidate_sentences) == dict:
        return {}

    try:
        # Introduce a delay before further processing
        time.sleep(1)
        
        # Enhance candidate sentences with additional knowledge
        condidate_sentences_knowledge = add_knowledge(condidate_sentences)
        
        # Prepare the key aspect that needs to be predicted
        lack = key_aspect
        
        # Generate prompts for different question types
        prompt_zhuguanti = root_cause_gengerate_zhuguanti_v1(condidate_sentences, lack, cot, ans)
        prompt_tiankongti = root_cause_gengerate_tiankongti_v1(condidate_sentences, lack, cot, ans)
        
        # Ask ChatGPT for answers using different prompts
        answerA, A, AA = ask_chatgpt_v1(prompt_zhuguanti)
        answerB, B, BB = ask_chatgpt_v1(prompt_tiankongti)
        
        # Generate a prompt for verification based on ChatGPT responses
        prompt_jianchadaan = root_cause_gengerate_jianchadaan(condidate_sentences, lack, [answerA, answerB])
        
        # Ask ChatGPT for verification answer
        answerC = ask_chatgpt(prompt_jianchadaan)
        
        # Compare the similarity of answers and choose the final answer
        nlp_A = nlp(answerA)
        nlp_B = nlp(answerB)
        nlp_C = nlp(answerC)
        
        # Choose the final answer based on the similarity scores
        if nlp_C.similarity(nlp_A) > nlp_C.similarity(nlp_B):
            return {"final_answer": answerC, "promopt": prompt_zhuguanti, "prompt_answer": answerA, 
                    "another_answer": answerB, "COT": A, "cot": AA}
        else:
            return {"final_answer": answerC, "promopt": prompt_tiankongti, "prompt_answer": answerB, 
                    "another_answer": answerA, "COT": B, "cot": BB}
    except Exception as e:
        # Handle exceptions and print an error message
        print('============')
        print('请注意：出错了')
        print(e)
        time.sleep(60)
        return {}
def check_root_cause(all_aspect):
    # Initialize a list to store results
    cot_list = []
    
    # Predict the root cause using the 'predict_root_cause' function
    res = predict_root_cause(all_aspect['vulnerability description'], all_aspect)
    
    # If the prediction is empty, return an empty dictionary and zero counts
    if res == {}:
        return {}, 0, cot_list

    # Extract information from the prediction result
    cot = res['COT']  
    cot1 = res['cot']
    root_cause = res['final_answer']
    sentence = all_aspect['vulnerability description']

    # Generate a prompt for verification based on the predicted root cause
    prompt_check = root_cause_gengerate_check(sentence, cot)
    
    # Ask ChatGPT for verification
    feed_back = ask_chatgpt(prompt_check)
    
    # Compare the similarity of the predicted root cause and the verification response
    nlp_A = nlp(root_cause)
    nlp_B = nlp(feed_back)
    
    # If similarity is above the threshold, append results to 'cot_list' and return the result
    if nlp_B.similarity(nlp_A) > 0.6:
        cot_list.append([root_cause, cot, feed_back, cot1])
        return root_cause, 0, cot_list
    else:
        s = 0
        # Retry up to three times if similarity is below the threshold
        while s < 3:
            s += 1
            # Predict root cause with version 1 of the function
            res = predict_root_cause_v1(all_aspect['vulnerability description'], all_aspect, cot, root_cause)
            if res == {}:
                return {}, s, cot_list
            cot = res['COT']   
            cot1 = res['cot']
            root_cause = res['final_answer']
            sentence = all_aspect['vulnerability description']
            
            # Generate a new verification prompt and ask ChatGPT
            prompt_check = root_cause_gengerate_check(sentence, cot)
            feed_back = ask_chatgpt(prompt_check)
            
            # Compare similarity again
            nlp_A = nlp(root_cause)
            nlp_B = nlp(feed_back)
            
            # If similarity is above the threshold, append results to 'cot_list' and return the result
            if nlp_B.similarity(nlp_A) > 0.6:
                cot_list.append([root_cause, cot, feed_back, cot1])
                return root_cause, s, cot_list  
            else:
                cot_list.append([root_cause, cot, feed_back, cot1])
        # If all retries fail, return a failure message and the result
        return 'exceed time, failed!', 4, cot_list


def predict_impact(sentence, key_aspect):
    # Generate candidate sentences based on the 'affected_product' and 'impact' aspects
    condidate_sentences = condidate_v2(sentence, data_des, all_aspect, 'affected_product', 'impact')
    cve_example_similary = []
    cve_example = sentence
    for i in range(len(all_aspect_dic)):
        if 'affected_product' in all_aspect_dic[i]:
            product = all_aspect_dic[i]['affected_product']
            
            if product in cve_example:
                cve_example_similary.append(all_aspect_dic[i])

    # If the candidate sentences are empty, return an empty dictionary
    if type(condidate_sentences) == dict:
        return {}

    try:
        # Add knowledge to the candidate sentences
        time.sleep(1)
        condidate_sentences_knowledge = add_knowledge(condidate_sentences)
        
        lack = key_aspect
        
        # Generate prompts for impact prediction
        prompt_zhuguanti = impact_gengerate_zhuguanti(condidate_sentences, lack)
        prompt_tiankongti = impact_gengerate_tiankongti(condidate_sentences, lack)
        
        # Ask ChatGPT for impact prediction using two different prompts
        answerA, A, AA = ask_chatgpt_v1(prompt_zhuguanti)
        answerB, B, BB = ask_chatgpt_v1(prompt_tiankongti)
        
        # Generate a prompt for verification based on the predicted impact responses
        prompt_jianchadaan = impact_gengerate_jianchadaan(condidate_sentences, lack, [answerA, answerB])
        
        # Ask ChatGPT for verification of the impact prediction
        answerC = ask_chatgpt(prompt_jianchadaan)
        
        # Compare the similarity of the predicted impact responses
        nlp_A = nlp(answerA)
        nlp_B = nlp(answerB)
        nlp_C = nlp(answerC)
        
        # If similarity is higher for the first prompt, return results with the first response
        if nlp_C.similarity(nlp_A) > nlp_C.similarity(nlp_B):
            return {"final_answer": answerC, "promopt": prompt_zhuguanti, "prompt_answer": answerA, 
                    "another_answer": answerB, "COT": A, "cot": AA}
        else:
            # If similarity is higher for the second prompt, return results with the second response
            return {"final_answer": answerC, "promopt": prompt_tiankongti, "prompt_answer": answerB, 
                    "another_answer": answerA, "COT": B, "cot": BB}
    except Exception as e:
        # Handle exceptions and print an error message
        print('============')
        print('请注意：出错了')
        print(e)
        time.sleep(60)
        return {}
def predict_impact_v1(sentence, key_aspect, cot, ans):
    condidate_sentences = condidate_v2(sentence, data_des, all_aspect, 'affected_product', 'impact')
    cve_example_similary = []
    cve_example = sentence
    for i in range(len(all_aspect_dic)):
        if 'affected_product' in all_aspect_dic[i]:
            product = all_aspect_dic[i]['affected_product']
            
            if product in cve_example:
                cve_example_similary.append(all_aspect_dic[i])

    if type(condidate_sentences) == dict:
        return {}

    try:
        time.sleep(1)
        condidate_sentences_knowledge = add_knowledge(condidate_sentences)
        
        lack = key_aspect
        
        # Generate prompts for impact prediction with additional parameters 'cot' and 'ans'
        prompt_zhuguanti = impact_gengerate_zhuguanti_v1(condidate_sentences, lack, cot, ans)
        prompt_tiankongti = impact_gengerate_tiankongti_v1(condidate_sentences, lack, cot, ans)
        
        # Ask ChatGPT for impact prediction using two different prompts
        answerA, A, AA = ask_chatgpt_v1(prompt_zhuguanti)
        answerB, B, BB = ask_chatgpt_v1(prompt_tiankongti)
        
        # Generate a prompt for verification based on the predicted impact responses
        prompt_jianchadaan = impact_gengerate_jianchadaan(condidate_sentences, lack, [answerA, answerB])
        
        # Ask ChatGPT for verification of the impact prediction
        answerC = ask_chatgpt(prompt_jianchadaan)
        
        # Compare the similarity of the predicted impact responses
        nlp_A = nlp(answerA)
        nlp_B = nlp(answerB)
        nlp_C = nlp(answerC)
        
        # If similarity is higher for the first prompt, return results with the first response
        if nlp_C.similarity(nlp_A) > nlp_C.similarity(nlp_B):
            return {"final_answer": answerC, "promopt": prompt_zhuguanti, "prompt_answer": answerA, 
                    "another_answer": answerB, "COT": A, "cot": AA}
        else:
            # If similarity is higher for the second prompt, return results with the second response
            return {"final_answer": answerC, "promopt": prompt_tiankongti, "prompt_answer": answerB, 
                    "another_answer": answerA, "COT": B, "cot": BB}
    except Exception as e:
        # Handle exceptions and print an error message
        print('============')
        print('请注意：出错了')
        print(e)
        time.sleep(60)
        return {}

def check_impact(all_aspect):
    cot_list = []
    res = predict_impact(all_aspect['vulnerability description'], all_aspect)
    if res == {}:
        return {}, 0, cot_list

    cot = res['COT']  
    cot1 = res['cot']
    
    impact = res['final_answer']
    sentence = all_aspect['vulnerability description']

    # Generate a prompt for checking the impact
    prompt_check = impact_gengerate_check(sentence, cot)
    feed_back = ask_chatgpt(prompt_check)
    
    # Compare the similarity of the predicted impact and feedback responses
    nlp_A = nlp(impact)
    nlp_B = nlp(feed_back)
    
    # If similarity is higher than a threshold, return results
    if nlp_B.similarity(nlp_A) > 0.6:
        cot_list.append([impact, cot, feed_back, cot1])
        return impact, 0, cot_list
    else:
        s = 0
        while s < 3:
            s += 1
            res = predict_impact_v1(all_aspect['vulnerability description'], all_aspect, cot, impact)
            if res == {}:
                 return {}, s, cot_list       
            cot = res['COT']   
            cot1 = res['cot']
            impact = res['final_answer']
            sentence = all_aspect['vulnerability description']
            
            # Generate a prompt for checking the impact
            prompt_check = impact_gengerate_check(sentence, cot)
            feed_back = ask_chatgpt(prompt_check)
            
            # Compare the similarity of the predicted impact and feedback responses
            nlp_A = nlp(impact)
            nlp_B = nlp(feed_back)
            
            # If similarity is higher than a threshold, return results
            if nlp_B.similarity(nlp_A) > 0.6:
                cot_list.append([impact, cot, feed_back, cot1])
                return impact, s, cot_list  
            else:
                cot_list.append([impact, cot, feed_back, cot1])
        return 'exceed time, failed!', 4, cot_list
def predict_attacker_type(sentence, key_aspect):
    # Generate candidate sentences based on the vulnerability description
    condidate_sentences = condidate_v2(sentence, data_des, all_aspect, 'affected_product', 'attacker_type')

    if type(condidate_sentences) == dict:
        return {}

    try:
        time.sleep(1)
        condidate_sentences_knowledge = add_knowledge(condidate_sentences)
        
        lack = key_aspect
        
        # Generate prompts for attacker type prediction
        prompt_zhuguanti = attacker_type_gengerate_zhuguanti(condidate_sentences, lack)
        prompt_tiankongti = attacker_type_gengerate_tiankongti(condidate_sentences, lack)
        
        # Ask ChatGPT for attacker type prediction using two different prompts
        answerA, A, AA = ask_chatgpt_v1(prompt_zhuguanti)
        answerB, B, BB = ask_chatgpt_v1(prompt_tiankongti)
        
        # Generate a prompt for verification based on the predicted attacker type responses
        prompt_jianchadaan = attacker_type_gengerate_jianchadaan(condidate_sentences, lack, [answerA, answerB])
        
        # Ask ChatGPT for verification of the attacker type prediction
        answerC = ask_chatgpt(prompt_jianchadaan)
        
        # Compare the similarity of the predicted attacker type responses
        nlp_A = nlp(answerA)
        nlp_B = nlp(answerB)
        nlp_C = nlp(answerC)
        
        # If similarity is higher for the first prompt, return results with the first response
        if nlp_C.similarity(nlp_A) > nlp_C.similarity(nlp_B):
            return {"final_answer": answerC, "promopt": prompt_zhuguanti, "prompt_answer": answerA, 
                    "another_answer": answerB, "COT": A, "cot": AA}
        else:
            # If similarity is higher for the second prompt, return results with the second response
            return {"final_answer": answerC, "promopt": prompt_tiankongti, "prompt_answer": answerB, 
                    "another_answer": answerA, "COT": B, "cot": BB}
    except Exception as e:
        # Handle exceptions and print an error message
        print('============')
        print('请注意：出错了')
        print(e)
        time.sleep(60)
        return {}

def predict_attacker_type_v1(sentence, key_aspect, cot, ans):
    # Generate candidate sentences based on the vulnerability description
    condidate_sentences = condidate_v2(sentence, data_des, all_aspect, 'affected_product', 'attacker_type')

    if type(condidate_sentences) == dict:
        return {}

    try:
        time.sleep(1)
        condidate_sentences_knowledge = add_knowledge(condidate_sentences)
        
        lack = key_aspect
        
        # Generate prompts for attacker type prediction with additional parameters 'cot' and 'ans'
        prompt_zhuguanti = attacker_type_gengerate_zhuguanti_v1(condidate_sentences, lack, cot, ans)
        prompt_tiankongti = attacker_type_gengerate_tiankongti_v1(condidate_sentences, lack, cot, ans)
        
        # Ask ChatGPT for attacker type prediction using two different prompts
        answerA, A, AA = ask_chatgpt_v1(prompt_zhuguanti)
        answerB, B, BB = ask_chatgpt_v1(prompt_tiankongti)
        
        # Generate a prompt for verification based on the predicted attacker type responses
        prompt_jianchadaan = attacker_type_gengerate_jianchadaan(condidate_sentences, lack, [answerA, answerB])
        
        # Ask ChatGPT for verification of the attacker type prediction
        answerC = ask_chatgpt(prompt_jianchadaan)
        
        # Compare the similarity of the predicted attacker type responses
        nlp_A = nlp(answerA)
        nlp_B = nlp(answerB)
        nlp_C = nlp(answerC)
        
        # If similarity is higher for the first prompt, return results with the first response
        if nlp_C.similarity(nlp_A) > nlp_C.similarity(nlp_B):
            return {"final_answer": answerC, "promopt": prompt_zhuguanti, "prompt_answer": answerA, 
                    "another_answer": answerB, "COT": A, "cot": AA}
        else:
            # If similarity is higher for the second prompt, return results with the second response
            return {"final_answer": answerC, "promopt": prompt_tiankongti, "prompt_answer": answerB, 
                    "another_answer": answerA, "COT": B, "cot": BB}
    except Exception as e:
        # Handle exceptions and print an error message
        print('============')
        print('请注意：出错了')
        print(e)
        time.sleep(60)
        return {}

def check_attacker_type(all_aspect):
    cot_list = []
    res = predict_attacker_type(all_aspect['vulnerability description'], all_aspect)
    if res == {}:
        return {}, 0, cot_list

    cot = res['COT']  
    cot1 = res['cot']
    
    attacker_type = res['final_answer']
    sentence = all_aspect['vulnerability description']

    # Generate a prompt for checking the attacker type
    prompt_check = attacker_type_gengerate_check(sentence, cot)
    feed_back = ask_chatgpt(prompt_check)
    
    # Compare the similarity of the predicted attacker type and feedback responses
    nlp_A = nlp(attacker_type)
    nlp_B = nlp(feed_back)
    
    # If similarity is higher than a threshold, return results
    if nlp_B.similarity(nlp_A) > 0.6:
        cot_list.append([attacker_type, cot, feed_back, cot1])
        return attacker_type, 0, cot_list
    else:
        s = 0
        while s < 3:
            s += 1
            res = predict_attacker_type_v1(all_aspect['vulnerability description'], all_aspect, cot, attacker_type)
            if res == {}:
                return {}, s, cot_list       
            cot = res['COT']   
            cot1 = res['cot']
            attacker_type = res['final_answer']
            sentence = all_aspect['vulnerability description']
            
            # Generate a prompt for checking the attacker type
            prompt_check = attacker_type_gengerate_check(sentence, cot)
            feed_back = ask_chatgpt(prompt_check)
            
            # Compare the similarity of the predicted attacker type and feedback responses
            nlp_A = nlp(attacker_type)
            nlp_B = nlp(feed_back)
            
            # If similarity is higher than a threshold, return results
            if nlp_B.similarity(nlp_A) > 0.6:
                cot_list.append([attacker_type, cot, feed_back, cot1])
                return attacker_type, s, cot_list  
            else:
                cot_list.append([attacker_type, cot, feed_back, cot1])
        return 'exceed time, failed!', 4, cot_list

