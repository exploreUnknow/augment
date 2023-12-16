# -*- coding: utf-8 -*-

from find_candidate import ask_chatgpt_history
def vulnerability_gengerate_zhuguanti(similar_sentences, target_sentences):
    '''
    Generate a prompt for inferring the vulnerability type based on similar and target vulnerability descriptions.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.

    Returns
    -------
    prompt : str
        Generated prompt for subjective vulnerability type inference.

    '''
    prompt = "please infer target vulnerability type (No more than 10 words) based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description, and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    
    # Iterate through similar sentences
    for i in similar_sentences:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: what is the vulnerability type? (answer should be not more than 10 words, and should not include explanation)\nAnswer:'
    return prompt

def vulnerability_gengerate_zhuguanti_v1(similar_sentences, target_sentences, cot, answer):
    '''
    Generate a prompt for inferring the vulnerability type based on similar and target vulnerability descriptions with error information.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.
    cot : str
        Error reasoning chain.
    answer : str
        Error answer.

    Returns
    -------
    prompt : str
        Generated prompt for subjective vulnerability type inference with error information.

    '''
    prompt = "please infer target vulnerability type (No more than 10 words) based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description, and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    
    # Iterate through similar sentences
    for i in similar_sentences:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' 
    
    # Adding error information to the prompt
    prompt = prompt + 'error reasoning chain: \n' + cot + '\nerror answer: ' + answer + '\n'
    
    prompt = prompt + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: what is the vulnerability type? (answer should be not more than 10 words, and should not include explanation)\nAnswer:'
    return prompt


def attacker_type_gengerate_zhuguanti(similar_sentences, target_sentences):
    '''
    Generate a prompt for inferring the attacker type based on similar and target vulnerability descriptions.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.

    Returns
    -------
    prompt : str
        Generated prompt for subjective attacker type inference.

    '''
    prompt = "please infer target attacker type (No more than 10 words and just include attacker type and attacker type do not include 'unknown') based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description, and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    
    # Iterate through similar sentences
    for i in similar_sentences:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: what is the attacker type? (answer should be not more than 10 words, and should not include explanation and attacker type do not include "unknown")\nAnswer:' 
    return prompt


def attacker_type_gengerate_zhuguanti_v1(similar_sentences, target_sentences, cot, answer):
    '''
    Generate a prompt for inferring the attacker type based on similar and target vulnerability descriptions with error information.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.
    cot : str
        Error reasoning chain.
    answer : str
        Error answer.

    Returns
    -------
    prompt : str
        Generated prompt for subjective attacker type inference with error information.

    '''
    prompt = "please infer target attacker type (No more than 10 words and just include attacker type and attacker type do not include 'unknown') based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description, and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    
    # Iterate through similar sentences
    for i in similar_sentences:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' 
    
    # Adding error information to the prompt
    prompt = prompt + 'error reasoning chain: \n' + cot + '\nerror answer: ' + answer + '\n'
    
    prompt = prompt + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: what is the attacker type? (answer should be not more than 10 words, and should not include explanation, and attacker type do not include "unknown")\nAnswer:' 
    return prompt
def attack_vector_gengerate_zhuguanti(similar_sentences, target_sentences):
    '''
    Generate a prompt for inferring the attack vector based on similar and target vulnerability descriptions.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.

    Returns
    -------
    prompt : str
        Generated prompt for subjective attack vector inference.

    '''
    prompt = "please infer target attack vector (No more than 10 words and just include attack vector and attack vector do not include 'unknown') based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description, and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    
    # Iterate through similar sentences
    for i in similar_sentences:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: what is the attack vector? (answer should be not more than 10 words, and should not include explanation and attack vector do not include "unknown")\nAnswer:' 
    return prompt


def attack_vector_gengerate_zhuguanti_v1(similar_sentences, target_sentences, cot, answer):
    '''
    Generate a prompt for inferring the attack vector based on similar and target vulnerability descriptions with error information.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.
    cot : str
        Error reasoning chain.
    answer : str
        Error answer.

    Returns
    -------
    prompt : str
        Generated prompt for subjective attack vector inference with error information.

    '''
    prompt = "please infer target attack vector (No more than 10 words and just include attack vector) based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description, and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    
    # Iterate through similar sentences
    for i in similar_sentences:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' 
    
    # Adding error information to the prompt
    prompt = prompt + 'error reasoning chain: \n' + cot + '\nerror answer: ' + answer + '\n'
    
    prompt = prompt + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: what is the attack vector? (answer should be not more than 10 words, and should not include explanation)\nAnswer:' 
    return prompt


def root_cause_gengerate_zhuguanti(similar_sentences, target_sentences):
    '''
    Generate a prompt for inferring the vulnerability root cause based on similar and target vulnerability descriptions.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.

    Returns
    -------
    prompt : str
        Generated prompt for subjective root cause inference.

    '''
    prompt = "please infer target vulnerability root cause (No more than 10 words and just include root cause and root cause do not include 'unknown') based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description, and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    
    # Iterate through similar sentences
    for i in similar_sentences:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: what is the root cause? (answer should be not more than 10 words, and should not include explanation and root cause do not include "unknown")\nAnswer:' 
    return prompt
def root_cause_gengerate_zhuguanti_v1(similar_sentences, target_sentences, cot, answer):
    '''
    Generate a prompt for inferring the vulnerability root cause based on similar and target vulnerability descriptions with error information.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.
    cot : str
        Error reasoning chain.
    answer : str
        Error answer.

    Returns
    -------
    prompt : str
        Generated prompt for subjective vulnerability root cause inference with error information.

    '''
    prompt = "please infer target vulnerability root cause (No more than 10 words and just include root cause) based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description, and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    
    # Iterate through similar sentences
    for i in similar_sentences:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' 
    
    # Adding error information to the prompt
    prompt = prompt + 'error reasoning chain: \n' + cot + '\nerror answer: ' + answer + '\n'
    
    prompt = prompt + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: what is the root cause? (answer should be not more than 10 words, and should not include explanation)\nAnswer:' 
    return prompt

def impact_gengerate_zhuguanti(similar_sentences, target_sentences):
    '''
    Generate a prompt for inferring the impact based on similar and target vulnerability descriptions.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.

    Returns
    -------
    prompt : str
        Generated prompt for subjective impact inference.

    '''
    prompt = "please infer target impact (1. No more than 10 words 2. Just include impact 3. Do not include 'unknown') based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description, and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    
    # Iterate through similar sentences
    for i in similar_sentences:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: what is the impact? (1. Answer should be not more than 10 words 2. Should not include explanation 3. Do not include "unknown")\nAnswer:' 
    return prompt


def impact_gengerate_zhuguanti_v1(similar_sentences, target_sentences, cot, answer):
    '''
    Generate a prompt for inferring the impact based on similar and target vulnerability descriptions with error information.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.
    cot : str
        Error reasoning chain.
    answer : str
        Error answer.

    Returns
    -------
    prompt : str
        Generated prompt for subjective impact inference with error information.

    '''
    prompt = "please infer target impact (No more than 10 words and just include impact) based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description, and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    
    # Iterate through similar sentences
    for i in similar_sentences:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' 
    
    # Adding error information to the prompt
    prompt = prompt + 'error reasoning chain: \n' + cot + '\nerror answer: ' + answer + '\n'
    
    prompt = prompt + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: what is the impact? (answer should be not more than 10 words, and should not include explanation)\nAnswer:' 
    return prompt
def vulnerability_gengerate_tiankongti(similar_sentences, target_sentences):
    '''
    Generate a prompt for inferring vulnerability type through fill-in-the-blank questions.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.

    Returns
    -------
    prompt : str
        Generated prompt for vulnerability type inference (fill-in-the-blank).

    '''
    prompt = "please infer vulnerability type (No more than 10 words) based on similar vulnerabilities, examples of inferring, target vulnerability description, and target vulnerability key aspects.\nSimilar vulnerabilities:\n["

    similar_sentences_0_5 = similar_sentences[:int(len(similar_sentences)/2)]
    similar_sentences_5_10 = similar_sentences[int(len(similar_sentences)/2):]
    
    # Iterate through the first half of similar sentences
    for i in similar_sentences_0_5:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' + 'Examples of inferring:\n['
    
    # Iterate through the second half of similar sentences
    for i in similar_sentences_5_10:
        des = i[0]
        aspect = i[1]
        
        # Replace the vulnerability_type with "(missing vulnerability_type)"
        des = des.replace(aspect['vulnerability_type'], '(missing vulnerability_type)')
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors (except vulnerability_type) to the prompt
        for j in aspect:
            if j != 'vulnerability_type':
                prompt = prompt + j + ': ' + aspect[j] + '\n'
        
        # Adding the inference example to the prompt
        prompt = prompt + 'vulnerability_type could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nvulnerability_type: '
        prompt = prompt + aspect['vulnerability_type'] + '\n},\n'
    
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'vulnerability_type could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nvulnerability_type: ' 
    return prompt

def vulnerability_gengerate_tiankongti_v1(similar_sentences, target_sentences, cot, answer):
    '''
    Generate a prompt for inferring vulnerability type through fill-in-the-blank questions with error information.

    Parameters
    ----------
    similar_sentences : list of lists
        List containing sublists with similar text and key factors. Each sublist has the format: [[text], {key factors}].
    target_sentences : dict
        Dictionary containing the target text and its key factors. Format: {'target text': 'key factors'}.
    cot : str
        Error reasoning chain.
    answer : str
        Error answer.

    Returns
    -------
    prompt : str
        Generated prompt for vulnerability type inference (fill-in-the-blank) with error information.

    '''
    prompt = "please infer vulnerability type (No more than 10 words) based on similar vulnerabilities, examples of inferring, target vulnerability description, and target vulnerability key aspects.\nSimilar vulnerabilities:\n["

    similar_sentences_0_5 = similar_sentences[:int(len(similar_sentences)/2)]
    similar_sentences_5_10 = similar_sentences[int(len(similar_sentences)/2):]
    
    # Iterate through the first half of similar sentences
    for i in similar_sentences_0_5:
        des = i[0]  # Extracting vulnerability description
        aspect = i[1]  # Extracting key factors
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors to the prompt
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    
    prompt = prompt + ']\n' + 'Examples of inferring:\n['
    
    # Iterate through the second half of similar sentences
    for i in similar_sentences_5_10:
        des = i[0]
        aspect = i[1]
        
        # Replace the vulnerability_type with "(missing vulnerability_type)"
        des = des.replace(aspect['vulnerability_type'], '(missing vulnerability_type)')
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        
        # Adding key factors (except vulnerability_type) to the prompt
        for j in aspect:
            if j != 'vulnerability_type':
                prompt = prompt + j + ': ' + aspect[j] + '\n'
        
        # Adding the inference example to the prompt
        prompt = prompt + 'vulnerability_type could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nvulnerability_type: '
        prompt = prompt + aspect['vulnerability_type'] + '\n},\n'
    
    prompt = prompt + ']\n' 
    prompt = prompt + 'error reasoning chain: \n' + cot + '\nerror answer: ' + answer + '\n'
    
    prompt = prompt + 'Target vulnerability:\n'
    
    # Adding target vulnerabilities to the prompt
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'vulnerability_type could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nvulnerability_type: ' 
    return prompt
def vulnerability_gengerate_check(sentences, cot):
    '''
    Generate a prompt to reason the vulnerability type based on a reasoning chain.

    Parameters
    ----------
    sentences : str
        Vulnerability description.
    cot : str
        Reasoning chain.

    Returns
    -------
    prompt : str
        Generated prompt for reasoning the vulnerability type.

    '''
    prompt = 'reason the vulnerability type base on reasoning chain.\nnoting: 1.vulnerability type is word or phrase 2.just return vulnerability type and do nor return other.\nvulnerability description: '
    prompt = prompt + sentences + ';\n' + 'reason chain: \n' + cot
    prompt = prompt + '\nquestion: what is the vulnerability type based reasoning chain?\nThe vulnerability type based on the reasoning chain is: '
    return prompt

def attack_vector_gengerate_check(sentences, cot):
    '''
    Generate a prompt to reason the attack vector based on a reasoning chain.

    Parameters
    ----------
    sentences : str
        Vulnerability description.
    cot : str
        Reasoning chain.

    Returns
    -------
    prompt : str
        Generated prompt for reasoning the attack vector.

    '''
    prompt = 'reason the attack vector base on reasoning chain.\nnoting: 1.attack vector is word or phrase 2.just return attack vector and do nor return other.\nvulnerability description: '
    prompt = prompt + sentences + ';\n' + 'reason chain: \n' + cot
    prompt = prompt + '\nquestion: what is the attack vector based reasoning chain?\nThe attack vector based on the reasoning chain is: '
    return prompt

def attacker_type_gengerate_check(sentences, cot):
    '''
    Generate a prompt to reason the attacker type based on a reasoning chain.

    Parameters
    ----------
    sentences : str
        Vulnerability description.
    cot : str
        Reasoning chain.

    Returns
    -------
    prompt : str
        Generated prompt for reasoning the attacker type.

    '''
    prompt = 'reason the attacker type base on reasoning chain.\nnoting: 1.attacker type is word or phrase 2.just return attacker type and do nor return other.\nvulnerability description: '
    prompt = prompt + sentences + ';\n' + 'reason chain: \n' + cot
    prompt = prompt + '\nquestion: what is the attacker type based reasoning chain?\nThe attacker type based on the reasoning chain is: '
    return prompt

def root_cause_gengerate_check(sentences, cot):
    '''
    Generate a prompt to reason the root cause based on a reasoning chain.

    Parameters
    ----------
    sentences : str
        Vulnerability description.
    cot : str
        Reasoning chain.

    Returns
    -------
    prompt : str
        Generated prompt for reasoning the root cause.

    '''
    prompt = 'reason the root cause base on reasoning chain.\nnoting: 1.root cause is word or phrase 2.just return root cause and do nor return other.\nvulnerability description: '
    prompt = prompt + sentences + ';\n' + 'reason chain: \n' + cot
    prompt = prompt + '\nquestion: what is the root cause based reasoning chain?\nThe root cause based on the reasoning chain is: '
    return prompt

def impact_gengerate_check(sentences, cot):
    '''
    Generate a prompt to reason the impact based on a reasoning chain.

    Parameters
    ----------
    sentences : str
        Vulnerability description.
    cot : str
        Reasoning chain.

    Returns
    -------
    prompt : str
        Generated prompt for reasoning the impact.

    '''
    prompt = 'reason the impact base on reasoning chain.\nnoting: 1.impact is word or phrase 2.just return impact and do nor return other.\nvulnerability description: '
    prompt = prompt + sentences + ';\n' + 'reason chain: \n' + cot
    prompt = prompt + '\nquestion: what is the impact based reasoning chain?\nThe impact based on the reasoning chain is: '
    return prompt
def attacker_type_gengerate_tiankongti(similar_sentences, target_sentences):
    '''
    Generate a fill-in-the-blank prompt to infer attacker type based on similar vulnerabilities, examples of inferring, target vulnerability description, and key aspects.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.

    Returns
    -------
    prompt : str
        Generated prompt for inferring the attacker type.

    '''
    prompt = "please infer attacker type (No more than 10 words and just include attacker type) based on similar vulnerabilities, examples of inferring, target vulnerability description and target vulnerability key aspects.\nSimilar vulnerabilities:\n["

    similar_sentences_0_5 = similar_sentences[:int(len(similar_sentences)/2)]
    similar_sentences_5_10 = similar_sentences[int(len(similar_sentences)/2):]
    for i in similar_sentences_0_5:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    prompt = prompt + ']\n' + 'Examples of inferring:\n['
    for i in similar_sentences_5_10:
        des = i[0]
        aspect = i[1]
        des = des.replace(aspect['attacker_type'], '(missing attacker type)')
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            if j != 'attacker_type':
                prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + 'attacker type could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nattacker type: '
        prompt = prompt + aspect['attacker_type'] + '\n},\n'
 
    
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'attacker type could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nattacker type: ' 
    return prompt

def attacker_type_gengerate_tiankongti_v1(similar_sentences, target_sentences, cot, answer):
    '''
    Generate a fill-in-the-blank prompt for inferring attacker type with error reasoning chain and error answer.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.
    cot : str
        Error reasoning chain.
    answer : str
        Error answer.

    Returns
    -------
    prompt : str
        Generated prompt for inferring the attacker type with error information.

    '''
    prompt = "please infer attacker type (No more than 10 words and just include attacker type) based on similar vulnerabilities, examples of inferring, target vulnerability description and target vulnerability key aspects.\nSimilar vulnerabilities:\n["

    similar_sentences_0_5 = similar_sentences[:int(len(similar_sentences)/2)]
    similar_sentences_5_10 = similar_sentences[int(len(similar_sentences)/2):]
    for i in similar_sentences_0_5:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    prompt = prompt + ']\n' 
    prompt = prompt + 'error reasoning chain: \n' + cot + '\nerror answer: ' + answer + '\n'
    
    prompt = prompt + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'attacker type could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nattacker type: ' 
    return prompt

def attack_vector_gengerate_tiankongti(similar_sentences, target_sentences):
    '''
    Generate a fill-in-the-blank prompt to infer attack vector based on similar vulnerabilities, examples of inferring, target vulnerability description, and key aspects.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.

    Returns
    -------
    prompt : str
        Generated prompt for inferring the attack vector.

    '''
    prompt = "please infer attack vector (No more than 10 words and just include attack vector) based on similar vulnerabilities, examples of inferring, target vulnerability description and target vulnerability key aspects.\nSimilar vulnerabilities:\n["

    similar_sentences_0_5 = similar_sentences[:int(len(similar_sentences)/2)]
    similar_sentences_5_10 = similar_sentences[int(len(similar_sentences)/2):]
    for i in similar_sentences_0_5:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    prompt = prompt + ']\n' + 'Examples of inferring:\n['
    for i in similar_sentences_5_10:
        des = i[0]
        aspect = i[1]
        des = des.replace(aspect['attack_vector'], '(missing attack vector)')
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            if j != 'attack_vector':
                prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + 'attack vector could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nattack vector: '
        prompt = prompt + aspect['attack_vector'] + '\n},\n'
 
    
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'attack vector could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nattack vector: ' 
    return prompt

def attack_vector_gengerate_tiankongti_v1(similar_sentences, target_sentences, cot, answer):
    '''
    Generate a fill-in-the-blank prompt for inferring attack vector with error reasoning chain and error answer.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.
    cot : str
        Error reasoning chain.
    answer : str
        Error answer.

    Returns
    -------
    prompt : str
        Generated prompt for inferring the attack vector with error information.

    '''
    prompt = "please infer attack vector (No more than 10 words and just include attack vector) based on similar vulnerabilities, examples of inferring, target vulnerability description and target vulnerability key aspects.\nSimilar vulnerabilities:\n["

    similar_sentences_0_5 = similar_sentences[:int(len(similar_sentences)/2)]
    similar_sentences_5_10 = similar_sentences[int(len(similar_sentences)/2):]
    for i in similar_sentences_0_5:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    prompt = prompt + ']\n' 
    prompt = prompt + 'error reasoning chain: \n' + cot + '\nerror answer: ' + answer + '\n'
    
    prompt = prompt + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'attack vector could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nattack vector: ' 
    return prompt

def root_cause_gengerate_tiankongti(similar_sentences, target_sentences):
    '''
    Generate a fill-in-the-blank prompt to infer root cause based on similar vulnerabilities, examples of inferring, target vulnerability description, and key aspects.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.

    Returns
    -------
    prompt : str
        Generated prompt for inferring the root cause.

    '''
    prompt = "please infer root cause (No more than 10 words and just include root_cause) based on similar vulnerabilities, examples of inferring, target vulnerability description and target vulnerability key aspects.\nSimilar vulnerabilities:\n["

    similar_sentences_0_5 = similar_sentences[:int(len(similar_sentences)/2)]
    similar_sentences_5_10 = similar_sentences[int(len(similar_sentences)/2):]
    for i in similar_sentences_0_5:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    prompt = prompt + ']\n' + 'Examples of inferring:\n['
    for i in similar_sentences_5_10:
        des = i[0]
        aspect = i[1]
        des = des.replace(aspect['root_cause'], '(missing root cause)')
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            if j != 'root_cause':
                prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + 'root cause could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nroot cause: '
        prompt = prompt + aspect['root_cause'] + '\n},\n'
 
    
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'root cause could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nroot cause: ' 
    return prompt

def root_cause_gengerate_tiankongti_v1(similar_sentences, target_sentences, cot, answer):
    '''
    Generate a fill-in-the-blank prompt for inferring root cause with error reasoning chain and error answer.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.
    cot : str
        Error reasoning chain.
    answer : str
        Error answer.

    Returns
    -------
    prompt : str
        Generated prompt for inferring the root cause with error information.

    '''
    prompt = "please infer root cause (No more than 10 words and just include root_cause) based on similar vulnerabilities, examples of inferring, target vulnerability description and target vulnerability key aspects.\nSimilar vulnerabilities:\n["

    similar_sentences_0_5 = similar_sentences[:int(len(similar_sentences)/2)]
    similar_sentences_5_10 = similar_sentences[int(len(similar_sentences)/2):]
    for i in similar_sentences_0_5:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    prompt = prompt + ']\n' 
    prompt = prompt + 'error reasoning chain: \n' + cot + '\nerror answer: ' + answer + '\n'
    
    prompt = prompt + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'root cause could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nroot cause: ' 
    return prompt
def impact_gengerate_tiankongti(similar_sentences, target_sentences):
    '''
    Generate a fill-in-the-blank prompt for inferring impact.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.

    Returns
    -------
    prompt : str
        Generated prompt for inferring the impact.

    '''
    prompt = "please infer impact (No more than 10 words and just include impact) based on similar vulnerabilities, examples of inferring, target vulnerability description and target vulnerability key aspects.\nSimilar vulnerabilities:\n["

    similar_sentences_0_5 = similar_sentences[:int(len(similar_sentences)/2)]
    similar_sentences_5_10 = similar_sentences[int(len(similar_sentences)/2):]
    for i in similar_sentences_0_5:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    prompt = prompt + ']\n' + 'Examples of inferring:\n['
    for i in similar_sentences_5_10:
        des = i[0]
        aspect = i[1]
        des = des.replace(aspect['impact'], '(missing impact)')
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            if j != 'impact':
                prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + 'impact could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nimpact: '
        prompt = prompt + aspect['impact'] + '\n},\n'
    
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'impact could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nimpact: ' 
    return prompt

def impact_gengerate_tiankongti_v1(similar_sentences, target_sentences, cot, answer):
    '''
    Generate a fill-in-the-blank prompt for inferring impact with error reasoning chain and error answer.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.
    cot : str
        Error reasoning chain.
    answer : str
        Error answer.

    Returns
    -------
    prompt : str
        Generated prompt for inferring the impact with error information.

    '''
    prompt = "please infer impact (No more than 10 words and just include impact) based on similar vulnerabilities, examples of inferring, target vulnerability description and target vulnerability key aspects.\nSimilar vulnerabilities:\n["

    similar_sentences_0_5 = similar_sentences[:int(len(similar_sentences)/2)]
    similar_sentences_5_10 = similar_sentences[int(len(similar_sentences)/2):]
    for i in similar_sentences_0_5:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    prompt = prompt + ']\n' 
    prompt = prompt + 'error reasoning chain: \n' + cot + '\nerror answer: ' + answer + '\n'
    
    prompt = prompt + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'impact could be inferred based on vulnerability description, key aspects, Similar vulnerabilities;\nimpact: ' 
    return prompt

def vulnerability_gengerate_jianchadaan(similar_sentences, target_sentences, answers):
    '''
    Generate a prompt for checking answers based on similar vulnerabilities, target vulnerability description, and key aspects.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.
    answers : list
        List of answer options.

    Returns
    -------
    prompt : str
        Generated prompt for checking answers.

    '''
    prompt = "Please select the correct answer from the vulnerability type options based on similar vulnerabilities, target vulnerability description, and target vulnerability key aspect.\nNoting: just return option text\nvulnerability type options: "
    bianhao = ['A','B']
    s = 0
    for i in answers:
        s += 1
        prompt = prompt + bianhao[s-1] + '. ' + answers[s-1] + '; '
    prompt = prompt + "\nSimilar vulnerabilities:\n["

    for i in similar_sentences:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
   
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: Please select the correct vulnerability type from the vulnerability type options.\nAnswer:' 
    return prompt
def attacker_type_gengerate_jianchadaan(similar_sentences, target_sentences, answers):
    '''
    Generate a prompt for checking answers based on similar vulnerabilities, target vulnerability description, and key aspects.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.
    answers : list
        List of answer options.

    Returns
    -------
    prompt : str
        Generated prompt for checking answers.

    '''
    prompt = "Please select the correct answer from the attacker type options based on similar vulnerabilities, target vulnerability description, and target vulnerability key aspect.\nNoting: just return option text\nattacker type options: "
    bianhao = ['A','B']
    s = 0
    for i in answers:
        s += 1
        prompt = prompt + bianhao[s-1] + '. ' + answers[s-1] + '; '
    prompt = prompt + "\nSimilar vulnerabilities:\n["

    for i in similar_sentences:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
   
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: Please select the correct attacker type from the attacker type options.\nAnswer:' 
    return prompt

def attack_vector_gengerate_jianchadaan(similar_sentences, target_sentences, answers):
    '''
    Generate a prompt for checking answers based on similar vulnerabilities, target vulnerability description, and key aspects.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.
    answers : list
        List of answer options.

    Returns
    -------
    prompt : str
        Generated prompt for checking answers.

    '''
    prompt = "Please select the correct answer from the attack vector options based on similar vulnerabilities, target vulnerability description, and target vulnerability key aspect.\nNoting: just return option text\nattack vector options: "
    bianhao = ['A','B']
    s = 0
    for i in answers:
        s += 1
        prompt = prompt + bianhao[s-1] + '. ' + answers[s-1] + '; '
    prompt = prompt + "\nSimilar vulnerabilities:\n["

    for i in similar_sentences:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
   
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: Please select the correct attack vector from the attack vector options.\nAnswer:' 
    return prompt

def root_cause_gengerate_jianchadaan(similar_sentences, target_sentences, answers):
    '''
    Generate a prompt for checking answers based on similar vulnerabilities, target vulnerability description, and key aspects.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.
    answers : list
        List of answer options.

    Returns
    -------
    prompt : str
        Generated prompt for checking answers.

    '''
    prompt = "Please select the correct answer from the root cause options based on similar vulnerabilities, target vulnerability description, and target vulnerability key aspect.\nNoting: just return option text\nroot cause options: "
    bianhao = ['A','B']
    s = 0
    for i in answers:
        s += 1
        prompt = prompt + bianhao[s-1] + '. ' + answers[s-1] + '; '
    prompt = prompt + "\nSimilar vulnerabilities:\n["

    for i in similar_sentences:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
   
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: Please select the correct root cause from the root cause options.\nAnswer:' 
    return prompt
def impact_gengerate_jianchadaan(similar_sentences, target_sentences, answers):
    '''
    Generate a prompt for checking answers based on similar vulnerabilities, target vulnerability description, and key aspects.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.
    answers : list
        List of answer options.

    Returns
    -------
    prompt : str
        Generated prompt for checking answers.

    '''
    prompt = "Please select the correct answer from the impact options based on similar vulnerabilities, target vulnerability description, and target vulnerability key aspect.\nNoting: just return option text\nimpact options: "
    bianhao = ['A','B']
    s = 0
    for i in answers:
        s += 1
        prompt = prompt + bianhao[s-1] + '. ' + answers[s-1] + '; '
    prompt = prompt + "\nSimilar vulnerabilities:\n["

    for i in similar_sentences:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
   
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question: Please select the correct impact from the impact options.\nAnswer:' 
    return prompt

def vulnerability_gengerate_zhuguanti1(similar_sentences, target_sentences):
    '''
    Generate a prompt for a subjective question about inferring the target vulnerability type based on similar vulnerability descriptions, key aspects, target vulnerability description, and key aspects.

    Parameters
    ----------
    similar_sentences : list
        List of similar vulnerabilities, each containing a description and key aspects.
    target_sentences : dict
        Target vulnerability description and key aspects.

    Returns
    -------
    prompt : str
        Generated prompt for the subjective question.

    '''
    prompt = "please infer target vulnerability type(Let’s think step by step) based on similar vulnerability description, similar vulnerability key aspect, target vulnerability description and target vulnerability key aspect.\nSimilar vulnerabilities:\n["
    for i in similar_sentences:
        des = i[0]
        aspect = i[1]
        prompt = prompt + '{\nvulnerability description: ' + des + ';\n'
        for j in aspect:
            prompt = prompt + j + ': ' + aspect[j] + '\n'
        prompt = prompt + '},\n'
    prompt = prompt + ']\n' + 'Target vulnerability:\n'
    for i in target_sentences:
        prompt = prompt + i + ': ' + target_sentences[i] + '\n'
    
    prompt = prompt + 'Question:what is the vulnerability type?\nLet’s think step by step\nAnswer:' 
    return prompt

def get_reason(prompt, answer):
    '''
    Get the reasoning for a given prompt and answer using chat-based language model.

    Parameters
    ----------
    prompt : str
        Prompt for the reasoning.
    answer : str
        Answer provided by the user.

    Returns
    -------
    str
        Reasoning generated by the language model.

    '''
    return ask_chatgpt_history(prompt, answer, 'please give your reason step by step.')

def gengerate_answer_byReason(key_aspect_name, reason, sentence):
    '''
    Generate a prompt for inferring the vulnerability description based on reasoning.

    Parameters
    ----------
    key_aspect_name : str
        Key aspect name (e.g., "impact").
    reason : str
        Reasoning basis.
    sentence : str
        Vulnerability description.

    Returns
    -------
    str
        Prompt for inferring the key aspect based on reasoning.

    '''
    prompt = "please infer the " + key_aspect_name + " of the vulnerability description according to reasoning basis.\n" 
    prompt = prompt + "vulnerability description: " + sentence + '\n'
    prompt = prompt + "reasoning basis: " + reason + '\n'
    prompt = prompt + key_aspect_name + ": "
    return prompt
