from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import collections
import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"  # Set CUDA devices, here disabled

from pip import main
from bert import modeling
from bert import optimization
from bert import tokenization
import tensorflow as tf
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Set TensorFlow log level to 3 (only errors)

import tf_metrics
import pickle
import shutil
from run_sequence_labeling import FLAGS, filed_based_convert_examples_to_features, file_based_input_fn_builder, estimator, Snips_Slot_Filling_Processor

def Extract_concepts(input_text):
    # Initialize processor and tokenizer
    processor = Snips_Slot_Filling_Processor()
    label_list = processor.get_labels()
    id2label = {}
    for (i, label) in enumerate(label_list):
        id2label[i] = label
    tokenizer = tokenization.FullTokenizer(vocab_file=FLAGS.vocab_file, do_lower_case=True)

    # Create a predict example and convert to TFRecord
    predict_example = processor._create_example(input_text, 'test')
    predict_file = os.path.join(FLAGS.output_predict, "predict.tf_record")
    filed_based_convert_examples_to_features(predict_example, label_list,
                                             FLAGS.max_seq_length, tokenizer,
                                             predict_file, mode="test")

    predict_drop_remainder = True if FLAGS.use_tpu else False
    predict_input_fn = file_based_input_fn_builder(
        input_file=predict_file,
        seq_length=FLAGS.max_seq_length,
        is_training=False,
        drop_remainder=predict_drop_remainder)

    # Use the trained model to predict outputs
    result = estimator.predict(input_fn=predict_input_fn)
    outputs = None
    for prediction in result:
        outputs = " ".join(id2label[id] for id in prediction if id != 0).replace('[CLS] ', '').replace(' [SEP]', '').replace(' [##WordPiece]', '')
    return outputs

def get_key_aspect_suoan(text):
    # Prepare input text for prediction
    input_t, input_l = [], []
    input_t.append(text)
    length = len(input_t[0].split())
    input_l.append(' '.join('O' * length))
    input_text = list(zip(input_t, input_l))

    # Get predictions using Extract_concepts function
    output = Extract_concepts(input_text)
    
    s = 0
    loc_vulnerability_type = []
    loc_root_cause = []
    loc_attacker_type = []
    loc_attacker_vector = []
    loc_impact = []

    # Process output to locate different aspects
    for i in output.split(' '):
        if 'vulnerability_type' in i:
            loc_vulnerability_type.append(s)
        if 'root_cause' in i:
            loc_root_cause.append(s)
        if 'attacker_type' in i:
            loc_attacker_type.append(s)
        if 'attacker_vector' in i:
            loc_attacker_vector.append(s)
        if 'impact' in i:
            loc_impact.append(s)
        s += 1

    vulnerability_type = ''
    root_cause = ''
    attacker_type = ''
    attacker_vector = ''
    impact = ''
    t = text
    text = text.split(' ')

    # Check if the length of the output matches the length of the input text
    if len(output.split(' ')) != len(text):
        return {"vulnerability_type": vulnerability_type.strip(), "root_cause": root_cause.strip(),
                "attacker_type": attacker_type.strip(), "attack_vector": attacker_vector.strip(),
                "impact": impact.strip(), "vulnerability_description": t}

    # Extract specific aspects based on their locations
    for i in loc_vulnerability_type:
        vulnerability_type = vulnerability_type + text[i] + ' '
    for i in loc_root_cause:
        root_cause = root_cause + text[i]  + ' '
    for i in loc_attacker_type:
        attacker_type = attacker_type + text[i]    + ' '
    for i in loc_attacker_vector:
        attacker_vector = attacker_vector + text[i]    + ' '
    for i in loc_impact:
        impact = impact + text[i]   + ' '

    return {"vulnerability_type": vulnerability_type.strip(), "root_cause": root_cause.strip(),
            "attacker_type": attacker_type.strip(), "attack_vector": attacker_vector.strip(),
            "impact": impact.strip(), "vulnerability_description": t}

# Example usage:
# a = get_key_aspect_suoan('The jQuery T(-) Countdown Widget WordPress plugin before 2.3.24 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.')
