import random
from typing import List
from black import assert_equivalent
import pytest

from credential import *
from stroll import * 
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT
import os

###########
## TESTS ##
###########
MIN_NB_ATTRIBUTES = 1
MAX_NB_ATTRIBUTES = 10

def test_jsonpickle():
    list_len = random.randint(MIN_NB_ATTRIBUTES, MAX_NB_ATTRIBUTES)
    attributes = [G1.order().random() for _ in range(list_len)]
    attributesmap = AttributeMap(dict(enumerate(attributes)))
    
    attributesmap_serialized = jsonpickle.encode(attributesmap)
    attributesmap_deserialized = jsonpickle.decode(attributesmap_serialized)

    assert attributesmap_deserialized == attributesmap

    sk, pk = generate_key(attributes)
    sk_serialized = jsonpickle.encode(sk)
    sk_deserialized = jsonpickle.decode(sk_serialized)
    pk_serialized = jsonpickle.encode(pk)
    pk_deserialized = jsonpickle.decode(pk_serialized)

    assert sk == sk_deserialized
    assert pk == pk_deserialized


    


####################################
## TOOLS METHODS FOR COMPUTATIONS ##
####################################


def randomly_split_attributes(
    attributes: List[Attribute],
) -> Tuple[AttributeMap, AttributeMap]:
    """From the list of all attributes, split in 2 lists of indices mapped to their related attribute"""
    L = len(attributes)
    # creates sguffled dict with keys in [1,L]
    shuffled_attributes = list(map(lambda i: (i[0] + 1, i[1]), enumerate(attributes)))
    random.shuffle(shuffled_attributes)
    split_index = random.randint(0, L)
    user_attributes = dict(shuffled_attributes[:split_index])
    issuer_attributes = dict(shuffled_attributes[split_index:])

    return user_attributes, issuer_attributes


def create_failing_map(attributes: AttributeMap, Pk: PublicKey) -> AttributeMap:
    """Creates an attributes map that should fail check_attribute_map"""
    list_len = Pk.L
    bad_key = random.choice(
        [random.randint(-1000, 0), random.randint(list_len + 1, 1000)]
    )  # a key that is not in [1,L]
    good_key = (
        random.choice(list(attributes.keys())) if len(attributes) > 0 else 0
    )  # a key in the interval (0 if empty -> value won't be used)
    too_long_attributes = attributes.copy()
    for i in range(list_len + random.randint(1, 10) - len(attributes)):
        # we make the dictionnary too big
        too_long_attributes[bad_key + i] = G1.order().random()
    bad_key_attributes = attributes.copy()
    if len(attributes) > 0:
        # we replace a good key by a bad key
        bad_key_attributes.pop(good_key)
    # if was empty, should anyway fail as above
    bad_key_attributes[bad_key] = G1.order().random()
    return random.choice([too_long_attributes, bad_key_attributes])
