import random
from typing import List
from black import assert_equivalent
import pytest
import string

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
    
    attributesmap_serialized = jsonpickle.encode(attributesmap).encode()
    attributesmap_deserialized = jsonpickle.decode(attributesmap_serialized)

    assert type(attributesmap_serialized) is bytes


    #assert attributesmap_deserialized == attributesmap

    sk, pk = generate_key(attributes)
    sk_serialized = jsonpickle.encode(sk).encode()
    assert type(sk_serialized) is bytes
    sk_deserialized = jsonpickle.decode(sk_serialized)

    assert type(sk_deserialized) is SecretKey
    assert sk.x == sk_deserialized.x
    assert sk.X == sk_deserialized.X
    assert sk.y_list == sk_deserialized.y_list
    assert sk.sk == sk_deserialized.sk
    assert sk.L == sk_deserialized.L

    pk_serialized = jsonpickle.encode(pk).encode()
    pk_deserialized = jsonpickle.decode(pk_serialized)
    assert type(pk_deserialized) is PublicKey
    assert type(pk_serialized) is bytes
    assert pk.g == pk_deserialized.g
    assert pk.g_hat == pk_deserialized.g_hat
    assert pk.Y_list == pk_deserialized.Y_list
    assert pk.pk == pk_deserialized.pk
    assert pk.X_hat == pk_deserialized.X_hat
    assert pk.Y_hat_list == pk_deserialized.Y_hat_list
    assert pk.L == pk_deserialized.L

    msgs = attributes_to_bytes(dict(enumerate(attributes)))
    signature = sign(sk, msgs)
    sign_serialized = jsonpickle.encode(signature).encode()
    sign_deserialized = jsonpickle.decode(sign_serialized)
    assert type(sign_deserialized) is Signature
    assert type(sign_serialized) is bytes
    assert signature.sigma == sign_deserialized.sigma 
    assert signature.sigma1 == sign_deserialized.sigma1
    assert signature.sigma2 == sign_deserialized.sigma2 

# def test_str_to_attributemap():
#     subscriptions = ["beach", "cinema", "bar", "museum", "casino"]
#     attributes = dict{1: Bn.from_decimal}


def test_sign():
    # initialise server, client
    server = Server()
    client = Client()

    # setup
    list_len = random.randint(MIN_NB_ATTRIBUTES, MAX_NB_ATTRIBUTES)
    letters = string.digits
    sub_index_upper_bound = max(2, list_len-1)
    subscriptions = [''.join(random.choice(letters) for i in range(length)) for length in range(1,sub_index_upper_bound)]
    username = ''.join(random.choice(letters) for i in range(random.randint(MIN_NB_ATTRIBUTES, MAX_NB_ATTRIBUTES)))
    #msgs = attributes_to_bytes(dict(enumerate(subscriptions)))
    #index_upper_bound = min(0, len(msgs)-1)
    #rand_index = random.randint(0,index_upper_bound)
    #msg = msgs[rand_index]
    msg = os.urandom(10)

    #user_subscriptions, _ = randomly_split_subscriptions(subscriptions)
    hidden_sub, disclosed_sub = randomly_split_subscriptions(subscriptions)


    assert len(subscriptions)>0


    # execute exchanges 
    sk, pk = server.generate_ca(subscriptions)
    issue_req, state = client.prepare_registration(pk, username, subscriptions)
    resp = server.process_registration(sk, pk, issue_req, username, subscriptions)
    cred = client.process_registration_response(pk, resp, state)
    sign = client.sign_request(pk, cred, msg, hidden_sub)

    assert server.check_request_signature(pk, msg, disclosed_sub, sign)






####################################
## TOOLS METHODS FOR COMPUTATIONS ##
####################################


def randomly_split_subscriptions(
    subscriptions: List[str],
) -> Tuple[List[str], List[str]]:
    """From the list of all attributes, split in 2 lists of indices mapped to their related attribute"""
    L = len(subscriptions)
    # creates sguffled dict with keys in [1,L]
    shuffled_subscriptions = subscriptions.copy()
    random.shuffle(shuffled_subscriptions)
    split_index = random.randint(0, L)
    user_subs = shuffled_subscriptions[:split_index]
    issuer_subs = shuffled_subscriptions[split_index:]

    return user_subs, issuer_subs


# def create_failing_map(attributes: AttributeMap, Pk: PublicKey) -> AttributeMap:
#     """Creates an attributes map that should fail check_attribute_map"""
#     list_len = Pk.L
#     bad_key = random.choice(
#         [random.randint(-1000, 0), random.randint(list_len + 1, 1000)]
#     )  # a key that is not in [1,L]
#     good_key = (
#         random.choice(list(attributes.keys())) if len(attributes) > 0 else 0
#     )  # a key in the interval (0 if empty -> value won't be used)
#     too_long_attributes = attributes.copy()
#     for i in range(list_len + random.randint(1, 10) - len(attributes)):
#         # we make the dictionnary too big
#         too_long_attributes[bad_key + i] = G1.order().random()
#     bad_key_attributes = attributes.copy()
#     if len(attributes) > 0:
#         # we replace a good key by a bad key
#         bad_key_attributes.pop(good_key)
#     # if was empty, should anyway fail as above
#     bad_key_attributes[bad_key] = G1.order().random()
#     return random.choice([too_long_attributes, bad_key_attributes])
