import random
from typing import List
import pytest
import sys

from credential import *
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT

######################
## SIGNATURE SCHEME ##
######################


def test_generate_key_success():
    list_len = random.randint(1, 30)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    assert Sk.L == list_len
    assert len(Sk.sk) == list_len + 2
    assert Pk.L == list_len
    assert len(Pk.pk) == 2 * list_len + 3


def test_generate_key_fail():
    attributes = []
    with pytest.raises(ValueError):
        generate_key(attributes)


def test_sign_success():
    list_len = random.randint(1, 30)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    msgs = attributes_to_bytes(dict(enumerate(attributes)))
    sigma = sign(Sk, msgs)

    assert verify(Pk, sigma, msgs)


def test_sign_fail():
    list_len = random.randint(1, 30)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    msgs = attributes_to_bytes(dict(enumerate(attributes)))
    sigma = sign(Sk, msgs)

    with pytest.raises(ValueError):
        assert verify(Pk, sigma, [])

    assert not verify(Pk, Signature(G1.unity(), G1.unity()), msgs)

    fake_Sk, fake_Pk = generate_key(attributes)
    assert not verify(fake_Pk, sigma, msgs)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##


def test_obtaining_credentials_succes():
    # setup parameters
    list_len = random.randint(1, 10)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    user_attributes, issuer_attributes = randomly_split_attributes(attributes)
    # start request
    user_state, issue_req = create_issue_request(Pk, user_attributes)
    blind_sig = sign_issue_request(Sk, Pk, issue_req, issuer_attributes)
    anon_cred = obtain_credential(Pk, blind_sig, user_state)
    # if no error thrown, success


def test_zkp_success():
    list_len = random.randint(1, 10)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    user_attributes, issuer_attributes = randomly_split_attributes(attributes)
    user_state, issue_req = create_issue_request(Pk, user_attributes)
    assert verify_zero_knowledge_proof(issue_req, Pk)


## SHOWING PROTOCOL ##

def test_disclosure_proof_verification():
    list_len = random.randint(1, 10)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    user_attributes, issuer_attributes = randomly_split_attributes(attributes)
    # start request
    user_state, issue_req = create_issue_request(Pk, user_attributes)
    blind_sig = sign_issue_request(Sk, Pk, issue_req, issuer_attributes)
    anon_cred = obtain_credential(Pk, blind_sig, user_state)

    hidden_attributes, disclosed_attributed = randomly_split_attributes(user_attributes)
    msgs = attributes_to_bytes(dict(enumerate(disclosed_attributed)))

    disc_proof = create_disclosure_proof(Pk, anon_cred, hidden_attributes, msgs[0])

    assert verify_disclosure_proof(Pk, disc_proof, msgs[0])



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
