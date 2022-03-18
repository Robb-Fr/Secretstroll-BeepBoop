from multiprocessing.sharedctypes import Value
from operator import le
import random
from typing import List
import py
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


def test_issue_request_kp_success():
    list_len = random.randint(1, 10)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    user_attributes, issuer_attributes = randomly_split_attributes(attributes)
    user_state, issue_req = create_issue_request(Pk, user_attributes)
    assert verify_issue_request_knowledge_proof(issue_req, Pk)


def test_obtaining_credential_fail():
    # setup parameters
    list_len = random.randint(1, 10)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    user_attributes, issuer_attributes = randomly_split_attributes(attributes)
    # start request
    with pytest.raises(ValueError):
        bad_attr_map = create_failing_map(user_attributes, Pk)
        create_issue_request(Pk, bad_attr_map)

    user_state, issue_req = create_issue_request(Pk, user_attributes)

    with pytest.raises(ValueError):
        bad_attr_map = create_failing_map(issuer_attributes, Pk)
        sign_issue_request(Sk, Pk, issue_req, bad_attr_map)
    with pytest.raises(ValueError):
        fake_keys = generate_key(attributes)
        sign_issue_request(fake_keys[0], fake_keys[1], issue_req, issuer_attributes)
    with pytest.raises(ValueError):
        fake_keys = generate_key(attributes)
        fake_state, fake_issue_request = create_issue_request(
            fake_keys[1], user_attributes
        )
        sign_issue_request(Sk, Pk, fake_issue_request, issuer_attributes)

    blind_sig = sign_issue_request(Sk, Pk, issue_req, issuer_attributes)
    with pytest.raises(ValueError):
        fake_keys = generate_key(attributes)
        obtain_credential(fake_keys[1], blind_sig, user_state)
    with pytest.raises(ValueError):
        fake_keys = generate_key(attributes)
        fake_state, fake_issue_request = create_issue_request(
            fake_keys[1], user_attributes
        )
        fake_sig = sign_issue_request(
            fake_keys[0], fake_keys[1], fake_issue_request, issuer_attributes
        )
        obtain_credential(Pk, fake_sig, fake_state)
    with pytest.raises(ValueError):
        obtain_credential(Pk, blind_sig, (G1.order().random(), user_attributes))
    with pytest.raises(ValueError):
        fake_user_attributes = user_attributes.copy()
        if len(user_attributes) > 0:
            fake_user_attributes[
                random.choice(list(fake_user_attributes.keys()))
            ] = G1.order().random()
        else:
            raise ValueError(
                "This case should expectedly not raise an error, for the test success we raise it voluntarly"
            )
        obtain_credential(Pk, blind_sig, (user_state[0], fake_user_attributes))


## SHOWING PROTOCOL ##


def test_disclosure_proof_verification():
    list_len = random.randint(1, 20)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    user_attributes, issuer_attributes = randomly_split_attributes(attributes)
    # start request
    user_state, issue_req = create_issue_request(Pk, user_attributes)
    blind_sig = sign_issue_request(Sk, Pk, issue_req, issuer_attributes)
    anon_cred = obtain_credential(Pk, blind_sig, user_state)

    hidden_attributes, disclosed_attributes = randomly_split_attributes(attributes)
    msg = random.randbytes(10)

    disc_proof = create_disclosure_proof(Pk, anon_cred, hidden_attributes, msg)

    #assert disclosed_attributes == disc_proof.disclosed_attributes

    assert verify_disclosure_proof(Pk, disc_proof, disclosed_attributes, msg)

#This test passes when disclosed attributes is empty (not when hidden empty)
def test_disclosure_proof_equality():
    list_len = random.randint(1, 20)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    user_attributes, issuer_attributes = randomly_split_attributes(attributes)
    # start request
    user_state, issue_req = create_issue_request(Pk, user_attributes)
    blind_sig = sign_issue_request(Sk, Pk, issue_req, issuer_attributes)
    anon_cred = obtain_credential(Pk, blind_sig, user_state)

    hidden_attributes, disclosed_attributes = randomly_split_attributes(attributes)
    
    sorted_hidden_attributes = dict(sorted(hidden_attributes.items()))
    sorted_disclosed_attributes = dict(sorted(disclosed_attributes.items()))

    # Compute the right side of the proof 
    r, t = G1.order().random(), G1.order().random()
    rnd_sigma_1 = anon_cred.sigma.sigma1**r
    rnd_sigma_2 = (anon_cred.sigma.sigma2 * anon_cred.sigma.sigma1**t) ** r
    sigma1_ghat_t = rnd_sigma_1.pair(Pk.g_hat) ** t
    sigma1_Yhat_a_list = [rnd_sigma_1.pair(Pk.Y_hat_list[i - 1])  ** sorted_hidden_attributes[i] for i in sorted_hidden_attributes.keys()]
    right_side = sigma1_ghat_t * GT.prod(sigma1_Yhat_a_list)

    # Compute the left side of the proof 
    sigma2_ghat = rnd_sigma_2.pair(Pk.g_hat)
    sigma1_Y_a_list = [rnd_sigma_1.pair(Pk.Y_hat_list[i - 1])  ** -sorted_disclosed_attributes[i] for i in sorted_disclosed_attributes.keys()]
    sigma1_Xhat = rnd_sigma_1.pair(Pk.X_hat)
    left_side = (sigma2_ghat * GT.prod(sigma1_Y_a_list)) / sigma1_Xhat

    assert left_side == right_side


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
