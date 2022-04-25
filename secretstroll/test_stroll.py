import os
import random
from typing import List

import pytest
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT

from credential import *
from stroll import *

###########
## TESTS ##
###########
MIN_NB_ATTRIBUTES = 5
MAX_NB_ATTRIBUTES = 5


def test_jsonpickle():
    list_len = random.randint(MIN_NB_ATTRIBUTES, MAX_NB_ATTRIBUTES)
    attributes = [G1.order().random() for _ in range(list_len)]
    attributesmap = AttributeMap(dict(enumerate(attributes)))

    attributesmap_serialized = jsonpickle.encode(attributesmap, keys=True).encode()
    attributesmap_deserialized = jsonpickle.decode(attributesmap_serialized, keys=True)

    assert type(attributesmap_serialized) is bytes
    assert attributesmap_deserialized == attributesmap

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


def test_generate_ca(benchmark):
    server = Server()
    client = Client()
    subscriptions = ["baseball", "bar"]
    sk, pk = server.generate_ca(subscriptions)
    benchmark(server.generate_ca, subscriptions)
    sk = jsonpickle.decode(sk)
    pk = jsonpickle.decode(pk)
    assert isinstance(sk, SecretKey) and isinstance(pk, PublicKey)
    # we now make sure the key pair is valid to use
    msgs = [
        jsonpickle.encode(client.client_secret).encode(),
        jsonpickle.encode(str_to_attribute("None")).encode(),
        jsonpickle.encode(str_to_attribute("bar")).encode(),
    ]
    assert verify(pk, sign(sk, msgs), msgs)


def test_issuance_protocol(benchmark):
    server = Server()
    client = Client()
    all_subscriptions = ["stadium", "hotel", "cool location"]
    user_subscription = ["hotel", "stadium"]
    sk, pk = server.generate_ca(all_subscriptions)
    # we make subfunction that captures the functionnality to that we can send it in becnhmark
    def make_registration():
        issue_req, user_state = client.prepare_registration(
            pk, "beepboop", user_subscription
        )
        blind_sig = server.process_registration(
            sk, pk, issue_req, "beepboop", user_subscription
        )
        cred = client.process_registration_response(pk, blind_sig, user_state)

    make_registration()
    benchmark(make_registration)


def test_showing_protocol(benchmark):
    server = Server()
    client = Client()
    all_subscriptions = ["glouglou", "home"]
    sk, pk = server.generate_ca(all_subscriptions)
    user_subscription = ["glouglou"]
    issue_req, user_state = client.prepare_registration(pk, "robb", user_subscription)
    blind_sig = server.process_registration(
        sk, pk, issue_req, "robb", user_subscription
    )
    cred = client.process_registration_response(pk, blind_sig, user_state)
    showed_subscription = ["glouglou"]

    cell_id = "grid 51".encode()
    disc_proof = client.sign_request(pk, cred, cell_id, showed_subscription)
    benchmark(client.sign_request, pk, cred, cell_id, showed_subscription)


def test_verifying_protocol_1(benchmark):
    server = Server()
    client = Client()
    all_subscriptions = ["beach", "waterfall"]
    sk, pk = server.generate_ca(all_subscriptions)
    user_subscription = ["waterfall", "beach"]
    issue_req, user_state = client.prepare_registration(pk, "mama", user_subscription)
    blind_sig = server.process_registration(
        sk, pk, issue_req, "mama", user_subscription
    )
    cred = client.process_registration_response(pk, blind_sig, user_state)
    showed_subscription = ["waterfall"]

    cell_id = "loc 46.52345 6.57890".encode()
    disc_proof = client.sign_request(pk, cred, cell_id, showed_subscription)
    assert server.check_request_signature(pk, cell_id, showed_subscription, disc_proof)
    benchmark(
        server.check_request_signature, pk, cell_id, showed_subscription, disc_proof
    )


def test_verifying_protocol_2(benchmark):
    server = Server()
    client = Client()
    all_subscriptions = ["shadow-moses", "mother-base", "home?", "philosphes"]
    sk, pk = server.generate_ca(all_subscriptions)
    user_subscription = ["home?", "shadow-moses"]
    issue_req, user_state = client.prepare_registration(
        pk, "naked-snake", user_subscription
    )
    blind_sig = server.process_registration(
        sk, pk, issue_req, "naked-snake", user_subscription
    )
    cred = client.process_registration_response(pk, blind_sig, user_state)
    showed_subscription = ["shadow-moses", "home?"]

    cell_id = "grid 100".encode()
    disc_proof = client.sign_request(pk, cred, cell_id, showed_subscription)
    assert server.check_request_signature(pk, cell_id, showed_subscription, disc_proof)
    benchmark(
        server.check_request_signature, pk, cell_id, showed_subscription, disc_proof
    )


def test_protocol_fails():
    server = Server()
    client = Client()
    all_subscriptions = ["pool", "park", "shadow-moses"]
    sk, pk = server.generate_ca(all_subscriptions)

    ## cannot subscribe to unknown attributes ##
    with pytest.raises(ValueError):
        user_subscription = random.choice([[], ["restaurant", "park"]])
        issue_req, user_state = client.prepare_registration(
            pk, "john", user_subscription
        )
        blind_sig = server.process_registration(
            sk, pk, issue_req, "john", user_subscription
        )

    user_subscription = ["shadow-moses", "pool"]
    issue_req, user_state = client.prepare_registration(pk, "john", user_subscription)
    blind_sig = server.process_registration(
        sk, pk, issue_req, "john", user_subscription
    )
    cred = client.process_registration_response(pk, blind_sig, user_state)

    ## cannot show non-existing attributes ##
    with pytest.raises(ValueError):
        showed_subscription = random.choice([[], ["blah"]])
        cell_id = "99".encode()
        disc_proof = client.sign_request(pk, cred, cell_id, showed_subscription)
        server.check_request_signature(pk, cell_id, showed_subscription, disc_proof)

    showed_subscription = random.choice([["park"], ["park", "pool"]])
    cell_id = "loc 46.52365 6.57092".encode()
    disc_proof = client.sign_request(pk, cred, cell_id, showed_subscription)
    ## cannot show attributes the credential does not sign for ##
    assert not server.check_request_signature(
        pk, cell_id, showed_subscription, disc_proof
    )
