import random
import pytest
import credential
from petrelic.multiplicative.pairing import G1, G2, GT, Bn
from os import urandom

def test_generate_key_success():
    list_len = random.randint(0, 30)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = credential.generate_key(attributes)
    assert Sk.L == list_len
    assert len(Sk.sk) == list_len + 2
    assert Pk.L == list_len
    assert len(Pk.pk) == 2 * list_len + 3


def test_generate_key_fail():
    attributes = []
    with pytest.raises(IndexError):
        credential.generate_key(attributes)


def test_sign_success():
    list_len = random.randint(0, 30)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = credential.generate_key(attributes)
    msgs = [urandom(16) for _ in range(list_len)]
    sigma = credential.sign(Sk, msgs)

    assert credential.verify(Pk, sigma, msgs)


def test_sign_fail():
    list_len = random.randint(0, 30)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = credential.generate_key(attributes)
    msgs = [urandom(16) for _ in range(list_len)]
    sigma = credential.sign(Sk, msgs)

    with pytest.raises(IndexError):
        assert credential.verify(Pk, sigma, [])

    with pytest.raises(ValueError):
        assert credential.verify(
            Pk, credential.Signature(G1.unity(), G1.order().random()), msgs
        )

    fake_Sk, fake_Pk = credential.generate_key(attributes)
    assert not credential.verify(fake_Pk, sigma, msgs)
