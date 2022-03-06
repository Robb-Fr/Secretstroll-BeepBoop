import random
import pytest
from credential import *
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT
from os import urandom

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
    msgs = [urandom(16) for _ in range(list_len)]
    sigma = sign(Sk, msgs)

    assert verify(Pk, sigma, msgs)


def test_sign_fail():
    list_len = random.randint(1, 30)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    msgs = [urandom(16) for _ in range(list_len)]
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
    list_len = random.randint(1, 30)
    attributes = [G1.order().random() for _ in range(list_len)]
    Sk, Pk = generate_key(attributes)
    split_attributes = randomly_split_attributes(attributes)
    user_attributes = split_attributes[0]
    issuer_attributes = split_attributes[1]
    pass


## SHOWING PROTOCOL ##

####################################
## TOOLS METHODS FOR COMPUTATIONS ##
####################################


def randomly_split_attributes(
    attributes: List[Attribute],
) -> Tuple[AttributeMap, AttributeMap]:
    """From the list of all attributes, split in 2 lists of indices mapped to their related attribute"""
    L = len(attributes)
    shuffled_attributes = list(enumerate(attributes))
    random.shuffle(shuffled_attributes)
    split_index = random.randint(1, L)
    return dict(shuffled_attributes[:split_index]), dict(
        shuffled_attributes[split_index:]
    )
