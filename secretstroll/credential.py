"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import Any, List, Tuple

from serialization import jsonpickle

from petrelic.bn import Bn

# Multiplicative pairing to preserve PS guide notations
from petrelic.multiplicative.pairing import G1Element, G2Element, G1, G2

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
# SecretKey = List[Any]
# PublicKey = List[Any]
# Signature = Any
Attribute = Bn  # a mod p element (p the order of pairing groups)
AttributeMap = dict[int, Bn]
# IssueRequest = Any
# BlindSignature = Any
# AnonymousCredential = Any
DisclosureProof = Any
UserState = Tuple[Bn, AttributeMap]


class SecretKey:
    def __init__(self, x: Bn, g: G1Element, y_list: List[Bn]) -> None:
        self.x = x
        self.X = g**x
        self.y_list = y_list
        self.sk = [self.x, self.X] + self.y_list
        self.L = len(self.y_list)


class PublicKey:
    def __init__(
        self, g: G1Element, y_list: List[Bn], g_hat: G2Element, X_hat: G2Element
    ) -> None:
        """Passing X_hat makes more sense in the sense of Public key: we should not make available to a public instance the secret x"""
        self.g = g
        self.Y_list = [g**y for y in y_list]
        self.g_hat = g_hat
        self.X_hat = X_hat
        self.Y_hat_list = [g_hat**y for y in y_list]
        self.pk = [self.g] + self.Y_list + [self.g_hat, self.X_hat] + self.Y_hat_list
        self.L = len(self.Y_list)


class Signature:
    def __init__(self, sigma1: G1Element, sigma2: G1Element) -> None:
        self.sigma = (sigma1, sigma2)
        self.sigma1 = self.sigma[0]
        self.sigma2 = self.sigma[1]


class IssueRequest:
    def __init__(self, C: G1Element) -> None:
        self.C = C


class BlindSignature:
    def __init__(
        self, g_u: G1Element, prod_u: G1Element, issuer_attributes: AttributeMap
    ) -> None:
        self.sigma = (g_u, prod_u)
        self.sigma1 = g_u
        self.sigma2 = prod_u
        self.issuer_attributes = issuer_attributes


class AnonymousCredential:
    def __init__(self, sigma: Signature, attributes: AttributeMap) -> None:
        self.sigma = sigma
        self.attributes = attributes


######################
## SIGNATURE SCHEME ##
######################


def generate_key(attributes: List[Attribute]) -> Tuple[SecretKey, PublicKey]:
    """Generate signer key pair"""
    l = len(attributes)
    if l < 1:
        raise ValueError("There must be at least one attribute")

    y_list = [G1.order().random() for _ in range(l)]
    x = G1.order().random()

    g = G1.generator()
    g_hat = G2.generator()

    Sk = SecretKey(x, g, y_list)
    Pk = PublicKey(g, y_list, g_hat, g_hat**x)

    return (Sk, Pk)


def sign(sk: SecretKey, msgs: List[bytes]) -> Signature:
    """Sign the vector of messages `msgs`"""
    if sk.L != len(msgs):
        raise ValueError(
            "Messages should have length L, the number of signed attributes"
        )

    y_m_product = [sk.y_list[i] * jsonpickle.decode(msgs[i]) for i in range(sk.L)]
    exponent = sk.x + sum(y_m_product)
    h = G1.generator()
    h_exp = h**exponent

    return Signature(h, h_exp)


def verify(pk: PublicKey, signature: Signature, msgs: List[bytes]) -> bool:
    """Verify the signature on a vector of messages"""
    if pk.L != len(msgs):
        raise ValueError(
            "Messages should have length L, the number of signed attributes"
        )
    if signature.sigma1 == G1.unity():  # unity is alias for neutral element
        # immediatly discards the case when sigma_1 is 1
        return False
    # creates the list of Y_i^m_i elements
    Y_hat_m_list = list(
        map(
            lambda Y_and_m: Y_and_m[0] ** jsonpickle.decode(Y_and_m[1]),
            zip(pk.Y_hat_list, msgs),
        )
    )
    public_product = pk.X_hat * G2.prod(Y_hat_m_list)
    left_side = signature.sigma1.pair(public_product)
    right_side = signature.sigma2.pair(pk.g_hat)

    return left_side == right_side


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##


def create_issue_request(
    pk: PublicKey, user_attributes: AttributeMap
) -> Tuple[UserState, IssueRequest]:
    """Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    Args:
        pk: the public key of the issuer
        user_attributes: the map of user selected attributes a_i for i in U

    Returns:
        tuple containing:
            - the t value used to as commitment witness, to be passed to the obtain credential_function
            - the request object to be sent to the issuer. Should not contain the witness as made to be sent as is to the issuer

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    if not check_attribute_map(user_attributes, pk.L):
        raise ValueError(
            "Incorrect attributes map: should be a dict of 0 to L values with keys in [1,L]"
        )
    t = G1.order().random()
    user_state = (t, user_attributes)
    if len(user_attributes) == 0:
        # deals early with the case where no user attributes to sign
        return user_state, IssueRequest(pk.g**t)
    # must take into account the Y_list index are in [0,L-1] and attributes in [1,L]
    Y_a_list = [pk.Y_list[i - 1] ** user_attributes[i] for i in user_attributes.keys()]
    commit_product = (pk.g**t) * G1.prod(Y_a_list)

    return user_state, IssueRequest(commit_product)


def sign_issue_request(
    sk: SecretKey, pk: PublicKey, request: IssueRequest, issuer_attributes: AttributeMap
) -> BlindSignature:
    """Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    if not check_attribute_map(issuer_attributes, pk.L):
        raise ValueError(
            "Incorrect attributes map: should be a dict of 0 to L values with keys in [1,L]"
        )
    # TODO implement the proof check
    u = G1.order().random()
    g_u = pk.g**u
    if len(issuer_attributes) == 0:
        # deals early with the case where no issuer attributes to sign
        return BlindSignature(g_u, (sk.X * request.C) ** u, issuer_attributes)

    # must take into account the Y_list index are in [0,L-1] and attributes in [1,L]
    Y_a_list = [
        pk.Y_list[i - 1] ** issuer_attributes[i] for i in issuer_attributes.keys()
    ]
    prod = sk.X * request.C * G1.prod(Y_a_list)
    prod_u = prod**u

    return BlindSignature(g_u, prod_u, issuer_attributes)


def obtain_credential(
    pk: PublicKey, response: BlindSignature, state: UserState
) -> AnonymousCredential:
    """Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.

    Args:
        pk: the public key of the issuer
        response: the blind signature containing the intermediate signature and the list of attributes intermediatly signed

    Returns:
        anonymous credential object containing the PS signature along with the attributes list it signs for

    """
    t, user_attributes = state
    if pk.L != len(user_attributes) + len(response.issuer_attributes):
        raise ValueError(
            "The sum of issuer and user signed attributes should be equal to L"
        )
    sigma1 = response.sigma1
    sigma2 = response.sigma2 / (sigma1**t)
    sigma = Signature(sigma1, sigma2)
    all_attributes = user_attributes | response.issuer_attributes
    sorted_all_attributes = dict(sorted(all_attributes.items()))
    if not verify(pk, sigma, attributes_to_bytes(sorted_all_attributes)):
        raise ValueError(
            "The provided signature is not valid for all the given attributes"
        )
    return AnonymousCredential(sigma, sorted_all_attributes)


## SHOWING PROTOCOL ##


def create_disclosure_proof(
    pk: PublicKey,
    credential: AnonymousCredential,
    hidden_attributes: List[Attribute],
    message: bytes,
) -> DisclosureProof:
    """Create a disclosure proof"""
    raise NotImplementedError()


def verify_disclosure_proof(
    pk: PublicKey, disclosure_proof: DisclosureProof, message: bytes
) -> bool:
    """Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    raise NotImplementedError()


####################################
## TOOLS METHODS FOR COMPUTATIONS ##
####################################


def check_attribute_map(attributes: AttributeMap, L: int) -> bool:
    if len(attributes) > L:
        # checks if there are too many attributes
        return False
    for index in attributes.keys():
        # check if indexes reference valid attributes
        if index < 1 or index > L:
            return False
    return True


def attributes_to_bytes(attributes: AttributeMap) -> List[bytes]:
    return list(map(lambda bn: jsonpickle.encode(bn), attributes.values()))
