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

from sys import byteorder

# Multiplicative pairing to preserve PS guide notations
from petrelic.multiplicative.pairing import G1, G2, GT, Bn, G1Element, G2Element

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
# SecretKey = List[Any]
# PublicKey = List[Any]
# Signature = Any
Attribute = Bn  # a mod p element (p the order of pairing groups)
AttributeMap = Any
IssueRequest = Any
BlindSignature = Any
AnonymousCredential = Any
DisclosureProof = Any


class SecretKey:
    def __init__(self, x: Bn, g: G1Element, y_list: List[Bn]) -> None:
        self.x = x
        self.X = g**x
        self.y_list = y_list
        self.sk = [self.x, self.X] + self.y_list
        self.L = len(self.y_list)


class PublicKey:
    def __init__(
        self, g: Bn, y_list: List[Bn], g_hat: G2Element, X_hat: G2Element
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
    def __init__(self, h: G1Element, exponent: Bn) -> None:
        self.h = h
        self.sigma = (h, h**exponent)
        self.sigma1 = self.sigma[0]
        self.sigma2 = self.sigma[1]


######################
## SIGNATURE SCHEME ##
######################


def generate_key(attributes: List[Attribute]) -> Tuple[SecretKey, PublicKey]:
    """Generate signer key pair"""
    l = len(attributes)
    if l < 1:
        raise IndexError("There must be at list one attribute")

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
        raise IndexError(
            "Messages should have length L, the number of signed attributes"
        )

    y_m_product = [sk.y_list[i] * bytes_to_Bn(msgs[i]) for i in range(sk.L)]
    exponent = sk.x + sum(y_m_product)
    h = G1.generator()

    return Signature(h, exponent)


def verify(pk: PublicKey, signature: Signature, msgs: List[bytes]) -> bool:
    """Verify the signature on a vector of messages"""
    if pk.L != len(msgs):
        raise IndexError(
            "Messages should have length L, the number of signed attributes"
        )
    if signature.sigma1 == G1.unity():  # unity is alias for neutral element
        raise ValueError("Sigma_1 should not be the neutral element")
    # creates the list of Y_i^m_i elements
    Y_hat_m_list = list(
        map(
            lambda Y_and_m: Y_and_m[0] ** bytes_to_Bn(Y_and_m[1]),
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


def create_issue_request(pk: PublicKey, user_attributes: AttributeMap) -> IssueRequest:
    """Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    raise NotImplementedError()


def sign_issue_request(
    sk: SecretKey, pk: PublicKey, request: IssueRequest, issuer_attributes: AttributeMap
) -> BlindSignature:
    """Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    raise NotImplementedError()


def obtain_credential(pk: PublicKey, response: BlindSignature) -> AnonymousCredential:
    """Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    raise NotImplementedError()


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


def bytes_to_Bn(b: bytes):
    return Bn(int.from_bytes(b, byteorder))
