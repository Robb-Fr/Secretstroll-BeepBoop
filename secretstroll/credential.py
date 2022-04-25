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

from hashlib import sha256
from typing import Any, List, Tuple

from petrelic.bn import Bn

# Multiplicative pairing to preserve PS guide notations
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element, G2Element

from serialization import jsonpickle

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
# SecretKey = List[Any]
# PublicKey = List[Any]
# Signature = Any
Attribute = Bn
"""A mod p element (p the order of pairing groups). Bn values might be derived from a string representation, but are here used in their Bn form for computations. One should ensure those are strictly positive numbers to be able to serialize this using `binary()` method for Bn"""
AttributeMap = dict[int, Bn]
"""Map from an attribute index to its Bn value: {i->a_i}
The full map of attributes is expected to have:
- i=1 -> user secret Bn representation (can be any Bn mod order(Q1))
- i>1 -> subscription Bn representation (or None)"""
# IssueRequest = Any
# BlindSignature = Any
# AnonymousCredential = Any
# DisclosureProof = Any
tAndUserAttributes = Tuple[Bn, AttributeMap]
"""Contains secret values t (random secret to produce commitment value) and the user_attributes that will be blindly signed. This will be used by the user to compute their full credential"""

ATTRIBUTE_MAP_ERROR = "Incorrect attributes map: Checks if an attribute map content is consistent with requirements on: - length, there cannot be more than `pk.all_attributes` as it stores all the possible attributes of the system - all index,attribute pair, (see `check_index_attribute_valid`)"


class SecretKey:
    """Stores the private key values: x, X, [y_1,...,y_L] and L value"""

    def __init__(self, x: Bn, g: G1Element, y_list: List[Bn]) -> None:
        self.x = x.mod(G1.order())
        self.X = g**x
        self.y_list = list(map(lambda x: x.mod(G1.order()), y_list))
        self.sk = [self.x, self.X] + self.y_list
        self.L = len(self.y_list)


class PublicKey:
    """Stores the public key values: g, [Y_1,...,Y_L], g_hat, X_hat, [Y_hat_1,...,Y_hat_L] and values L along with all_attributes, concatenating:
    - the Bn representation of None value at first index (the one dedicated to user secret attribute). Allows to make `None` a valid attribute.
    - the Bn representation of all subscription, assuming correct ordering"""

    def __init__(
        self,
        g: G1Element,
        y_list: List[Bn],
        g_hat: G2Element,
        X_hat: G2Element,
        all_attributes: List[Attribute],
    ) -> None:
        self.g = g
        self.Y_list = [g**y for y in y_list]
        self.g_hat = g_hat
        self.X_hat = X_hat
        self.Y_hat_list = [g_hat**y for y in y_list]
        self.pk = [self.g] + self.Y_list + [self.g_hat, self.X_hat] + self.Y_hat_list
        self.L = len(self.Y_list)
        self.all_attributes = all_attributes


class Signature:
    """Stores the pair of G1Elements representing the signature"""

    def __init__(self, sigma1: G1Element, sigma2: G1Element) -> None:
        self.sigma = (sigma1, sigma2)
        self.sigma1 = self.sigma[0]
        self.sigma2 = self.sigma[1]


class PedersenKnowledgeProof:
    """Contains all the necessary values to verify a Zero Knowledge proof under a Pederson Commited value with Fiat Schamir heuristic. Not called Zero Knowledge as the heuristic trace cannot be simulated

    Args:
        challenge: the computed challenge corresponding to the hash of public values and commitment

        response_0: the response corresponding to the first secret commited value (t value). It is separated to catch the possibility of making a simple Schnorr's proof

        response_attr_index: a tuple containing:
            - the response value for the secret attribute
            - the secret attribute index for the verifier to identify which public key to put to the response power"""

    def __init__(
        self,
        challenge: Bn,
        response_0: Bn,
        response_attr_index: List[Tuple[Attribute, int]],
    ) -> None:
        """We make sure all the received attributes are taken modulo G1 order (making them positive)"""
        self.challenge = challenge.mod(G1.order())
        self.response_0 = response_0.mod(G1.order())
        self.response_index = list(
            map(lambda x: (x[0].mod(G1.order()), x[1]), response_attr_index)
        )


class IssueRequest:
    """Stores both values to create an issue request, object to be sent to the credential issuer.

    Args:
        C: the commit value to be blindly signed by the issuer
        pi: the non-interractive proof of knowledge the prove the user owns secrets values t and (a_i), i in U"""

    def __init__(self, com: G1Element, pi: PedersenKnowledgeProof) -> None:
        self.com = com
        self.pi = pi


class BlindSignature:
    """Stores both G1Element of the sigma' blind signature generated by the issuer. The issuer_attributes are stored there to let these accessible to the user that will compute the anonymous credential"""

    def __init__(
        self, g_u: G1Element, prod_u: G1Element, issuer_attributes: AttributeMap
    ) -> None:
        self.sigma = (g_u, prod_u)
        self.sigma1 = g_u
        self.sigma2 = prod_u
        self.issuer_attributes = issuer_attributes


class AnonymousCredential:
    """Stores the final anonymous credential and all the attributes it signs for. Takes care of taking the attributes modulo G1 order as all attribute representations in Bn should be"""

    def __init__(self, sigma: Signature, attributes: AttributeMap) -> None:
        self.sigma = sigma
        self.attributes = dict(
            map(lambda x: (x[0], x[1].mod(G1.order())), attributes.items())
        )


class DisclosureProof:
    """Store the randomized signature signing for the disclosed attributes and the associate non-interactive proof of knowledge. Does not store the disclosed attributes in order to keep the create_disclosure_proof function signature. The disclosed attributes should be sent alongside this proof"""

    def __init__(self, sigma: Signature, proof: PedersenKnowledgeProof) -> None:
        self.sigma = sigma
        self.pi = proof


######################
## SIGNATURE SCHEME ##
######################


def generate_key(attributes: List[Attribute]) -> Tuple[SecretKey, PublicKey]:
    """Generate signer key pair"""
    l = len(attributes)
    if l < 1:
        raise ValueError("There must be at least one attribute")
    for attr in attributes:
        if not isinstance(attr, Bn) or not attr >= 0:
            raise TypeError("Attributes should be Bn positive objects")

    y_list = [G1.order().random() for _ in range(l)]
    x = G1.order().random()

    g = G1.generator()
    g_hat = G2.generator()

    Sk = SecretKey(x, g, y_list)
    Pk = PublicKey(g, y_list, g_hat, g_hat**x, attributes)

    return (Sk, Pk)


def sign(sk: SecretKey, msgs: List[bytes]) -> Signature:
    """Sign the vector of messages `msgs`.
    Args:
        sk: the signer secret key
        msgs: a list of bytes vector messages. We assume a jsonpickle encoded python object that can be decoded to a Bn object. The jsonpickle decoded object m_i is set to power g ** m_i with g a G1 element.
    """
    if sk.L != len(msgs):
        raise ValueError("Messages should have length L")
    for msg in msgs:
        if not isinstance(jsonpickle.decode(msg), Bn):
            raise TypeError("Messages should be jsonpickle encoded Bn objects")

    y_m_product = [sk.y_list[i] * jsonpickle.decode(msgs[i]) for i in range(sk.L)]
    exponent = sk.x + sum(y_m_product)
    h = G1.generator()
    h_exp = h**exponent

    return Signature(h, h_exp)


def verify(pk: PublicKey, signature: Signature, msgs: List[bytes]) -> bool:
    """Verify the signature on a vector of messages.
    Args:
        pk: the signer public key
        signature: the tested signature for the messages
        msgs: a list of bytes vector messages. We assume a jsonpickle encoded python object that can be decoded to a Bn object. The jsonpickle decoded object m_i is set to power g ** m_i with g a G1 element.
    """
    if pk.L != len(msgs):
        raise ValueError("Messages should have length L")

    for msg in msgs:
        if not isinstance(jsonpickle.decode(msg), Bn):
            raise TypeError("Messages should be jsonpickle encoded Bn objects")

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
) -> Tuple[tAndUserAttributes, IssueRequest]:
    """Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    Args:
        pk: the public key of the issuer
        user_attributes: the map of user selected attributes a_i for i in U

    Returns:
        tuple containing:
            - the user state containing the witness t used to generate the commit value and the attribute map of the user credentials that will be blindly signed by the signer. To be used in the obtain_credential function
            - the request object to be sent to the issuer. This is made to be sent as is to the issuer.
    """
    if not check_attribute_map(user_attributes, pk):
        raise ValueError(ATTRIBUTE_MAP_ERROR)
    t = G1.order().random()
    user_state = (t, user_attributes)
    # computes the product of Y_i^a_i for all i in the user attributes indexes
    # must take into account the Y_list index are in [0,L-1] and attributes in [1,L]
    Y_a_list = [pk.Y_list[i - 1] ** user_attributes[i] for i in user_attributes.keys()]
    com = (pk.g**t) * G1.prod(Y_a_list)
    kp = create_issue_request_knowledge_proof(pk, t, user_attributes, com)
    if len(user_attributes) == 0:
        # deals early with the case where no user attributes to sign
        return user_state, IssueRequest(pk.g**t, kp)
    return user_state, IssueRequest(com, kp)


def sign_issue_request(
    sk: SecretKey, pk: PublicKey, request: IssueRequest, issuer_attributes: AttributeMap
) -> BlindSignature:
    """Create a signature corresponding to the user's request

    This corresponds to the "issuer signing" step in the issuance protocol.
    """
    if not check_attribute_map(issuer_attributes, pk):
        raise ValueError(ATTRIBUTE_MAP_ERROR)
    if not verify_issue_request_knowledge_proof(request, pk):
        raise ValueError(
            "Incorrect proof of knowledge associated with the issue request"
        )
    u = G1.order().random()
    g_u = pk.g**u
    if len(issuer_attributes) == 0:
        # deals early with the case where no issuer attributes to sign
        return BlindSignature(g_u, (sk.X * request.com) ** u, issuer_attributes)

    # computes the product of Y_i^a_i for all i in the issuer attributes indexes
    # must take into account the Y_list index are in [0,L-1] and attributes in [1,L]
    Y_a_list = [
        pk.Y_list[i - 1] ** issuer_attributes[i] for i in issuer_attributes.keys()
    ]
    prod = sk.X * request.com * G1.prod(Y_a_list)
    prod_u = prod**u
    return BlindSignature(g_u, prod_u, issuer_attributes)


def obtain_credential(
    pk: PublicKey, response: BlindSignature, state: tAndUserAttributes
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
    if not check_attribute_map(
        response.issuer_attributes, pk
    ) or not check_attribute_map(user_attributes, pk):
        raise ValueError(ATTRIBUTE_MAP_ERROR)
    if pk.L != len(user_attributes) + len(response.issuer_attributes):
        raise ValueError(
            "The sum of issuer and user signed attributes should be equal to L"
        )
    sigma1 = response.sigma1
    sigma2 = response.sigma2 / (sigma1**t)
    sigma = Signature(sigma1, sigma2)
    # we sort the dict to have the attributes aligned with their index
    sorted_all_attributes = dict(
        sorted((user_attributes | response.issuer_attributes).items())
    )
    if not verify(pk, sigma, attributes_to_bytes(sorted_all_attributes)):
        raise ValueError(
            "The provided signature is not valid for all the given attributes"
        )
    return AnonymousCredential(sigma, sorted_all_attributes)


def create_issue_request_knowledge_proof(
    pk: PublicKey, t: Bn, user_attributes: AttributeMap, com: G1Element
) -> PedersenKnowledgeProof:
    """Create the Zero Knowledge Proof object that shows knowledge of commit value t and attributes (a_i) for i in U, the user attributes hidden to issuer. Follows the Pederson commitment implementation from Exercice Set 1.2 with a non-interactive adaptation"""
    randoms = [G1.order().random()]
    U = len(user_attributes)
    R = pk.g ** randoms[0]
    sorted_user_attributes = dict(sorted(user_attributes.items()))
    if U > 0:
        r_list = [G1.order().random() for _ in range(U)]
        # Computes the list of Y_i^r_j for i in U (user attributes' indexes) and j in [1,...,|U|] (number of user attributes)
        Y_s_prod = [
            pk.Y_list[i - 1] ** r_list[j]
            for j, i in enumerate(sorted_user_attributes.keys())
        ]
        randoms += r_list
        R *= G1.prod(Y_s_prod)
    challenge = Bn.from_hex(
        sha256(jsonpickle.encode((pk.pk, R, com)).encode()).hexdigest()
    ).mod(G1.order())

    responses = [randoms[0] - challenge * t]
    response_index = []
    if U > 0:
        # computes a list of responses s = r - c * a_i
        responses += [
            rnd - challenge * attr
            for rnd, attr in zip(randoms[1:], sorted_user_attributes.values())
        ]
        response_index = list(zip(responses[1:], sorted_user_attributes.keys()))
    return PedersenKnowledgeProof(challenge, responses[0], response_index)


def verify_issue_request_knowledge_proof(
    issue_req: IssueRequest, pk: PublicKey
) -> bool:
    """Verifies the Zero Knowledge Proof object that shows knowledge of commit value t and attributes (a_i) for i in U, the user attributes hidden to issuer. Follows the Pederson commitment implementation from Exercice Set 1.2 with a non-interactive adaptation"""
    com, pi = issue_req.com, issue_req.pi
    R_prime = com**pi.challenge * pk.g**pi.response_0
    if len(pi.response_index) > 0:
        R_prime *= G1.prod(
            [pk.Y_list[index - 1] ** resp for resp, index in pi.response_index]
        )
    challenge_prime = Bn.from_hex(
        sha256(jsonpickle.encode((pk.pk, R_prime, com)).encode()).hexdigest()
    ).mod(G1.order())
    return pi.challenge == challenge_prime


## SHOWING PROTOCOL ##


def create_disclosure_proof(
    pk: PublicKey,
    credential: AnonymousCredential,
    hidden_attributes: AttributeMap,
    message: bytes,
) -> DisclosureProof:
    """
    Create a disclosure proof

    See ABC_guide, Showing Protocol 2.b for the proof.
    We have a proof such that pi = PK{(t,hidden attributes) : left_side(disclosed attributes) = right_side(t, hidden_attributes)}

    To create the proof we compute the right_side with random elements instead of the secrets. This is our R value. We then send a challenge based on R as well as elements constructed from the secrets and their random counterparts (responses), this is a done in a Pederson proof of knowledge way but adapted to the GT group
    """
    if not check_attribute_map(credential.attributes, pk) or not check_attribute_map(
        hidden_attributes, pk
    ):
        raise ValueError(ATTRIBUTE_MAP_ERROR)
    sorted_hidden_attributes = dict(sorted(hidden_attributes.items()))
    H = len(sorted_hidden_attributes)

    r, t = GT.order().random(), GT.order().random()
    randoms = [GT.order().random()]

    # Compute the right side of the proof with "fake" secrets as the commit
    rnd_sigma_1 = credential.sigma.sigma1**r
    rnd_sigma_2 = (credential.sigma.sigma2 * credential.sigma.sigma1**t) ** r
    sign = Signature(rnd_sigma_1, rnd_sigma_2)

    R = rnd_sigma_1.pair(pk.g_hat) ** randoms[0]
    com = rnd_sigma_1.pair(pk.g_hat) ** t

    if H > 0:
        ai_prime_list = [GT.order().random() for _ in range(H)]
        # Computes the list of Y_i^r_j for i in U (user attributes' indexes) and j in [1,...,|U|] (number of user attributes)
        Y_hat_r_prod = [
            rnd_sigma_1.pair(pk.Y_hat_list[i - 1]) ** ai_prime_list[ai_index]
            for ai_index, i in enumerate(sorted_hidden_attributes.keys())
        ]
        # Computes the com value as the product of Y_i^a_i for i in the hidden attributes indexes
        Y_hat_a_prod = [
            rnd_sigma_1.pair(pk.Y_hat_list[i - 1]) ** sorted_hidden_attributes[i]
            for i in sorted_hidden_attributes.keys()
        ]
        randoms += ai_prime_list
        R *= GT.prod(Y_hat_r_prod)
        com *= GT.prod(Y_hat_a_prod)

    challenge = Bn.from_hex(
        sha256(jsonpickle.encode((pk.pk, com, R, message)).encode()).hexdigest()
    ).mod(GT.order())

    responses = [randoms[0] - challenge * t]  # st' = t' - Ct
    response_index = []
    if H > 0:
        # computes a list of responses s = r - c * a_i
        responses += [
            rnd - challenge * attr
            for rnd, attr in zip(randoms[1:], sorted_hidden_attributes.values())
        ]
        response_index = list(zip(responses[1:], sorted_hidden_attributes.keys()))

    proof = PedersenKnowledgeProof(challenge, responses[0], response_index)
    return DisclosureProof(sign, proof)


def verify_disclosure_proof(
    pk: PublicKey,
    disclosure_proof: DisclosureProof,
    disclosed_attributes: AttributeMap,
    message: bytes,
) -> bool:
    """
    Verifies the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes

    See ABC_guide, Showing Protocol 2.b for the proof.
    We have a proof such that pi = PK{(t,hidden attributes) : left_side(disclosed attributes) = right_side(t, hidden_attributes)}

    To verify, we first compute the left_side which is independent of the secrets.
    We then compute the right_side with the proof responses (secret - c*random) -> right_side_prime
    Then we compute R' = (left_side ** c)*right_side_prime
    Since left = right, R' should be equal to R
    We verify this by comparing challenge(R) and challenge(R')
    This concludes our proof
    """
    if not check_attribute_map(disclosed_attributes, pk):
        raise ValueError(ATTRIBUTE_MAP_ERROR)
    # Need to verify that sigma1 is not the unity element in G1
    if disclosure_proof.sigma.sigma1 == G1.unity:
        return False

    sorted_disclosed_attributes = dict(sorted(disclosed_attributes.items()))
    D = len(sorted_disclosed_attributes)

    sign = disclosure_proof.sigma

    # Compute left side of proof (commit)
    sigma2_ghat = sign.sigma2.pair(pk.g_hat)
    sigma1_Y_a_list = []
    if D > 0:
        sigma1_Y_a_list = [
            sign.sigma1.pair(pk.Y_hat_list[i - 1]) ** -sorted_disclosed_attributes[i]
            for i in sorted_disclosed_attributes.keys()
        ]

    sigma1_Xhat = sign.sigma1.pair(pk.X_hat)
    com = (sigma2_ghat * GT.prod(sigma1_Y_a_list)) / sigma1_Xhat

    # Compute R' (right side under t', ai')
    t_prime = disclosure_proof.pi.response_0
    com_c = com**disclosure_proof.pi.challenge
    ghat_tprime = sign.sigma1.pair(pk.g_hat) ** t_prime
    R_prime = com_c * ghat_tprime
    # if we have hidden attributes
    if pk.L - D > 0:
        ais_prime = disclosure_proof.pi.response_index
        sigma1_Yhat_a_list = [
            sign.sigma1.pair(pk.Y_hat_list[index - 1]) ** resp
            for (resp, index) in ais_prime
        ]
        R_prime *= GT.prod(sigma1_Yhat_a_list)

    # Compute challenge of R'
    challenge_prime = Bn.from_hex(
        sha256(jsonpickle.encode((pk.pk, com, R_prime, message)).encode()).hexdigest()
    ).mod(GT.order())

    # Check challenge(R) = challenge(R')
    return disclosure_proof.pi.challenge == challenge_prime


####################################
# TOOLS METHODS FOR ATTRIBUTES MAP #
####################################


def check_attribute_map(attributes: AttributeMap, pk: PublicKey) -> bool:
    """Checks if an attribute map content is consistent with requirements on:
    - length, there cannot be more than `pk.all_attributes` as it stores all the possible attributes of the system
    - all index,attribute pair are valid (see `check_index_attribute_valid`)"""
    if len(attributes) > pk.L:
        # checks if there are too many attributes
        return False
    return all(
        check_index_attribute_valid(index, attr, pk)
        for index, attr in attributes.items()
    )


def check_index_attribute_valid(
    index: int, attribute: Attribute, pk: PublicKey
) -> bool:
    """Checks if:
    - the index is in range [1,L]
    - the attribute is a positive number
    - if the index is not 1 (attribute represents strictly a subscription), the subscrption is a valid one in the system
    Note that the user secret attribute is represented as `None` in the list `pk.all_attributes`. This allows to check the map is valid even if we have some attribute value set to `None`"""
    return (index > 0 and index <= pk.L and attribute >= 0) and (
        attribute in pk.all_attributes if index > 1 else True
    )


def attributes_to_bytes(attributes: AttributeMap) -> List[bytes]:
    """Converts an attribute map to a list of encoded attributes. Helps representing the attributes as messages to be signed for an anonymous credential issuance.
    - Assumes no sorting of the incoming map and returns list of values sorted by their previous map's keys.
    - Assumes attributes are valid and already taken positive and mod p"""
    # we take care of sorting attributes by keys in order to have it consistent with the list representation
    sorted_attributes = dict(sorted(attributes.items()))
    return list(map(lambda bn: jsonpickle.encode(bn), sorted_attributes.values()))
