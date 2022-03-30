"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Type, Union, Tuple
from petrelic.bn import Bn
from credential import *


# Optional import
from serialization import jsonpickle


# Type aliases
"""Represents the secret user state, containing: 
    - the t value used to generate the issue request
    - the user attributes, hidden to the issuer
    - the username
"""
UserState = Tuple[tAndUserAttributes, str]

NB_PRIVATE_ATTRIBUTES = 1


class Server:
    """Server"""

    def __init__(self):
        """
        Server constructor.
        """

    @staticmethod
    def generate_ca(subscriptions: List[str]) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's pubic information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        # creates the list of all attributes with the Bn corresponding to `None` as first one. The first attribute will represent user secret but is strictly associated to a user and therefore, makes no sense to be stored by server. The storing of None is useful for checking validity of subscription as None subscription should be valid.
        # takes care of sorting subscriptions in alphabetical order for consistency
        attributes = list(
            map(lambda x: str_to_attribute(x), ["None"] + sorted(subscriptions))
        )
        sk, pk = generate_key(attributes)
        server_sk = jsonpickle.encode(sk).encode()
        server_pk = jsonpickle.encode(pk).encode()

        return server_sk, server_pk

    def process_registration(
        self,
        server_sk: bytes,
        server_pk: bytes,
        issuance_request: bytes,
        username: str,
        subscriptions: List[str],
    ) -> bytes:
        """Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        sk = jsonpickle.decode(server_sk)
        pk = jsonpickle.decode(server_pk)
        issue_req = jsonpickle.decode(issuance_request)
        if (
            not isinstance(sk, SecretKey)
            or not isinstance(pk, PublicKey)
            or not isinstance(issue_req, IssueRequest)
        ):
            raise TypeError("Bad deserialization of inputs")

        if not check_subscriptions(pk, subscriptions):
            raise ValueError("Cannot subscribe to unknown subscrption type")

        issuer_attributes_map = create_issuer_attributes(pk, subscriptions)
        blind_sign = sign_issue_request(sk, pk, issue_req, issuer_attributes_map)

        return jsonpickle.encode(blind_sign, keys=True).encode()

    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes,
    ) -> bool:
        """Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        pk = jsonpickle.decode(server_pk)
        disc_proof = jsonpickle.decode(signature, keys=True)
        if not isinstance(pk, PublicKey) or not isinstance(disc_proof, DisclosureProof):
            raise TypeError("Bad deserialization of inputs")

        if not check_subscriptions(pk, revealed_attributes):
            raise ValueError("Unknown showed attributes")

        disclosed_attributes = create_disclosed_attributes(pk, revealed_attributes)
        return verify_disclosure_proof(pk, disc_proof, disclosed_attributes, message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.

        Initializes some client secret used to obtain a credential uniquely binded to the client
        """
        self.client_secret = G1.order().random()

    def prepare_registration(
        self, server_pk: bytes, username: str, subscriptions: List[str]
    ) -> Tuple[bytes, UserState]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        pk = jsonpickle.decode(server_pk)
        if not isinstance(pk, PublicKey):
            raise TypeError("Bad deserialization of inputs")

        user_attributes = create_user_attribtues(self.client_secret)
        user_state, issue_request = create_issue_request(pk, user_attributes)
        issue_request_as_bytes = jsonpickle.encode(issue_request, keys=True).encode()

        return issue_request_as_bytes, (user_state, username)

    def process_registration_response(
        self, server_pk: bytes, server_response: bytes, private_state: UserState
    ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        pk = jsonpickle.decode(server_pk)
        blind_sign = jsonpickle.decode(server_response, keys=True)
        if not isinstance(pk, PublicKey) or not isinstance(blind_sign, BlindSignature):
            raise TypeError("Bad deserialization of inputs")

        t_user_attr, username = private_state
        cred = obtain_credential(pk, blind_sign, t_user_attr)

        return jsonpickle.encode(cred, keys=True).encode()

    def sign_request(
        self, server_pk: bytes, credentials: bytes, message: bytes, types: List[str]
    ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        pk = jsonpickle.decode(server_pk)
        cred = jsonpickle.decode(credentials, keys=True)
        if not isinstance(pk, PublicKey) or not isinstance(cred, AnonymousCredential):
            raise TypeError("Bad deserialization of inputs")

        disclosed_attributes = create_disclosed_attributes(pk, types).items()
        # we take the hidden attributes as the attributes signed by the credential that are not part of the disclosed ones
        hidden_attributes = {
            i: attr
            for i, attr in cred.attributes.items()
            if (i, attr) not in disclosed_attributes
        }
        disclosure_proof = create_disclosure_proof(pk, cred, hidden_attributes, message)

        return jsonpickle.encode(disclosure_proof, keys=True).encode()


###############################################
##    METHODS FOR ATTRIBUTES/SUBSCRIPTION    ##
###############################################


def check_subscriptions(pk: PublicKey, subscriptions: List[str]) -> bool:
    """Checks all the subscriptions input are in the list of recognized subscriptions by the server and we are not in the bad case where no subscriptions are taken (makes no sense to subscribe to nothing)"""
    return len(subscriptions) > 0 and all(
        str_to_attribute(subscr) in pk.all_attributes for subscr in subscriptions
    )


def create_user_attribtues(secret: Attribute) -> AttributeMap:
    """Creates the user attributes for a client secret: an attribute map for the NB_PRIVATE_ATTRIBUTES first attribute indexes"""
    return {1: secret}


def create_disclosed_attributes(
    pk: PublicKey, chosen_subscriptions: List[str]
) -> AttributeMap:
    all_subscriptions_map = all_subscriptions_attribute_map(pk)
    chosen_subscriptions_attributes = subscriptions_to_attribute_list(
        chosen_subscriptions
    )
    return {
        i: subscr
        for i, subscr in all_subscriptions_map.items()
        if subscr in chosen_subscriptions_attributes
    }


def create_issuer_attributes(
    pk: PublicKey, chosen_subscriptions: List[str]
) -> AttributeMap:
    """Creates a padded attribute map for the disclosure of attributes representing subscriptions.
    Args:
        - pk: the server public key
        - chosen_subscriptions: the string representation of the subscriptions that should be included in the attribute map
    Returns:
        an attribute map {i->a_i} such that a_i is the string representation of the chosen subscription attribute or the attribute representation of None if the attribute was not chosen to be disclosed"""
    all_subscriptions_map = all_subscriptions_attribute_map(pk)
    chosen_subscriptions_attributes = subscriptions_to_attribute_list(
        chosen_subscriptions
    )
    return {
        i: (
            subscr
            if subscr in chosen_subscriptions_attributes
            else str_to_attribute("None")
        )
        for i, subscr in all_subscriptions_map.items()
    }


def subscriptions_to_attribute_list(subscriptions: List[str]) -> List[Attribute]:
    """Makes an attribute (Bn) list from a list of string represented subscriptions"""
    return list(map(lambda x: str_to_attribute(x), subscriptions))


def all_subscriptions_attribute_map(
    pk: PublicKey,
) -> AttributeMap:
    """Builds the attribute map of all the attributes that are recognized by the server having public key pk"""
    # we first shift x[0] by 1 as list index are in [0,L-1] while attributes index are in [1,L]
    # we also take into account that only the L-NB_PRIVATE_ATTRIBUTES attributes represent the subscriptions
    return dict(
        map(
            lambda x: (x[0] + 1, x[1]),
            list(enumerate(pk.all_attributes))[NB_PRIVATE_ATTRIBUTES:],
        )
    )


def str_to_attribute(subscription: str) -> Attribute:
    """Transforms a string into a valid positive mod(order(G1)) attribute value as Bn"""
    return Bn.from_binary(subscription.encode()).mod(G1.order())
