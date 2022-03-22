"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Type, Union, Tuple
from petrelic.bn import Bn
from credential import *


# Optional import
from serialization import jsonpickle


# Type aliases

UserState = Tuple[tAndUserAttributes, str]


class Server:
    """Server"""

    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################

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
        # adds an attribute the represent the fact that username is part of attributes
        attributes = subscriptions
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
        ###############################################
        # TODO: Complete this function.
        ###############################################
        sk = jsonpickle.decode(server_sk)
        pk = jsonpickle.decode(server_pk)

        issue_req = jsonpickle.decode(issuance_request)
        issuer_attributes_map = subset_subscriptions_to_attribute_map(
            pk.all_attributes, subscriptions
        )

        all_attributes_map = all_subscriptions_to_attribute_map(pk.all_attributes)

        for i, attr in issuer_attributes_map.items():
            if (
                not attr == str_to_attribute("None")
                and not all_attributes_map.get(i) == attr
            ):
                raise ValueError("Cannot subscribe to unknown subscrption type")

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
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk)
        disclosed_attributes = subset_subscriptions_to_attribute_map(
            pk.all_attributes, revealed_attributes
        )
        disc_proof = jsonpickle.decode(signature, keys=True)

        if not isinstance(disc_proof, DisclosureProof):
            raise TypeError("Disclosure proof decoded object is incorrect")

        return verify_disclosure_proof(pk, disc_proof, disclosed_attributes, message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################

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
        server_pk_deserialized = jsonpickle.decode(server_pk)
        user_attributes = dict()
        user_state, issue_request = create_issue_request(
            server_pk_deserialized, user_attributes
        )

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
        ###############################################
        # TODO: maybe need to do something with state
        ###############################################
        pk = jsonpickle.decode(server_pk)
        blind_sign = jsonpickle.decode(server_response, keys=True)
        if not isinstance(blind_sign, BlindSignature):
            raise TypeError("Inccorrect type of parsed blind signature")

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
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk)
        cred = jsonpickle.decode(credentials, keys=True)
        disclosed_attributes = subset_subscriptions_to_attribute_map(
            pk.all_attributes, types
        ).items()
        hidden_attributes = {
            i: attr
            for i, attr in cred.attributes.items()
            if (i, attr) not in disclosed_attributes
        }

        disclosure_proof = create_disclosure_proof(pk, cred, hidden_attributes, message)

        return jsonpickle.encode(disclosure_proof, keys=True).encode()


###############################################
#           AUXILIARY TOOL METHODS
###############################################


def subset_subscriptions_to_attribute_map(
    all_attributes: List[Attribute], subscriptions: List[str]
) -> AttributeMap:
    """Returns the attribute map associated with the list of attributes given all the public attributes"""
    all_attributes_map = all_subscriptions_to_attribute_map(all_attributes)
    subscriptions_as_attributes = list(
        map(lambda x: str_to_attribute(x), subscriptions)
    )
    attributes_map = {
        i: (
            str_to_attribute(subscr)
            if subscr in subscriptions_as_attributes
            else str_to_attribute("None")
        )
        for i, subscr in all_attributes_map.items()
    }
    assert check_attribute_map(attributes_map, len(all_attributes))
    return attributes_map


def all_subscriptions_to_attribute_map(
    all_attributes: List[Attribute],
) -> AttributeMap:
    """Build the attribute map of all attributes the recognized subscription attributes from the list of attributes in the public key"""
    attributes = {i + 1: subscr for i, subscr in enumerate(all_attributes)}
    return attributes


def str_to_attribute(subscription: str) -> Attribute:
    """Transforms a string into a valid mod(order(G1)) attribute value as Bn"""
    return Bn.from_binary(subscription.encode()).mod(G1.order())
