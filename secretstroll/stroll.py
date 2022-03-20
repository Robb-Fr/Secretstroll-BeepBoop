"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple
from petrelic.bn import Bn
from credential import *


# Optional import
from serialization import jsonpickle


# Type aliases
State = Tuple[UserState, str]


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
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
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
        attributes = str_to_attribute_map(subscriptions)
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
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.

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
        req = jsonpickle.decode(issuance_request)
        subscriptions.insert(0, username)
        attributes = str_to_attribute_map(subscriptions)

        blind_sign = sign_issue_request(sk, pk, req, attributes)

        return jsonpickle.encode(blind_sign).encode()


    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

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
        disclosed_attributes = str_to_attribute_map(revealed_attributes)
        disc_proof = jsonpickle.decode(signature)

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
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
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
  
        #subscriptions.insert(0, username)
        attributes = str_to_attribute_map(subscriptions)

        user_state, issue_request = create_issue_request(server_pk_deserialized, attributes)

        #state = State(None)

        issue_request_as_bytes = jsonpickle.encode(issue_request)

        return issue_request_as_bytes, (user_state, username) 


    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
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
        server_pk_deserialized = jsonpickle.decode(server_pk)
        blind_sign = jsonpickle.decode(server_response)

        cred = obtain_credential(server_pk_deserialized, blind_sign, private_state[0])

        return jsonpickle.encode(cred).encode()


    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
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

        server_pk_deserialized = jsonpickle.decode(server_pk)
        cred = jsonpickle.decode(credentials)
        hidden_attributes = str_to_attribute_map(types)

        disclosure_proof = create_disclosure_proof(server_pk_deserialized, cred, hidden_attributes, message)

        return jsonpickle.encode(disclosure_proof).encode()

