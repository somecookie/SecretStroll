"""
Classes that you need to complete.
"""

# Optional import
from serialization import jsonpickle
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element, G2Element
from petrelic.bn import Bn
from crypto import PublicKey, SecretKey
from messages import IssuanceRequest, IssuanceResponse
import hashlib


class Server:
    """Server"""

    @staticmethod
    def generate_ca(valid_attributes):
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            valid_attributes (string): a list of all valid attributes. Users cannot
            get a credential with a attribute which is not included here.

            Note: You can use JSON to encode valid_attributes in the string.

        Returns:
            (tuple): tuple containing:
                byte[] : server's pubic information
                byte[] : server's secret key
            You are free to design this as you see fit, but all commuincations
            needs to be encoded as byte arrays.
        """
        raise NotImplementedError

    def register(self, server_sk, issuance_request, username, attributes):
        """ Registers a new account on the server.

        Args:
            server_sk (byte []): the server's secret key (serialized)
            issuance_request (bytes[]): The issuance request (serialized)
            username (string): username
            attributes (string): attributes

            Note: You can use JSON to encode attributes in the string.

        Return:
            response (bytes[]): the client should be able to build a credential
            with this response.
        """
        raise NotImplementedError

    def check_request_signature(
        self, server_pk, message, revealed_attributes, signature
    ):
        """

        Args:
            server_pk (byte[]): the server's public key (serialized)
            message (byte[]): The message to sign
            revealed_attributes (string): revealed attributes
            signature (bytes[]): user's autorization (serialized)

            Note: You can use JSON to encode revealed_attributes in the string.

        Returns:
            valid (boolean): is signature valid
        """
        raise NotImplementedError


class Client:
    """Client"""

    def prepare_registration(self, server_pk, username, attributes):
        """Prepare a request to register a new account on the server.

        Args:
            server_pk (byte[]): a server's public key (serialized)
            username (string): username
            attributes (string): user's attributes

            Note: You can use JSON to encode attributes in the string.

        Return:
            tuple:
                byte[]: an issuance request
                (private_state): You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        server_pk_parsed = jsonpickle.decode(server_pk)
        secret_key = SecretKey.generate_random()
        t = G1.order().random()
        r_t = G1.order().random()
        r_s = G1.order().random()
        R = (G1.generator() ** r_t) * (server_pk_parsed.Y[0] ** r_t)
        C = (G1.generator()**t) * (server_pk_parsed.Y[0] ** r_s)

        # Add public inputs
        m = hashlib.sha256()
        m.update(G1.generator().to_binary())
        m.update(server_pk_parsed.Y[0].to_binary())
        m.update(R.to_binary())
        m.update(C.to_binary())

        c = Bn.from_binary(m.digest())
        s_t = r_t.mod_sub(c * t, G1.order())
        s_s = r_s.mod_sub(c * secret_key.x, G1.order())

        req = IssuanceRequest(username, attributes, C, s_s, s_t)

        return jsonpickle.encode(req)

    def proceed_registration_response(self, server_pk, server_response, private_state):
        """Process the response from the server.

        Args:
            server_pk (byte[]): a server's public key (serialized)
            server_response (byte[]): the response from the server (serialized)
            private_state (private_state): state from the prepare_registration
            request corresponding to this response

        Return:
            credential (byte []): create an attribute-based credential for the user
        """
        raise NotImplementedError

    def sign_request(self, server_pk, credential, message, revealed_info):
        """Signs the request with the clients credential.

        Arg:
            server_pk (byte[]): a server's public key (serialized)
            credential (byte[]): client's credential (serialized)
            message (byte[]): message to sign
            revealed_info (string): attributes which need to be authorized

            Note: You can use JSON to encode revealed_info.

        Returns:
            byte []: message's signature (serialized)
        """
        raise NotImplementedError
