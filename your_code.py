"""
Classes that you need to complete.
"""

import json

from crypto import PublicKey, SecretKey, Signature
from petrelic.multiplicative.pairing import G1
from petrelic.bn import Bn
import serialization
from messages import IssuanceResponse, IssuanceRequest
import hashlib

class Server:
    """Server"""

    @staticmethod
    def generate_ca(valid_attributes):
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and chooses a secret key
        for the server.

        Args:
            valid_attributes (string): comma separated list of attributes

        Returns:
            (tuple): tuple containing:
                byte[] : server's pubic information
                byte[] : server's secret key
            You are free to design this as you see fit, but all communications
            needs to be encoded as byte arrays.
        """

        attr = valid_attributes.split(",")
        if len(attr) == 0:
            raise TypeError("attributes format is not valid")

        attr.insert(0, "secret_key")
        sk = SecretKey.generate_random(attr)
        pk = PublicKey.from_secret_key(sk)
        return serialization.jsonpickle.encode(pk).encode("utf-8"), serialization.jsonpickle.encode(sk).encode("utf-8")

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

        sk = serialization.jsonpickle.decode(server_sk.decode("utf-8"))
        pk = PublicKey.from_secret_key(sk)

        attrs = attributes.split(",")
        print(attrs, )
        for attr in attrs:
            if attr not in sk.valid_attributes:
                print("attributes are not valid")
                return b''

        req_utf8 = issuance_request.encode("utf8").decode("utf8")
        print(req_utf8)
        req = serialization.jsonpickle.decode(req_utf8)

        m = hashlib.sha256()
        m.update(G1.generator().to_binary())
        m.update(pk.Y1[0].to_binary())
        m.update(req.R.to_binary())
        m.update(req.commitment.to_binary())

        c = Bn.from_binary(m.digest())
        R = (G1.generator() ** req.s_t) * (pk.Y1[0] ** req.s_s) * (req.commitment ** c)

        if req.R != R:
            print("Rs are not equal")
            return b''

        u = G1.order().random()
        sig1 = G1.order() ** u

        sig2 = sk.X * req.commitment
        for i, attr in enumerate(Server.valid_attributes[1:]):
            exp = 1 if attr in attributes else 0
            sig2 = sig2 * (pk.Y1[i] ** exp)
        sig2 = sig2 ** u

        credential = Signature(sig1, sig2)
        resp = IssuanceResponse(credential)
        print(sig1, sig2)
        return serialization.jsonpickle.encode(resp).encode("utf8")

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

        server_pk = serialization.jsonpickle.decode(server_pk.decode('utf-8'))
        print(server_pk)
        secret_key = G1.order().random()
        t = G1.order().random()
        r_t = G1.order().random()
        r_s = G1.order().random()
        R = (G1.generator() ** r_t) * (server_pk.Y1[0] ** r_s)
        C = (G1.generator() ** t) * (server_pk.Y1[0] ** secret_key)

        # Add public inputs
        m = hashlib.sha256()
        m.update(G1.generator().to_binary())
        m.update(server_pk.Y1[0].to_binary())
        m.update(R.to_binary())
        m.update(C.to_binary())

        c = Bn.from_binary(m.digest())
        s_t = r_t.mod_sub(c * t, G1.order())
        s_s = r_s.mod_sub(c * secret_key, G1.order())

        req = IssuanceRequest(C, R, s_s, s_t)
        req_bytes = serialization.jsonpickle.encode(req).encode('utf-8')
        return req_bytes, (secret_key, attributes, t)

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

        if server_response == b"":
            raise ValueError("empty response for registration")

        server_pk_parsed = serialization.jsonpickle.decode(server_pk.decode('utf-8'))
        (secret_key, attributes, t) = private_state
        issuance_response = serialization.jsonpickle.decode(server_response.decode('utf-8'))
        sig = issuance_response.crendential

        credential = Signature(sig.epsilon1, sig.epsilon2 / (sig.epsilon1 ** t))

        # TODO: verify credential

        return serialization.jsonpickle.encode(credential).encode('utf-8')

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
