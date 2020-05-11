"""
Classes that you need to complete.
"""

import json

from crypto import PublicKey, SecretKey, Signature, Credential, GeneralizedSchnorrProof
from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.bn import Bn
import serialization
from messages import IssuanceResponse, IssuanceRequest, RequestSignature
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

        # Handle empty attrs list
        if len(attrs) == 1 and attrs[0] == '':
            attrs = []

        for attr in attrs:
            if attr not in sk.valid_attributes:
                print("attributes are not valid")
                return b''

        req = serialization.jsonpickle.decode(issuance_request)
        m = hashlib.sha256()
        m.update(G1.generator().to_binary())
        m.update(pk.Y1[0].to_binary())
        m.update(req.R.to_binary())
        m.update(req.commitment.to_binary())

        c = Bn.from_hex(m.hexdigest()).mod(G1.order())
        R = (G1.generator() ** req.s_t) * \
            (pk.Y1[0] ** req.s_s) * (req.commitment ** c)

        if req.R != R:
            print("Rs are not equal")
            return b''

        u = G1.order().random()
        sig1 = G1.generator() ** u

        sig2 = sk.X * req.commitment
        for i, attr in enumerate(sk.valid_attributes[1:], 1):
            exp = 1 if attr in attributes else 0
            sig2 = sig2 * (pk.Y1[i] ** exp)
        sig2 = sig2 ** u

        credential = Signature(sig1, sig2)
        resp = IssuanceResponse(credential)
        return serialization.jsonpickle.encode(resp).encode("utf-8")

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
        server_pk_parsed = serialization.jsonpickle.decode(server_pk.decode('utf-8'))
        revealed_attributes = revealed_attributes.split(',')
        if len(revealed_attributes) == 0 and revealed_attributes[0] == '':
            revealed_attributes = []

        req = serialization.jsonpickle.decode(signature)

        statement = req.r_sig.sigma2.pair(G2.generator())
        statement = statement / req.r_sig.sigma1.pair(server_pk_parsed.X2)
        bases = []

        # Add base for t
        bases.append(req.r_sig.sigma1.pair(G2.generator()))

        # Add base for secret key
        bases.append(req.r_sig.sigma1.pair(server_pk_parsed.Y2[0]))

        for i, attr in enumerate(server_pk_parsed.valid_attributes[1:], 1):
            Yi = server_pk_parsed.Y2[i]
            if attr in revealed_attributes:
                statement = statement / req.r_sig.sigma1.pair(Yi)

            bases.append(req.r_sig.sigma1.pair(Yi))

        proof = GeneralizedSchnorrProof(bases, statement, responses=req.responses, commitment=req.commitment)
        c = proof.get_shamir_challenge(message)

        return proof.verify(c)


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

        c = Bn.from_hex(m.hexdigest()).mod(G1.order())
        s_t = r_t.mod_sub(c * t, G1.order())
        s_s = r_s.mod_sub(c * secret_key, G1.order())

        req = IssuanceRequest(C, R, s_s, s_t)
        req_bytes = serialization.jsonpickle.encode(req).encode('utf-8')

        # Handle empty attrs list
        attributes = attributes.split(',')
        if len(attributes) == 1 and attributes[0] == '':
            attributes = []

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

        server_pk_parsed = serialization.jsonpickle.decode(
            server_pk.decode('utf-8'))
        (secret_key, attributes, t) = private_state
        issuance_response = serialization.jsonpickle.decode(
            server_response.decode('utf-8'))
        sig = issuance_response.credential

        sig_unblind = Signature(sig.sigma1, sig.sigma2 / (sig.sigma1 ** t))
        credential = Credential(secret_key, attributes, sig_unblind)

        messages = [secret_key]
        for attr in server_pk_parsed.valid_attributes[1:]:
            m = Bn.from_num(1) if attr in attributes else Bn.from_num(0)
            messages.append(m)

        if not credential.signature.verify(server_pk_parsed, messages):
            raise ValueError("received credentials are not valid")

        return serialization.jsonpickle.encode(credential).encode('utf-8')

    def sign_request(self, server_pk, credential, message, revealed_info):
        """Signs the request with the clients credential.

        arg:
            server_pk (byte[]): a server's public key (serialized)
            credential (byte[]): client's credential (serialized)
            message (byte[]): message to sign
            revealed_info (string): attributes which need to be authorized

            Note: You can use JSON to encode revealed_info.

        returns:
            byte []: message's signature (serialized)
        """

        # Parse args
        server_pk_parsed = serialization.jsonpickle.decode(
            server_pk.decode('utf-8'))
        cred = serialization.jsonpickle.decode(credential.decode('utf-8'))
        revealed_info = revealed_info.split(',')
        if len(revealed_info) == 1 and revealed_info[0] == '':
            revealed_info = []

        # Start PoK
        sig = cred.signature
        r = G1.order().random()
        t = G1.order().random()
        cred_randomized = Signature(
            sig.sigma1 ** r, (sig.sigma2 * sig.sigma1 ** t)**r)

        #
        # Begin generalized Schnorr Zk-PoK with Fiat-Shamir heuristic
        #

        # Add t
        bases = [cred_randomized.sigma1.pair(G2.generator())]
        statement = bases[-1] ** t
        secrets = [t]

        # Add secret key
        bases.append(cred_randomized.sigma1.pair(server_pk_parsed.Y2[0]))
        statement = statement * bases[-1]**cred.secret_key
        secrets.append(cred.secret_key)

        for i, attr in enumerate(server_pk_parsed.valid_attributes[1:], 1):
            # Add only if it is a hidden attribute
            exp = 1 if attr in cred.attributes and attr not in revealed_info else 0
            bases.append(cred_randomized.sigma1.pair(server_pk_parsed.Y2[i]))
            statement = statement * bases[-1]**exp
            secrets.append(exp)

        proof = GeneralizedSchnorrProof(bases, statement, secrets=secrets)
        com = proof.get_commitment()
        c = proof.get_shamir_challenge(message)
        responses = proof.get_responses(c)

        req = RequestSignature(cred_randomized, com, responses)

        return serialization.jsonpickle.encode(req).encode('utf-8')
