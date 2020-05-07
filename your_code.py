"""
Classes that you need to complete.
"""

# Optional import
from serialization import jsonpickle
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element, G2Element
from petrelic.bn import Bn
from crypto import PublicKey, SecretKey
import json


@jsonpickle.handlers.register(G1Element)
class G1ElementHandler(jsonpickle.handlers.BaseHandler):
    """Handler to pass an element of G1 to JSON format."""

    def flatten(self, obj, data):
        """Refer to jsonpickle.handlers.BaseHandler.flatten doc."""
        data['bytes'] = obj.to_binary()

    def restore(self, data):
        """Refer to jsonpickle.handlers.BaseHandler.restore doc."""
        return G1Element.from_binary(data['bytes'])


@jsonpickle.handlers.register(G2Element)
class G2ElementHandler(jsonpickle.handlers.BaseHandler):
    """Handler to pass an element of G2 to JSON format."""

    def flatten(self, obj, data):
        """Refer to jsonpickle.handlers.BaseHandler.flatten doc."""
        data['bytes'] = obj.to_binary()

    def restore(self, data):
        """Refer to jsonpickle.handlers.BaseHandler.restore doc."""
        return G2Element.from_binary(data['bytes'])


@jsonpickle.handlers.register(Bn)
class BnElementHandler(jsonpickle.handlers.BaseHandler):
    """Handler to pass an element of Bn to JSON format."""

    def flatten(self, obj, data):
        """Refer to jsonpickle.handlers.BaseHandler.flatten doc."""
        data['bytes'] = obj.binary()

    def restore(self, data):
        """Refer to jsonpickle.handlers.BaseHandler.restore doc."""
        return Bn.from_binary(data['bytes'])


class Server:
    """Server"""
    Valid_Attributes = []

    @staticmethod
    def generate_ca(valid_attributes):
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and chooses a secret key
        for the server.

        Args:
            valid_attributes (string): the path to a JSON file containing the attributes.

        Returns:
            (tuple): tuple containing:
                byte[] : server's pubic information
                byte[] : server's secret key
            You are free to design this as you see fit, but all communications
            needs to be encoded as byte arrays.
        """

        with open(valid_attributes) as json_file:
            attr_json = json.load(json_file)
            if not Server.verify_attributes_list(attr_json):
                raise TypeError("attributes format is not valid")
            Server.Valid_Attributes = attr_json["user"] + attr_json["issuer"]
            sk = SecretKey.generate_random(len(Server.Valid_Attributes))
            pk = PublicKey.from_secret_key(sk)

            return jsonpickle.encode(sk), jsonpickle.encode(pk)

    @staticmethod
    def verify_attributes_list(attrs):
        """
        Verifies if the JSON that represents the valid attributes is valid.
        The JSON for L attributes, where k of them are user determined attributes and L-k are issuer determined,
        must have the following format:
        {
            "user": ["a0",...,"a_(k-1)"]
            "issuer": ["ak",...,"a_(L-1)"]
        }
        :param attrs: dict that represents the JSON
        :return: boolean indicating if the JSON is valid or not
        """
        if "issuer" not in attrs or "user" not in attrs:
            return False

        if type(attrs["user"]) is not list or type(attrs["issuer"]) is not list:
            return False

        return all([isinstance(e, str) for e in attrs["user"]]) and all([isinstance(e, str) for e in attrs["issuer"]])

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
        raise NotImplementedError

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
