"""Define the PS cryptosystem primitives."""
from serialization import jsonpickle
from petrelic.native.pairing import G1, G2, G1Element, G2Element


class PublicKeyHandler(jsonpickle.handlers.BaseHandler):
    """Handler to pass a PublicKey in JSON format."""

    def flatten(obj, data):
        """Refer to jsonpickle.handlers.BaseHandler.flatten doc."""
        data['X'] = obj.X.to_binary()
        data['Y1'] = list(map(lambda Y: Y.to_binary(), obj.Y1))
        data['Y2'] = list(map(lambda Y: Y.to_binary(), obj.Y2))

    def restore(data):
        """Refer to jsonpickle.handlers.BaseHandler.restore doc."""
        X = G1Element.from_binary(data['X'])
        Y1 = list(map(lambda Y_bin: G1Element.from_binary(Y_bin), data['Y1']))
        Y2 = list(map(lambda Y_bin: G2Element.from_binary(Y_bin), data['Y2']))

        return PublicKey(X, Y1, Y2)


@PublicKeyHandler.handles
class PublicKey:
    """Public Key in PS cryptosystem."""

    def __init__(self, X, Y1, Y2):
        """Initialize a public key.

        Args:
            X (petrelic.native.pairing.G1): element of group G1
            Y1 (petrelic.native.pairing.G1[]): a list of elements of group G1
            Y2 (petrelic.native.pairing.G2[]): a list of elements of group G2

        Returns:
            PublicKey: a new instance of the class
        """
        self.X = X
        self.Y1 = Y1.copy()
        self.Y2 = Y2.copy()

    def from_secret_key(sk):
        """Initialize a public using a secret key.

        Args:
            sk (SecretKey): the secret key

        Return:
            PublicKey: a new instance of the class
        """
        X = sk.x * G1.generator()
        Y1 = list(map(lambda y: y*G1.generator(), sk.y))
        Y2 = list(map(lambda y: y*G2.generator(), sk.y))

        return PublicKey(X, Y1, Y2)


class SecretKey:
    """Secret Key in PS cryptosystem."""

    def __init__(self, x, y):
        """Initialize a public key.

        Args:
            x (petrelic.bn.Bn): element in Z_p
            y (petrelic.bn.Bn[]): a list of elements in Z_p

        Returns:
            SecretKey: a new instance of the class
        """
        self.X = x * G1.generator()
        self.x = x
        self.y = y.copy()

    def generate_random(y_length):
        """Generate a random secret key.

        Args:
            y_length (int): the number of y elements. Must be >= 1

        Returns:
            SecretKey: a new random instance of the class
        """
        if not y_length >= 1:
            return None

        x = G1.order().random()
        y = [G1.order().random() for _ in range(y_length)]

        return SecretKey(x, y)
