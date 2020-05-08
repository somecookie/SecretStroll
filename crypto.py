"""Define the PS cryptosystem primitives."""
from petrelic.multiplicative.pairing import G1, G2


class PublicKey:
    """Public Key in PS cryptosystem."""

    def __init__(self, X, Y1, Y2):
        """Initialize a public key.

        Args:
            X (petrelic.multiplicative.pairing.G2): element of group G2
            Y1 (petrelic.multiplicative.pairing.G1[]): a list of elements of group G1
            Y2 (petrelic.multiplicative.pairing.G2[]): a list of elements of group G2

        Returns:
            PublicKey: a new instance of the class
        """
        self.X = X
        self.Y1 = Y1.copy()
        self.Y2 = Y2.copy()

    @staticmethod
    def from_secret_key(sk):
        """Initialize a public using a secret key.

        Args:
            sk (SecretKey): the secret key

        Return:
            PublicKey: a new instance of the class
        """
        X = G2.generator() ** sk.x
        Y1 = list(map(lambda y: G1.generator() ** y, sk.y))
        Y2 = list(map(lambda y: G2.generator() ** y, sk.y))

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
        self.X = G1.generator() ** x
        self.x = x
        self.y = y.copy()

    @staticmethod
    def generate_random(y_length=1):
        """Generate a random secret key.

        Args:
            y_length (int): the number of y elements. Must be >= 1

        Returns:
            SecretKey: a new random instance of the class
        """
        if not y_length >= 1:
            raise ValueError("The number of y elements cannot be 0")

        x = G1.order().random()
        y = [G1.order().random() for _ in range(y_length)]

        return SecretKey(x, y)


class Signature:
    """Represent a signature using PS scheme."""

    def __init__(self, epsilon1, epsilon2):
        """Initialize a signature

        Args:
            epsilon1 (petrelic.multiplicative.pairing.G1Element) first part of the sig
            epsilon2 (petrelic.multiplicative.pairing.G1Element) second part of the sig

        Returns:
            Signature: a new instance of the class
        """
        self.epsilon1 = epsilon1
        self.epsilon2 = epsilon2

    def verify(self, pk, messages):
        """Verifiy a signature.

        Args:
            pk (PublicKey): the public key
            messages (petrelic.bn.Bn[]): the array of messages

        Return:
            Bool: whether the signature is correct
        """
        if self.epsilon1 == G1.neutral_element():
            return False

        if len(messages) != len(pk.Y2):
            return False

        acc = pk.X
        for i in range(len(messages)):
            acc = acc * (pk.Y2[i] ** messages[i])

        return self.epsilon1.pair(acc) == self.epsilon2.pair(G2.generator())
