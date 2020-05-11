"""Define the PS cryptosystem primitives."""
from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.bn import Bn
import hashlib


class PublicKey:
    """Public Key in PS cryptosystem."""

    def __init__(self, X2, Y1, Y2, valid_attributes):
        """Initialize a public key.

        Args:
            X2 (petrelic.multiplicative.pairing.G2): element of group G2
            Y1 (petrelic.multiplicative.pairing.G1[]): a list of elements of group G1
            Y2 (petrelic.multiplicative.pairing.G2[]): a list of elements of group G2
            valid_attrbiutes (string[]): list of valid attributes

        Returns:
            PublicKey: a new instance of the class
        """
        self.X2 = X2
        self.Y1 = Y1.copy()
        self.Y2 = Y2.copy()
        self.valid_attributes = valid_attributes

    @staticmethod
    def from_secret_key(sk):
        """Initialize a public using a secret key.

        Args:
            sk (SecretKey): the secret key

        Return:
            PublicKey: a new instance of the class
        """
        X2 = G2.generator() ** sk.x
        Y1 = list(map(lambda y: G1.generator() ** y, sk.y))
        Y2 = list(map(lambda y: G2.generator() ** y, sk.y))

        return PublicKey(X2, Y1, Y2, sk.valid_attributes)


class SecretKey:
    """Secret Key in PS cryptosystem."""

    def __init__(self, x, y, valid_attributes):
        """Initialize a public key.

        Args:
            x (petrelic.bn.Bn): element in Z_p
            y (petrelic.bn.Bn[]): a list of elements in Z_p
            valid_attrbiutes (string[]): list of valid attributes

        Returns:
            SecretKey: a new instance of the class
        """
        self.X = G1.generator() ** x
        self.x = x
        self.y = y.copy()
        self.valid_attributes = valid_attributes

    @staticmethod
    def generate_random(valid_attributes):
        """Generate a random secret key.

        Args:
            valid_attrbiutes (string[]): list of valid attributes

        Returns:
            SecretKey: a new random instance of the class
        """
        y_length = len(valid_attributes)
        if not y_length >= 1:
            raise ValueError("The number of y elements cannot be 0")

        x = G1.order().random()
        y = [G1.order().random() for _ in range(y_length)]

        return SecretKey(x, y, valid_attributes)


class Signature:
    """Represent a signature using PS scheme."""

    def __init__(self, sigma1, sigma2):
        """Initialize a signature

        Args:
            sigma1 (petrelic.multiplicative.pairing.G1Element) first part of the sig
            sigma2 (petrelic.multiplicative.pairing.G1Element) second part of the sig

        Returns:
            Signature: a new instance of the class
        """
        self.sigma1 = sigma1
        self.sigma2 = sigma2

    def verify(self, pk, messages):
        """Verify a signature.

        Args:
            pk (PublicKey): the public key
            messages (petrelic.bn.Bn[]): the array of messages

        Return:
            Bool: whether the signature is correct
        """
        if self.sigma1 == G1.neutral_element():
            return False

        if len(messages) != len(pk.Y2):
            return False

        acc = pk.X2
        for i in range(len(messages)):
            acc = acc * (pk.Y2[i] ** messages[i])

        return self.sigma1.pair(acc) == self.sigma2.pair(G2.generator())

class Credential:
    def __init__(self, secret_key, attributes, signature):
        self.secret_key = secret_key
        self.attributes = attributes
        self.signature = signature


class GeneralizedSchnorrProof:
    def __init__(self, group, bases, statement=None, secrets=None, responses=None, commitment=None):
        self.bases = bases
        self.secrets = secrets
        self.responses = responses
        self.commitment = commitment
        self.random_exp = None
        self.group = group
        if statement is None and secrets is not None:
            self.statement = group.neutral_element()
            for i in range(len(bases)):
                self.statement = self.statement * bases[i]**secrets[i]
        else:
            self.statement = statement

    def get_commitment(self):
        if self.commitment is not None:
            return self.commitment

        if self.random_exp is None:
            self.random_exp = [self.group.order().random() for _ in range(len(self.bases))]

        com = self.group.neutral_element()
        for i in range(len(self.bases)):
            com = com * self.bases[i] ** self.random_exp[i]

        self.commitment = com

        return com

    def get_shamir_challenge(self, message=None):
        m = hashlib.sha256()
        for base in self.bases:
            m.update(base.to_binary())
        m.update(self.get_commitment().to_binary())
        m.update(self.statement.to_binary())

        if message is not None:
            m.update(message)

        c = Bn.from_hex(m.hexdigest()).mod(self.group.order())

        return c

    def get_responses(self, challenge):
        if self.secrets is None:
            raise ValueError("Secrets must be given.")

        r = []
        for i in range(len(self.bases)):
            mult = challenge*self.secrets[i]
            r.append(self.random_exp[i].mod_add(mult, self.group.order()))

        return r

    def verify(self, challenge):
        if self.responses is None:
            raise ValueError("Challenge responses must be given.")

        left = self.commitment * self.statement**challenge
        right = self.group.neutral_element()

        for i in range(len(self.responses)):
            right = right * self.bases[i]**self.responses[i]

        return left == right
