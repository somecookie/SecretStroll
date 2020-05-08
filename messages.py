"""Define the messages sent through the network."""


class IssuanceRequest:
    """Client request for credentials."""

    def __init__(self, commitment, R, s_s, s_t):
        """Return a new instance of an issuance request.

        Args:
            username (string): username of the user
            attributes (string): the attributes of the user in JSON format
            commitment (petrelic.multiplicative.pairing.G1): ZK-PoK commitment to hidden attributes
            R (petrelic.multiplicative.pairing.G1): commitment in the ZK-Pok
            s_s (petrelic.bn.Bn): ZK-PoK response for the secret part
            s_t (petrelic.bn.Bn): ZK-PoK response for the random t part

        Returns:
            IssuanceRequest: a new instance of the class
            """
        self.com = commitment
        self.R = R
        self.s_s = s_s
        self.s_t = s_t


class IssuanceResponse:
    """Server response for an issuance request."""

    def __init__(self, credential):
        """Return a new issuance response.

        Args:
            credential (Signature): a signature on the user public and private attibutes

        Return:
            IssuanceResponse: a new instance of the class
        """
        self.credential = credential
