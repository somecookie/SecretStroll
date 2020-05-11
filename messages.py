"""Define the messages sent through the network."""


class IssuanceRequest:
    """Client request for credentials."""

    def __init__(self, statement, commitment, responses):
        """Return a new instance of an issuance request.

        Args:
            username (string): username of the user
            attributes (string): the attributes of the user in JSON format
            statement (petrelic.multiplicative.pairing.G1): ZK-PoK statement to be proven
            commitment (petrelic.multiplicative.pairing.G1): commitment in the ZK-Pok
            responses (petrelic.bn.Bn[]): ZK-PoK responses

        Returns:
            IssuanceRequest: a new instance of the class
            """
        self.commitment = commitment
        self.statement = statement
        self.responses = responses


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


class RequestSignature:
    """Signature on a user request."""
    def __init__(self, randomized_signature, commitment, responses):
        """Return a new signature on a user request.

        Args:
            randomized_signature (Signature): a randomized crendential
            commitment (petrelic.multiplicative.groupElement): commitment on
                the random values of the PoK
            reponses (petrelic.bn.Bn[]): responses to the PoK challenge

        Return:
            RequestSignature: a new instance of the class
        """
        self.r_sig = randomized_signature
        self.commitment = commitment
        self.responses = responses

