"""Define the messages sent through the network."""


class IssuanceRequest:
    """Client request for credentials."""

    def __init__(self, username, attributes, com, s_s, s_t):
        """Return a new instance of an issuance request.

        Args:
            username (string): username of the user
            attributes (string): the attributes of the user in JSON format
            com (petrelic.multiplicative.pairing.G1): ZK-PoK commitment to hidden attributes
            s_s (petrelic.bn.Bn): ZK-PoK response for the secret part
            s_t (petrelic.bn.Bn): ZK-PoK response for the random t part

        Returns:
            IssuanceRequest: a new instance of the class
            """
        self.username = username
        self.attributes = attributes
        self.com = com
        self.s_s = s_s
        self.s_t = s_t