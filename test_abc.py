from your_code import Server, Client


def test_valid_run():
    """"
    This test performs a valid run, i.e., the following tasks are being performed:
    - The server generates the keys and sets up the list of attributes
    - The client and the server interact such that the client gets its ABC
    - The client request a service to the server showing only one attribute
    """

    # Set up server
    server_attr = "gym,spa,restaurant,bars"
    server_pk, server_sk = Server.generate_ca(server_attr)
    server = Server()

    # Client issues registration request
    client_attr = "gym,bars"
    username = "bob"
    client = Client()
    issuance_request, client_private_state = client.prepare_registration(server_pk, username, client_attr)

    # Server handles registration request
    issuance_response = server.register(server_sk, issuance_request, username, client_attr)

    # Client handles issuance response
    client_anon_cred = client.proceed_registration_response(server_pk, issuance_response, client_private_state)

    # Client makes loc request revealing only one attribute
    client_reveal_attr = "gym"
    lat = 46.52345
    lon = 6.57890
    client_msg = ("{},{}".format(lat, lon)).encode("utf-8")
    sig = client.sign_request(server_pk, client_anon_cred, client_msg, client_reveal_attr)

    # Server handles request
    assert server.check_request_signature(server_pk, client_msg, client_reveal_attr, sig), "invalid signature from " \
                                                                                           "the client "


def test_invalid_attribute():
    """"
        This test performs a invalid run, i.e., the following tasks are being performed:
        - The server generates the keys and sets up the list of attributes
        - The client and the server interact such that the client gets its ABC
        - The client request a service to the server showing only one attribute.
        However, this attribute is not valid for this client.
        """
    # Set up server
    server_attr = "gym,spa,restaurant,bars"
    server_pk, server_sk = Server.generate_ca(server_attr)
    server = Server()

    # Client issues registration request
    client_attr = ""
    username = "bob"
    client = Client()
    issuance_request, client_private_state = client.prepare_registration(server_pk, username, client_attr)

    # Server handles registration request
    issuance_response = server.register(server_sk, issuance_request, username, client_attr)

    # Client handles issuance response
    client_anon_cred = client.proceed_registration_response(server_pk, issuance_response, client_private_state)

    # Client makes loc request revealing only one attribute
    client_reveal_attr = "restaurant"
    lat = 46.52345
    lon = 6.57890
    client_msg = ("{},{}".format(lat, lon)).encode("utf-8")
    sig = client.sign_request(server_pk, client_anon_cred, client_msg, client_reveal_attr)

    # Server handles request
    assert not server.check_request_signature(server_pk, client_msg, client_reveal_attr, sig), "invalid signature from " \
                                                                                               "the client "
