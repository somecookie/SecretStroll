import pytest
from your_code import Server, Client


def test_valid_run():
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
