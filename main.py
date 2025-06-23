from duo.client import DuoClient


# Example usage
if __name__ == "__main__":
    username = ''
    password = ''

    with DuoClient(username, password) as client:
        client.set_service('https://bypass.utormfa.utoronto.ca/','Shibboleth.sso/SAML2/POST')

        if client.authenticate(auth_method="Duo Push", passcode=""):
            response = client.access_service()
            print("Success! Accessed protected service")
            print(response.text)
        else:
            print("Authentication failed")