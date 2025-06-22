from duo.client import DuoClient


# Example usage
if __name__ == "__main__":
    username = ''
    password = ''

    with DuoClient(username, password) as client:
        if client.authenticate(auth_method="Duo Push"):
            response = client.access_service('https://acorn.utoronto.ca/sws/')
            print("Success! Accessed protected service")
            print(f"Response length: {len(response.text)}")
        else:
            print("Authentication failed")