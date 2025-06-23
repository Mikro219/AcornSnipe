import requests as req
import re
import time
from duo import duo_auth, saml, parser
from typing import Optional


class DuoClient:
    """A client for handling Duo two-factor authentication with UToronto services."""

    def __init__(self, username: str, password: str):
        """
        Initialize the Duo client.

        Args:
            username: UToronto username
            password: UToronto password
        """
        self.username = username
        self.password = password
        self.url = 'https://acorn.utoronto.ca/'
        self.saml_url = 'spACS'
        self.session = req.Session()
        self.duo_host = None
        self.sid = None
        self.tx = None
        self.txid = None
        self.xsrf = None
        self.akey = None


    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close session."""
        self.session.close()

    def authenticate(self,
                     auth_method: str = "Duo Push",
                     passcode: Optional[str] = None,
                     device: str = "phone1") -> bool:
        """
        Perform full authentication flow with Duo.

        Args:
            auth_method: Either "Duo Push" or "Passcode"
            passcode: Required if auth_method is "Passcode"
            device: Device identifier for Duo Push

        Returns:
            True if authentication successful, False otherwise
        """
        try:
            # Step 1: Initial login
            if not self._initial_login():
                return False

            # Step 2: Duo authentication
            if not self._duo_auth(auth_method, passcode, device):
                return False

            # Step 3: Complete SAML flow
            if not self._complete_saml(auth_method):
                return False

            return True

        except Exception as e:
            print(f"Authentication failed: {e}")
            return False

    def _initial_login(self) -> bool:
        """Perform initial login to get to Duo prompt."""
        # Get initial page
        url = 'https://bypass.utormfa.utoronto.ca/'
        response = self.session.get(self.url)

        if response.status_code != 200:
            print(f"Failed to access initial URL: {response.status_code}")
            return False

        # Extract CSRF token and form action
        tokens = parser.extract_csrf_and_action(response.text)

        if not tokens:
            print("Failed to find required form elements")
            return False

        csrf_token = tokens['csrf_token']
        relative_url = tokens['action']

        # Submit credentials
        base_url = 'https://idpz.utorauth.utoronto.ca'
        payload = {
            'csrf_token': csrf_token,
            'j_username': self.username,
            'j_password': self.password,
            '_eventId_proceed': ''
        }

        response = self.session.post(base_url + relative_url, data=payload)

        # Extract session ID
        sid_match = re.search('sid=([^&]+)', response.url)
        if not sid_match:
            print("Failed to extract session ID")
            return False

        self.sid = sid_match.group(1)

        # Extract Duo host from response URL
        duo_host_match = re.search(r'https://([^/]+\.duosecurity\.com)', response.url)
        if duo_host_match:
            self.duo_host = duo_host_match.group(1)
        else:
            # Fallback to hardcoded host
            self.duo_host = "api-832cdf07.duosecurity.com"

        # Parse Duo frame parameters
        duo_tokens = parser.extract_duo_tokens(response.text)

        if not duo_tokens:
            print("Failed to find Duo frame parameters")
            return False

        self.tx = duo_tokens['tx']
        self.xsrf = duo_tokens['_xsrf']
        self.akey = duo_tokens['akey']

        # Initialize Duo frame
        payload = {
            "tx": self.tx,
            "parent": 'None',
            "_xsrf": self.xsrf,
            "version": 'v4',
            "akey": self.akey,
            "has_session_trust_analysis_feature": False
        }

        self.session.post(response.url, data=payload)
        return True

    def _duo_auth(self, auth_method: str, passcode: Optional[str], device: str) -> bool:
        """Perform Duo authentication."""
        if auth_method == "Passcode" and not passcode:
            print("Passcode required for Passcode authentication method")
            return False

        # Prepare authentication payload
        payload = {
            "device": device if auth_method == "Duo Push" else "null",
            "factor": auth_method,
            "postAuthDestination": "OIDC_EXIT",
            "browser_features": {
                "touch_supported": False,
                "platform_authenticator_status": "available",
                "webauthn_supported": True
            },
            "sid": self.sid
        }

        if auth_method == "Passcode":
            payload["passcode"] = passcode

        # Submit authentication request
        response = duo_auth.post_prompt(self.session, self.duo_host, payload)

        if response.status_code != 200:
            print(f"Duo prompt failed: {response.status_code}")
            return False

        response_data = response.json()

        if response_data.get('stat') != 'OK':
            print(f"Duo authentication failed: {response_data}")
            return False

        print(f"Duo status: {response_data['stat']}")

        self.txid = response_data['response']['txid']

        # Poll for authentication status
        if not self._poll_duo_status():
            return False

        return True

    def _poll_duo_status(self, timeout: int = 60) -> bool:
        """Poll Duo for authentication status."""
        payload = {
            'txid': self.txid,
            'sid': self.sid
        }

        start_time = time.time()
        last_poll = start_time

        while time.time() - start_time < timeout:
            # Poll every second
            if time.time() - last_poll >= 1:
                last_poll = time.time()

                response = duo_auth.get_status(self.session, self.duo_host, payload)

                if response.status_code != 200:
                    print(f"Status poll failed: {response.status_code}")
                    return False

                response_data = response.json()

                if response_data.get('stat') != 'OK':
                    print(f"Status poll error: {response_data}")
                    return False

                status_code = response_data['response']['status_code']

                if status_code == 'allow':
                    print("Duo authentication approved!")
                    return True
                elif status_code == 'deny':
                    print("Duo authentication denied!")
                    return False
                elif status_code == 'pushed':
                    print("Waiting for Duo approval...")
                    continue
                else:
                    print(f"Unknown status: {status_code}")

        print("Duo authentication timed out")
        return False

    def _complete_saml(self, auth_method: str) -> bool:
        """Complete SAML authentication flow."""
        payload = {
            "sid": self.sid,
            "txid": self.txid,
            "factor": auth_method,
            "_xsrf": self.xsrf,
            "dampen_choice": True
        }

        response = duo_auth.post_exit(self.session, self.duo_host, payload)

        saml_response = parser.extract_saml_response(response.text)

        if not saml_response:
            print("Failed to find SAML response")
            return False

        response = saml.web_completion(self.session, self.url + self.saml_url, saml_response)

        if response.status_code != 200:
            print(f"SAML submission failed: {response.status_code}")
            return False

        return True

    def set_service(self, url: str, saml_url: str) -> None:
        """
        Sets a protected service that requires authentication.

        Args:
            url: URL to access
            saml_url: URL to post
        """
        self.url = url
        self.saml_url = saml_url

    def access_service(self) -> req.Response:
        """
        Access a protected service after authentication.

        Returns:
            Response object
        """
        return self.session.get(self.url)

    def get_session(self) -> req.Session:
        """Get the authenticated session object."""
        return self.session