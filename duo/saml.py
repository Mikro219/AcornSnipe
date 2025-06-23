from requests import Session, Response


def web_completion(session: Session, saml_url: str, saml_response: str) -> Response:
    """Submit SAML response"""
    payload = {
        'SAMLResponse': saml_response
    }

    return session.post(saml_url, data=payload)
