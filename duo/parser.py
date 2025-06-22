from bs4 import BeautifulSoup
from typing import Optional, Dict


def extract_csrf_and_action(html: str) -> Optional[Dict[str, str]]:
    """Extract CSRF token and form action URL from login page."""
    soup = BeautifulSoup(html, 'html.parser')
    csrf_elem = soup.find('input', {'name': 'csrf_token'})
    form_elem = soup.find('form', {'method': 'post'})

    if not csrf_elem or not form_elem:
        return None

    return {
        "csrf_token": csrf_elem['value'],
        "action": form_elem['action']
    }


def extract_duo_tokens(html: str) -> Optional[Dict[str, str]]:
    """Extract tx, _xsrf, and akey from Duo form."""
    soup = BeautifulSoup(html, 'html.parser')
    tx = soup.find('input', {'name': 'tx'})
    xsrf = soup.find('input', {'name': '_xsrf'})
    akey = soup.find('input', {'name': 'akey'})

    if not tx or not xsrf or not akey:
        return None

    return {
        "tx": tx['value'],
        "_xsrf": xsrf['value'],
        "akey": akey['value']
    }


def extract_saml_response(html: str) -> Optional[str]:
    """Extract SAMLResponse from final Duo exit page."""
    soup = BeautifulSoup(html, 'html.parser')
    saml_elem = soup.find('input', {'name': 'SAMLResponse'})
    return saml_elem['value'] if saml_elem else None