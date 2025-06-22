from requests import Session, Response


def get_status(session: Session, duo_host: str, payload: dict[str: str]) -> Response:
    """Send get request for duo prompt status"""
    return session.post(f'https://{duo_host}/frame/v4/status', data=payload)


def post_prompt(session: Session, duo_host: str, payload: dict[str: str]) -> Response:
    """Send post request for authentication"""
    return session.post(f'https://{duo_host}/frame/v4/prompt', data=payload)


def post_exit(session: Session, duo_host: str, payload: dict[str: str]) -> Response:
    """Send post request for clean exit"""
    return session.post(f'https://{duo_host}/frame/v4/oidc/exit', data=payload)