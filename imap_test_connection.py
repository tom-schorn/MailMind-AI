"""IMAP connection testing and auto-detection utility."""

import logging
from typing import Tuple, Optional
from imap_tools import MailBox, MailBoxStartTls, MailBoxUnencrypted

from Entities import EmailCredential


def test_imap_connection(credential: EmailCredential) -> Tuple[bool, str, Optional[dict]]:
    """
    Test IMAP connection and auto-detect best settings.

    Args:
        credential: EmailCredential to test

    Returns:
        Tuple of (success: bool, message: str, suggested_settings: dict)
    """
    logger = logging.getLogger('MailMind')

    test_configs = []

    if credential.port == 993:
        test_configs = [
            ('SSL', MailBox, True, False),
        ]
    elif credential.port == 143:
        test_configs = [
            ('TLS', MailBoxStartTls, False, True),
            ('Unencrypted', MailBoxUnencrypted, False, False),
        ]
    else:
        test_configs = [
            ('SSL', MailBox, True, False),
            ('TLS', MailBoxStartTls, False, True),
            ('Unencrypted', MailBoxUnencrypted, False, False),
        ]

    for name, mailbox_class, use_ssl, use_tls in test_configs:
        try:
            logger.info(f"Testing {name} connection to {credential.host}:{credential.port}")

            mailbox = mailbox_class(credential.host, credential.port)
            mailbox.login(credential.username, credential.password, initial_folder='INBOX')
            mailbox.logout()

            return (
                True,
                f"Connection successful using {name}",
                {'use_ssl': use_ssl, 'use_tls': use_tls, 'port': credential.port}
            )

        except Exception as e:
            logger.debug(f"{name} failed: {e}")
            continue

    return (
        False,
        f"All connection methods failed. Check credentials and server settings.",
        None
    )


def suggest_imap_settings(host: str, port: int) -> dict:
    """
    Suggest IMAP settings based on common configurations.

    Args:
        host: IMAP server hostname
        port: IMAP server port

    Returns:
        Dictionary with suggested settings
    """
    common_configs = {
        'imap.gmail.com': {'port': 993, 'use_ssl': True, 'use_tls': False},
        'outlook.office365.com': {'port': 993, 'use_ssl': True, 'use_tls': False},
        'imap.mail.yahoo.com': {'port': 993, 'use_ssl': True, 'use_tls': False},
        'imap.aol.com': {'port': 993, 'use_ssl': True, 'use_tls': False},
        'imap.gmx.net': {'port': 993, 'use_ssl': True, 'use_tls': False},
        'imap.web.de': {'port': 993, 'use_ssl': True, 'use_tls': False},
    }

    if host in common_configs:
        return common_configs[host]

    if port == 993:
        return {'port': 993, 'use_ssl': True, 'use_tls': False}
    elif port == 143:
        return {'port': 143, 'use_ssl': False, 'use_tls': True}
    else:
        return {'port': 993, 'use_ssl': True, 'use_tls': False}
