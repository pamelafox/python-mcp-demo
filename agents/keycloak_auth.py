"""
Keycloak authentication helpers for MCP agents.

Provides OAuth2 client credentials flow authentication via Keycloak's
Dynamic Client Registration (DCR) endpoint.

Usage:
    from keycloak_auth import get_auth_headers

    headers = await get_auth_headers(keycloak_realm_url)
    # Returns {"Authorization": "Bearer <token>"} or None if no URL provided
"""

from __future__ import annotations

import logging
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)


async def register_client_via_dcr(keycloak_realm_url: str, client_name_prefix: str = "agent") -> tuple[str, str]:
    """
    Register a new client dynamically using Keycloak's DCR endpoint.

    Args:
        keycloak_realm_url: The Keycloak realm URL (e.g., http://localhost:8080/realms/myrealm)
        client_name_prefix: Prefix for the generated client name

    Returns:
        Tuple of (client_id, client_secret)

    Raises:
        RuntimeError: If DCR registration fails
    """
    dcr_url = f"{keycloak_realm_url}/clients-registrations/openid-connect"
    logger.info("📝 Registering client via DCR...")

    async with httpx.AsyncClient() as http_client:
        response = await http_client.post(
            dcr_url,
            json={
                "client_name": f"{client_name_prefix}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "client_secret_basic",
            },
            headers={"Content-Type": "application/json"},
        )

        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"DCR registration failed at {dcr_url}: "
                f"status={response.status_code}, "
                f"response={response.text}"
            )

        data = response.json()
        logger.info(f"✅ Registered client: {data['client_id'][:20]}...")
        return data["client_id"], data["client_secret"]


async def get_keycloak_token(keycloak_realm_url: str, client_id: str, client_secret: str) -> str:
    """
    Get an access token from Keycloak using client_credentials grant.

    Args:
        keycloak_realm_url: The Keycloak realm URL
        client_id: The OAuth client ID
        client_secret: The OAuth client secret

    Returns:
        The access token string

    Raises:
        RuntimeError: If token request fails
    """
    token_url = f"{keycloak_realm_url}/protocol/openid-connect/token"
    logger.info("🔑 Getting access token from Keycloak...")

    async with httpx.AsyncClient() as http_client:
        response = await http_client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Token request failed at {token_url}: "
                f"status={response.status_code}, "
                f"response={response.text}"
            )

        token_data = response.json()
        logger.info(f"✅ Got access token (expires in {token_data.get('expires_in', '?')}s)")
        return token_data["access_token"]


async def get_auth_headers(
    keycloak_realm_url: str | None, client_name_prefix: str = "agent"
) -> dict[str, str] | None:
    """
    Get authorization headers if Keycloak is configured.

    This is the main entry point for agents that need OAuth authentication.
    It handles the full flow: DCR registration -> token acquisition -> headers.

    Args:
        keycloak_realm_url: The Keycloak realm URL, or None to skip auth
        client_name_prefix: Prefix for the dynamically registered client name

    Returns:
        {"Authorization": "Bearer <token>"} if keycloak_realm_url is set, None otherwise
    """
    if not keycloak_realm_url:
        return None

    client_id, client_secret = await register_client_via_dcr(keycloak_realm_url, client_name_prefix)
    access_token = await get_keycloak_token(keycloak_realm_url, client_id, client_secret)
    return {"Authorization": f"Bearer {access_token}"}
