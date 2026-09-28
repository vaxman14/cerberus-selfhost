from __future__ import annotations
import os
from .models import AuthRecord, Head
from . import signwell


class AuthorizationError(Exception):
    pass


class AuthorizationGate:
    """Cardinal #7 in code. Passive heads run on public content.
    The active backend head refuses without a signed authorization reference,
    and if a SignWell API key is present, that reference must verify as completed."""

    PASSIVE_HEADS = {Head.FRONTEND, Head.SPEED, Head.NOSE, Head.REVENUE}

    def __init__(self, auth: AuthRecord):
        self.auth = auth

    def authorize(self, head: Head) -> None:
        if head in self.PASSIVE_HEADS:
            return
        # the single authorized operator (owner) may run active heads directly
        if self.auth.admin_override:
            return
        ref = self.auth.signed_authorization_ref
        if not ref:
            raise AuthorizationError(
                f"{head.value}: active testing blocked. No signed authorization on file. "
                "Head 2 requires a completed SignWell authorization reference."
            )
        verified = signwell.is_authorization_complete(ref)
        if verified is False:
            raise AuthorizationError(
                f"{head.value}: SignWell document {ref} is not fully signed yet."
            )
        if verified is None and os.environ.get(
                "CERBERUS_ALLOW_UNVERIFIED_AUTH", "").lower() not in ("1", "true", "yes"):
            raise AuthorizationError(
                f"{head.value}: authorization could not be verified. Configure "
                "SIGNWELL_API_KEY or explicitly set CERBERUS_ALLOW_UNVERIFIED_AUTH=true."
            )
