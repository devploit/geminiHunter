from unittest.mock import AsyncMock

import httpx
import pytest

from geminihunter.config import Config
from geminihunter.intelligence.recon import KeyRecon
from geminihunter.models import KeyStatus, ValidatedKey


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 429])
async def test_generation_does_not_prove_paid_billing(status):
    session = AsyncMock()
    session.fetch.return_value = httpx.Response(status)
    recon = KeyRecon(object(), Config(), session)
    billing, _, _ = await recon._check_billing("synthetic-key", {}, "v1beta", False)
    assert billing is None


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [None, httpx.Response(200), httpx.Response(403)])
async def test_probe_cannot_prove_key_has_no_ip_or_api_restrictions(response):
    session = AsyncMock()
    session.fetch.return_value = response
    recon = KeyRecon(object(), Config(), session)
    result = await recon._detect_restrictions(ValidatedKey(key="synthetic-key", status=KeyStatus.VALID))
    assert result.unrestricted is False
    assert result.restriction_type != "none"
