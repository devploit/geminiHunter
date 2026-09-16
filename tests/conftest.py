import pytest
import respx


@pytest.fixture(autouse=True)
def mock_http():
    """Never send real HTTP requests from the test suite."""
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router
