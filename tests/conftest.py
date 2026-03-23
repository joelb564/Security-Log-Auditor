"""Common fixtures for Security Log Auditor tests."""

import pytest
from unittest.mock import patch


@pytest.fixture
def mock_elevated():
    with patch("core.platform_utils.is_elevated", return_value=True):
        yield


@pytest.fixture
def mock_not_elevated():
    with patch("core.platform_utils.is_elevated", return_value=False):
        yield
