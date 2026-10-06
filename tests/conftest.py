import pytest

from dac.rules import load_rules


@pytest.fixture(scope="session")
def rules():
    return load_rules()
