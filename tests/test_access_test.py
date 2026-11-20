import pytest
from fakes import ALEX_ID, APOLLO_SCOPE, PRIYA_ID, FakeTestIdentityCredential

from app.remediation import access_test
from app.remediation.access_test import (
    access_test_result,
    run_controlled_access_test,
    storage_account_url,
)


def test_storage_account_url_from_scope():
    assert storage_account_url(APOLLO_SCOPE) == (
        "https://apollostorage.blob.core.windows.net"
    )


def test_non_storage_scope_is_rejected():
    with pytest.raises(ValueError):
        storage_account_url("/subscriptions/demo/resourceGroups/rg")


def test_not_performed_without_credential():
    result = run_controlled_access_test(APOLLO_SCOPE, "c", "b", None)

    assert result["status"] == "NOT_PERFORMED"
    assert access_test_result(result) is None


def test_not_performed_without_test_blob():
    result = run_controlled_access_test(
        APOLLO_SCOPE, None, None, FakeTestIdentityCredential(ALEX_ID)
    )

    assert result["status"] == "NOT_PERFORMED"


def test_allowed_when_identity_still_has_access(fake_azure):
    result = run_controlled_access_test(
        APOLLO_SCOPE,
        "access-test",
        "alex-test.txt",
        FakeTestIdentityCredential(ALEX_ID),
    )

    assert result["status"] == "ACCESS_ALLOWED"
    assert access_test_result(result) is True


def test_denied_when_identity_has_no_access(fake_azure):
    result = run_controlled_access_test(
        APOLLO_SCOPE,
        "access-test",
        "alex-test.txt",
        FakeTestIdentityCredential(PRIYA_ID),
    )

    assert result["status"] == "ACCESS_DENIED"
    assert access_test_result(result) is False


def test_other_http_errors_are_inconclusive(monkeypatch):
    from azure.core.exceptions import HttpResponseError

    class MissingBlob:
        def __init__(self, **kwargs):
            pass

        def get_blob_properties(self):
            error = HttpResponseError(message="BlobNotFound")
            error.status_code = 404
            raise error

    monkeypatch.setattr(access_test, "BlobClient", MissingBlob)

    result = run_controlled_access_test(
        APOLLO_SCOPE, "c", "b", FakeTestIdentityCredential(ALEX_ID)
    )

    assert result["status"] == "INCONCLUSIVE"
    assert access_test_result(result) is None


def test_access_test_is_read_only():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(access_test))
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    assert "get_blob_properties" in called
    assert not called & {
        "upload_blob",
        "delete_blob",
        "set_blob_metadata",
        "start_copy_from_url",
    }
