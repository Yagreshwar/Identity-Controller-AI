from app.investigation.permission_analysis import analyze_permissions


def test_broad_permissions():
    role_definition = {
        "permissions": [
            {
                "actions": ["*"],
                "data_actions": []
            }
        ]
    }

    result = analyze_permissions(role_definition)

    assert result["status"] == "ANALYZED"
    assert result["permission_level"] == "BROAD"


def test_specific_permissions():
    role_definition = {
        "permissions": [
            {
                "actions": [
                    "Microsoft.Storage/storageAccounts/read"
                ],
                "data_actions": []
            }
        ]
    }

    result = analyze_permissions(role_definition)

    assert result["status"] == "ANALYZED"
    assert result["permission_level"] == "SPECIFIC"


def test_storage_blob_data_contributor_is_write_capable():
    result = analyze_permissions({
        "permissions": [{
            "actions": [],
            "data_actions": [
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
            ],
        }]
    })

    assert result["write_capable"] is True
    assert result["permission_level"] == "SPECIFIC"


def test_read_only_role_is_not_write_capable():
    result = analyze_permissions({
        "permissions": [{
            "actions": ["Microsoft.Storage/storageAccounts/read"],
            "data_actions": [],
        }]
    })

    assert result["write_capable"] is False


def test_excluded_write_is_not_counted():
    result = analyze_permissions({
        "permissions": [{
            "actions": [
                "Microsoft.Storage/storageAccounts/read",
                "Microsoft.Storage/storageAccounts/write",
            ],
            "not_actions": ["Microsoft.Storage/storageAccounts/write"],
            "data_actions": [],
        }]
    })

    assert result["write_capable"] is False


def test_missing_role_definition():
    result = analyze_permissions({})

    assert result["status"] == "ROLE_DEFINITION_UNAVAILABLE"
    assert result["write_capable"] is None
