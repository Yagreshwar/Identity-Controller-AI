
import os
import json
import sys

from app.connectors.entra_client import get_identity_details
from app.connectors.rbac_client import (
    get_role_assignments,
    get_role_definition
)


def main():
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    storage_scope = os.getenv("AZURE_STORAGE_SCOPE")

    if not subscription_id:
        raise ValueError("AZURE_SUBSCRIPTION_ID is not configured.")

    if not storage_scope:
        raise ValueError("AZURE_STORAGE_SCOPE is not configured.")

    development_scope = (
        f"/subscriptions/{subscription_id}"
        "/resourceGroups/idcmd-development"
    )

    identities = {
        "Alex": (
            os.getenv("ALEX_OBJECT_ID"),
            storage_scope
        ),
        "Priya": (
            os.getenv("PRIYA_OBJECT_ID"),
            development_scope
        ),
        "Build Service": (
            os.getenv("BUILD_SERVICE_OBJECT_ID"),
            storage_scope
        )
    }

    missing = [
        name for name, (identity_id, _) in identities.items()
        if not identity_id
    ]

    if missing:
        raise ValueError(
            f"Missing Object IDs for: {', '.join(missing)}"
        )

    results = []

    for name, (identity_id, identity_scope) in identities.items():

        if identity_id is None:
            raise ValueError(f"Missing Object ID for {name}")

        print(f"\n{'=' * 50}")
        print(f"IDENTITY: {name}")
        print(f"{'=' * 50}")

        identity = get_identity_details(identity_id)

        assignments = get_role_assignments(
            identity_id,
            scope=identity_scope
        )

        role_details = []

        for assignment in assignments:
            role_definition = get_role_definition(
                assignment["role_definition_id"]
            )

            assignment["role_name"] = role_definition["name"]

            role_details.append({
                "assignment": assignment,
                "permissions": role_definition["permissions"]
            })

        results.append({
            "identity_name": name,
            "identity": identity,
            "role_assignments": role_details
        })

    print("\nIDENTITY DISCOVERY RESULTS")
    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Discovery failed: {exc}")
        sys.exit(1)
