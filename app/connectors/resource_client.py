
import json
import os
from pathlib import Path

from azure.core.exceptions import ResourceNotFoundError
from app.connectors.credentials import discovery_credential
from azure.mgmt.resource.resources import ResourceManagementClient

from app.connectors.entra_client import get_identity_details

PROJECT_ROOT = Path(__file__).resolve().parents[2]

OWNERSHIP_FILE = PROJECT_ROOT / "data" / "demo_ownership.json"
PROJECTS_FILE = PROJECT_ROOT / "data" / "demo_projects.json"

subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

if not subscription_id:
    raise ValueError("AZURE_SUBSCRIPTION_ID is not configured")

credential = discovery_credential

resource_client = ResourceManagementClient(
    credential,
    subscription_id
)


def _load_json(file_path: Path) -> dict:
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def get_resource_owner_record(
    resource_id: str,
    project_id: str | None = None,
) -> dict | None:
    """
    Return the ownership registry entry for a resource. Several projects
    can share one resource, so the project ID selects the accountable owner.
    """
    ownership_data = _load_json(OWNERSHIP_FILE)

    for resource in ownership_data.get("resources", []):
        if (
            resource.get("resource_id", "").rstrip("/").casefold()
            != resource_id.rstrip("/").casefold()
        ):
            continue

        if (
            project_id
            and resource.get("project_id", "").casefold()
            != project_id.casefold()
        ):
            continue

        return resource

    return None


def get_resource_owner(
    resource_id: str,
    project_id: str | None = None,
) -> str | None:
    """Retrieve the resource owner from the demo ownership registry."""
    record = get_resource_owner_record(resource_id, project_id)

    return record.get("owner") if record else None


def get_resource_details(resource_id: str) -> dict:
    normalized_id = resource_id.rstrip("/")
    parts = normalized_id.split("/")

    try:
        resource_group_index = next(
            index
            for index, part in enumerate(parts)
            if part.casefold() == "resourcegroups"
        )
    except StopIteration:
        raise ValueError(f"Invalid Azure resource ID: {resource_id}")

    # A resource-group name must follow "resourceGroups".
    if resource_group_index + 1 >= len(parts):
        raise ValueError(f"Invalid Azure resource ID: {resource_id}")

    resource_group_name = parts[resource_group_index + 1]

    # Resource-group scope
    if resource_group_index + 2 == len(parts):
        resource = resource_client.resource_groups.get(
            resource_group_name
        )

        return {
            "resource_id": resource.id,
            "name": resource.name,
            "resource_type": "Microsoft.Resources/resourceGroups",
            "location": resource.location,
            "tags": resource.tags
        }

    # Individual Azure resource
    resource = resource_client.resources.get_by_id(
        normalized_id,
        api_version=os.getenv(
            "AZURE_RESOURCE_API_VERSION",
            "2021-04-01"
        )
    )

    return {
        "resource_id": resource.id,
        "name": resource.name,
        "resource_type": resource.type,
        "location": resource.location,
        "tags": resource.tags
    }


def get_project_assignment(identity_id: str) -> list:
    identity = get_identity_details(identity_id)

    if not identity:
        return []

    identity_values = {
        identity_id.casefold(),
        identity["object_id"].casefold(),
        identity["display_name"].casefold(),
    }

    if identity.get("user_principal_name"):
        identity_values.add(
            identity["user_principal_name"].casefold()
        )

    data = _load_json(PROJECTS_FILE)

    return [
        project
        for project in data.get("projects", [])
        if any(
            isinstance(project_identity, str)
            and project_identity.casefold() in identity_values
            for project_identity in project.get("identities", [])
        )
    ]


def get_project_resources(project_id: str) -> list[dict]:
    ownership_data = _load_json(OWNERSHIP_FILE)

    project_resources = [
        resource
        for resource in ownership_data.get("resources", [])
        if resource.get("project_id", "").casefold()
        == project_id.casefold()
    ]

    verified_resources = []

    for resource in project_resources:
        resource_id = resource.get("resource_id")

        if not resource_id:
            continue

        try:
            get_resource_details(resource_id)
            verified_resources.append(resource)

        except ResourceNotFoundError:
            continue

    return verified_resources
