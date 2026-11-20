
from app.connectors.activity_client import (
    get_access_activity,
    get_management_activity,
)
from app.connectors.entra_client import (
    get_identity_details,
    search_identity,
)
from app.connectors.graph_client import get_identity_memberships
from app.connectors.rbac_client import (
    get_role_assignments,
    get_role_definition,
)
from app.connectors.resource_client import (
    get_project_assignment,
    get_project_resources,
    get_resource_details,
    get_resource_owner,
)

INVESTIGATION_TOOLS = {
    "search_identity": search_identity,
    "get_identity_details": get_identity_details,
    "get_identity_memberships": get_identity_memberships,
    "get_role_assignments": get_role_assignments,
    "get_role_definition": get_role_definition,
    "get_resource_details": get_resource_details,
    "get_project_assignment": get_project_assignment,
    "get_project_resources": get_project_resources,
    "get_resource_owner": get_resource_owner,
    "get_access_activity": get_access_activity,
    "get_management_activity": get_management_activity,
}
