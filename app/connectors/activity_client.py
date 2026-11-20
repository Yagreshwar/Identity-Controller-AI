
import os
from datetime import UTC, datetime

from azure.core.exceptions import HttpResponseError
from app.connectors.credentials import discovery_credential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from dotenv import load_dotenv

load_dotenv()

workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")

credential = discovery_credential
logs_client = LogsQueryClient(credential)


def _validate_time_range(
    start_time: datetime,
    end_time: datetime
) -> None:
    if start_time.tzinfo is None or end_time.tzinfo is None:
        raise ValueError(
            "Start and end times must include timezone information."
        )

    if start_time >= end_time:
        raise ValueError("Start time must be earlier than end time.")


def _escape_kql(value: str) -> str:
    return value.replace("'", "''")


def _extract_activities(response) -> list[dict]:
    tables = (
        response.tables
        if response.status == LogsQueryStatus.SUCCESS
        else response.partial_data
    )

    activities = []

    for table in tables or []:
        columns = [
            column if isinstance(column, str) else column.name
            for column in table.columns
        ]

        activities.extend(
            dict(zip(columns, row))
            for row in table.rows
        )

    return activities


def _query_activity(
    query: str,
    start_time: datetime,
    end_time: datetime
) -> dict:
    if not workspace_id:
        return {
            "status": "TELEMETRY_UNAVAILABLE",
            "activities": []
        }

    try:
        response = logs_client.query_workspace(
            workspace_id=workspace_id,
            query=query,
            timespan=(start_time, end_time)
        )

        activities = _extract_activities(response)

        # Positive evidence remains useful even if the query is partial.
        if activities:
            return {
                "status": "ACTIVITY_CONFIRMED",
                "activities": activities
            }

        if response.status != LogsQueryStatus.SUCCESS:
            return {
                "status": "INSUFFICIENT_COVERAGE",
                "activities": []
            }

        return {
            "status": "INSUFFICIENT_COVERAGE",
            "activities": []
        }

    except HttpResponseError:
        return {
            "status": "TELEMETRY_UNAVAILABLE",
            "activities": []
        }


def get_access_activity(
    identity_id: str,
    resource_id: str,
    start_time: datetime,
    end_time: datetime
) -> dict:
    """
    Retrieve successful Azure Storage Blob data-plane activity
    for an identity within a resource or resource-group scope.
    """

    if not identity_id or not resource_id:
        raise ValueError(
            "Identity ID and resource ID are required."
        )

    _validate_time_range(start_time, end_time)

    start = start_time.astimezone(UTC).isoformat()
    end = end_time.astimezone(UTC).isoformat()

    identity_id = _escape_kql(identity_id)
    resource_id = _escape_kql(resource_id.rstrip("/"))

    query = f"""
        StorageBlobLogs
        | where TimeGenerated between (
            datetime({start}) .. datetime({end})
        )
        | where RequesterObjectId == '{identity_id}'
        | where _ResourceId startswith '{resource_id}'
        | where toint(StatusCode) between (200 .. 299)
        | project TimeGenerated, OperationName, Uri,
                  StatusCode, RequesterObjectId, _ResourceId
    """

    result = _query_activity(
        query,
        start_time,
        end_time
    )

    if result["activities"]:
        return result

    if result["status"] != "INSUFFICIENT_COVERAGE":
        return result

    coverage_complete = (
        os.getenv(
            "LOG_ANALYTICS_COVERAGE_COMPLETE",
            "false"
        ).lower() == "true"
    )

    if coverage_complete:
        result["status"] = "NO_ACTIVITY_OBSERVED"

    return result


def get_management_activity(
    caller: str,
    resource_id: str,
    start_time: datetime,
    end_time: datetime
) -> dict:
    """
    Retrieve Azure management-plane activity for an identity
    within a resource or resource-group scope.
    """

    if not caller or not resource_id:
        raise ValueError(
            "Caller and resource ID are required."
        )

    _validate_time_range(start_time, end_time)

    start = start_time.astimezone(UTC).isoformat()
    end = end_time.astimezone(UTC).isoformat()

    caller = _escape_kql(caller)
    resource_id = _escape_kql(resource_id.rstrip("/"))

    query = f"""
        AzureActivity
        | where TimeGenerated between (
            datetime({start}) .. datetime({end})
        )
        | where Caller =~ '{caller}'
        | where ResourceId startswith '{resource_id}'
        | project TimeGenerated, OperationNameValue,
                  ActivityStatusValue, Caller, ResourceId,
                  CorrelationId
        | order by TimeGenerated desc
    """

    return _query_activity(
        query,
        start_time,
        end_time
    )
