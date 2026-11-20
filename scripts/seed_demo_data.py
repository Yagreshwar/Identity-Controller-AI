
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIRECTORY = PROJECT_ROOT / "data"


def load_demo_data(filename: str, collection_name: str) -> list:
    file_path = DATA_DIRECTORY / filename

    if not file_path.exists():
        raise FileNotFoundError(f"Demo data file not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if collection_name not in data:
        raise ValueError(
            f"Expected '{collection_name}' collection in {filename}"
        )

    records = data[collection_name]

    if not isinstance(records, list):
        raise ValueError(
            f"'{collection_name}' in {filename} must be a list"
        )

    return records


def main():
    projects = load_demo_data(
        "demo_projects.json", "projects"
    )

    resources = load_demo_data(
        "demo_ownership.json", "resources"
    )

    identities = load_demo_data(
        "demo_identities.json", "identities"
    )

    print("Demo data loaded successfully.")
    print(f"Projects: {len(projects)}")
    print(f"Resources: {len(resources)}")
    print(f"Identities: {len(identities)}")


if __name__ == "__main__":
    main()
