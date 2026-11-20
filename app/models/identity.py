from pydantic import BaseModel


class Identity(BaseModel):
    identity_id: str
    display_name: str
    user_principal_name: str | None = None
    account_enabled: bool
    identity_type: str