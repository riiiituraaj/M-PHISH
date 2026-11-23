"""v2 evidence contract: operational state, coverage and severity are independent."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .core.network import redact_url

CONTRACT_VERSION = "2.0"
POLICY_VERSION = "evidence-policy-v2"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Observations(StrictModel):
    consent: bool = False
    fields: list[Literal["password", "email", "otp", "card", "phone", "address", "banking"]] = (
        Field(default_factory=list, max_length=12)
    )
    form_actions: list[str] = Field(default_factory=list, max_length=12)
    password_inputs: int = Field(default=0, ge=0, le=100)
    forms: int = Field(default=0, ge=0, le=100)
    frame_coverage: Literal["top_frame_only"] = "top_frame_only"
    page_fingerprint: str | None = Field(default=None, max_length=128)

    @field_validator("form_actions")
    @classmethod
    def private_actions(cls, values):
        return [redact_url(value) for value in values]


class InvestigationContext(StrictModel):
    visual_consent: bool = False
    observations: Observations | None = None
    tab_id: int | None = Field(default=None, ge=0)
    session_id: str | None = Field(default=None, max_length=100)


class InvestigationRequest(StrictModel):
    url: str = Field(max_length=4096)
    context: InvestigationContext = Field(default_factory=InvestigationContext)

    @field_validator("url")
    @classmethod
    def url_policy(cls, value):
        return redact_url(value)


class ActionDetails(StrictModel):
    form_action: str | None = Field(default=None, max_length=4096)
    form_action_url: str | None = Field(default=None, max_length=4096)
    destination: str | None = Field(default=None, max_length=4096)
    field_categories: list[
        Literal["password", "email", "otp", "card", "phone", "address", "banking"]
    ] = Field(default_factory=list, max_length=12)
    page_fingerprint: str | None = Field(default=None, max_length=128)
    is_executable: bool = False

    @field_validator("form_action", "form_action_url", "destination")
    @classmethod
    def redact(cls, value):
        return redact_url(value) if value else None


class DynamicTrustRequest(InvestigationRequest):
    action_type: Literal[
        "password_focused",
        "card_focused",
        "otp_focused",
        "banking_focused",
        "form_focused",
        "download_attempt",
        "form_submit",
    ]
    action_details: ActionDetails = Field(default_factory=ActionDetails)


class Credentials(StrictModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    password: str = Field(min_length=12, max_length=128)


class UserSettings(StrictModel):
    knowledge_level: Literal["simple", "standard", "technical"] | None = None
    history_enabled: bool | None = None
    ai_enabled: bool | None = None
    notifications_enabled: bool | None = None
    retention_days: int | None = Field(default=None, ge=1, le=30)


class PairRequest(StrictModel):
    extension_id: str = Field(pattern=r"^[a-p]{32}$")


class ExchangeRequest(PairRequest):
    code: str = Field(min_length=20, max_length=100)
