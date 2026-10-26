from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

class Source(BaseModel):
    device_id: str | None = None
    authenticated: bool = False
    signature_verified: bool = False

class EventIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal['1.0'] = '1.0'
    event_id: str = Field(min_length=4, max_length=120)
    event_type: str = Field(min_length=3, max_length=100)
    source_product: Literal['guardian','arxvigil']
    tenant_id: str = Field(min_length=1,max_length=120)
    subject_type: Literal['person','vehicle','asset','device']
    subject_id: str = Field(min_length=1,max_length=120)
    occurred_at: datetime
    source: Source = Field(default_factory=Source)
    observation: dict[str,Any] = Field(default_factory=dict)
    integrity: dict[str,Any] = Field(default_factory=dict)

class ReviewIn(BaseModel):
    status: Literal['ACCEPTED','REJECTED']
    reviewer: str = Field(min_length=1,max_length=120)
    note: str = Field(default='',max_length=2000)

class LoginIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    organisation_id: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=200)
    totp: str | None = None
    recovery_code: str | None = None

    @field_validator("organisation_id", "email", "password", mode="before")
    @classmethod
    def strip_text(cls, value):
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("totp", "recovery_code", mode="before")
    @classmethod
    def blank_code_is_missing(cls, value):
        if not isinstance(value, str):
            return value
        text = value.strip()
        return text or None

class MfaConfirmIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: str = Field(min_length=6, max_length=6)

class IdentityCheckIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    password: str = Field(min_length=12, max_length=200)

class DeviceCredentialIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    device_id: str = Field(min_length=2, max_length=120)
    product: Literal['guardian','arxvigil']

class PasswordResetIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=12, max_length=200)

class UserCreateIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=200)
    role: Literal['operator','supervisor','administrator','service','developer']

class UserUpdateIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    role: Literal['operator','supervisor','administrator','service','developer'] | None = None
    disabled: bool | None = None

class ModelUpdateIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=2, max_length=120)
    version: str = Field(min_length=1, max_length=50)
    kind: Literal['rules','template','agent']
    status: Literal['active','retired']
    description: str = Field(min_length=3, max_length=500)

class QuestionIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    question: str = Field(min_length=1, max_length=2000)

class StatusIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['OPEN','IN_REVIEW','CLOSED']
    note: str = Field(default='', max_length=2000)

class GrantIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    from_product: Literal['guardian','arxvigil']
    to_product: Literal['guardian','arxvigil']
    purpose: str = Field(min_length=3, max_length=200)

class SearchIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    query: str = Field(min_length=1, max_length=200)
