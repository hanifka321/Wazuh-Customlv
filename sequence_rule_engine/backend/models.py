from typing import List
from pydantic import BaseModel, Field


class Step(BaseModel):
    as_alias: str = Field(..., alias="as")
    where: str


class Output(BaseModel):
    timestamp_ref: str
    format: str


class Rule(BaseModel):
    id: str
    name: str
    by: List[str]
    within_seconds: int
    sequence: List[Step]
    output: Output
