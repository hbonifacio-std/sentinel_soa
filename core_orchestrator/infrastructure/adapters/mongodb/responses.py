from dataclasses import dataclass
from typing import TypeVar, Optional, Generic, List

T = TypeVar("T")

@dataclass
class PaginationMeta:
    total_records: int
    page: int
    limit: int
    next_page: Optional[str] = None
    prev_page: Optional[str] = None

@dataclass
class PaginatedResult(Generic[T]):
    info: PaginationMeta
    results: List[T]