from typing import TypeVar, Optional, List, Generic, Dict, Any

from pydantic import BaseModel, Field

D = TypeVar("D", bound=BaseModel)
class InfoPaginatedDTO(BaseModel):
    total_records: int = Field(..., description="Total number of records")
    page: int = Field(..., description="Current page number")
    limit: int = Field(..., description="Number of records per page")
    next_page: Optional[str] = Field(default=None, description="Next page number")
    prev_page: Optional[str] = Field(default=None, description="Previous page number")


class ResponsePaginatedDTO(BaseModel, Generic[D]):
    info: InfoPaginatedDTO
    results: List[D]

    def set_next_and_prev_page(self,path: str):
        skip = (self.info.page - 1) * self.info.limit
        next_page = f"{path}?page={self.info.page + 1}&limit={self.info.limit}" if (skip + self.info.limit) < self.info.total_records else None
        prev_page = f"{path}?page={self.info.page - 1}&limit={self.info.limit}" if self.info.page > 1 else None
        self.info.next_page = next_page
        self.info.prev_page = prev_page

class OperationResponseDTO(BaseModel):
    status: str = Field(..., description="Operation status (e.g., success, accepted, updated, deleted)")
    message: str = Field("Operation completed successfully", description="Descriptive message")
    client_id: Optional[str] = Field(None, description="Customer/tenant identifier")
    source_id: Optional[str] = Field(None, description="Source resource identifier, if applicable")
    affected_records: int = Field(1, description="Number of records processed, created, or modified")
    details: Optional[Dict[str, Any]] = Field(None, description="Optional additional information")