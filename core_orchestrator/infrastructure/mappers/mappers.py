
from dataclasses import asdict
from typing import TypeVar, Generic, Type, List

from pydantic import BaseModel

from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.domain.entities.telemetry.reports import AnalysisReport
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginationMeta
from core_orchestrator.infrastructure.dto.responses import InfoPaginatedDTO, ResponsePaginatedDTO
from core_orchestrator.infrastructure.dto.telemetry.analysis_report_dto import AnalysisReportResponseDTO
from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO

T = TypeVar("T")
D = TypeVar("D", bound=BaseModel)

class GenericMapper(Generic[T, D]):
    def __init__(self, dataclass_cls: Type[T], dto_cls: Type[D]) -> None:
        self.dataclass_cls = dataclass_cls
        self.dto_cls = dto_cls

    def to_dataclass(self, dto: D) -> T:
        data = dto.model_dump()
        fields = self.dataclass_cls.__dataclass_fields__.keys()
        return self.dataclass_cls(**{k: v for k, v in data.items() if k in fields})

    def to_dataclass_list(self, dtos: List[D]) -> List[T]:
        return [self.to_dataclass(dto) for dto in dtos]

    def to_dto(self, entity: T) -> D:
        return self.dto_cls.model_validate(asdict(entity), from_attributes=True)

    def to_dto_list(self, entities: List[T]) -> List[D]:
        return [self.to_dto(entity) for entity in entities]

    def to_paginated_dto(
            self,
            entities: List[T],
            info_paginated: PaginationMeta,
            path: str
    ) -> ResponsePaginatedDTO[D]:
        """
        Converts a list of entities into a paginated response DTO.

        This method takes a list of entities, pagination metadata, and a base path,
        then constructs a paginated response DTO containing the entities converted to
        DTO format and additional pagination information such as total records, current
        page, next page, and previous page.

        Parameters:
            entities (List[T]): The list of entities to be converted into the DTO list
            info_paginated (PaginationMeta): The pagination metadata, including the
                total number of records, current page, and limit per page
            path (str): The base path used to construct the next and previous page links

        Returns:
            ResponsePaginatedDTO[D]: The DTO containing the paginated results and
            accompanying pagination information.
        """

        dto_list = self.to_dto_list(entities)
        skip = (info_paginated.page - 1) * info_paginated.limit
        next_page = f"{path}?page={info_paginated.page + 1}&limit={info_paginated.limit}" if (skip + info_paginated.limit) < info_paginated.total_records else None
        prev_page = f"{path}?page={info_paginated.page - 1}&limit={info_paginated.limit}" if info_paginated.page > 1 else None


        info = InfoPaginatedDTO(
            total_records=info_paginated.total_records,
            page=info_paginated.page,
            limit=info_paginated.limit,
            next_page=next_page,
            prev_page=prev_page
        )

        return ResponsePaginatedDTO(
            info=info,
            results=dto_list
        )

class AnalysisReportMapper(GenericMapper[AnalysisReport, AnalysisReportResponseDTO]):
    def __init__(self):
        super().__init__(dataclass_cls=AnalysisReport, dto_cls=AnalysisReportResponseDTO)

class LogEventMapper(GenericMapper[LogEvent, LogEventDTO]):
    def __init__(self):
        super().__init__(dataclass_cls=LogEvent, dto_cls=LogEventDTO)

analysis_report_mapper = AnalysisReportMapper()
log_event_mapper = LogEventMapper()