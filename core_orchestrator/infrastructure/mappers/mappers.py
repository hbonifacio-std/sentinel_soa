
from dataclasses import asdict, is_dataclass, replace
from typing import TypeVar, Generic, Type, List, Any, Mapping, get_args, get_origin, Union, get_type_hints

from pydantic import BaseModel

from core_orchestrator.domain.entities.rule_engine import HeuristicRule, ValidationRules
from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.domain.entities.telemetry.reports import AnalysisReport
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginationMeta
from core_orchestrator.infrastructure.dto.responses import InfoPaginatedDTO, ResponsePaginatedDTO
from core_orchestrator.infrastructure.dto.rules_heuristics.rules_heuristics_dto import RuleResponseDTO
from core_orchestrator.infrastructure.dto.telemetry.analysis_report_dto import AnalysisReportResponseDTO
from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO

T = TypeVar("T")
D = TypeVar("D", bound=BaseModel)

class GenericMapper(Generic[T, D]):
    def __init__(self, dataclass_cls: Type[T], dto_cls: Type[D]) -> None:
        self.dataclass_cls = dataclass_cls
        self.dto_cls = dto_cls

    def to_dataclass(self, dto: D) -> T:
        """Convert a DTO (Pydantic) into the target domain type.

        Supports both dataclasses and Pydantic models as domain types.
        """
        data = dto.model_dump()
        # dataclass target
        if hasattr(self.dataclass_cls, "__dataclass_fields__"):
            type_hints = get_type_hints(self.dataclass_cls)

            def _resolve_dataclass_type(field_type: Any):
                if isinstance(field_type, type) and is_dataclass(field_type):
                    return field_type
                origin = get_origin(field_type)
                if origin is Union:
                    for arg in get_args(field_type):
                        resolved = _resolve_dataclass_type(arg)
                        if resolved is not None:
                            return resolved
                return None

            def _coerce(field_type: Any, value: Any):
                nested_type = _resolve_dataclass_type(field_type)
                if nested_type is not None and isinstance(value, Mapping):
                    nested_hints = get_type_hints(nested_type)
                    nested_payload = {}
                    for nested_name, nested_def in nested_type.__dataclass_fields__.items():
                        if nested_name in value:
                            nested_payload[nested_name] = _coerce(nested_hints.get(nested_name, nested_def.type), value[nested_name])
                    return nested_type(**nested_payload)
                return value

            fields = self.dataclass_cls.__dataclass_fields__.keys()
            payload = {}
            for field_name in fields:
                if field_name in data:
                    payload[field_name] = _coerce(type_hints.get(field_name), data[field_name])
            return self.dataclass_cls(**payload)

        # pydantic model target
        if isinstance(self.dataclass_cls, type) and issubclass(self.dataclass_cls, BaseModel):
            return self.dataclass_cls.model_validate(data)

        # fallback: try direct construction
        return self.dataclass_cls(**data)

    def to_dataclass_list(self, dtos: List[D]) -> List[T]:
        return [self.to_dataclass(dto) for dto in dtos]

    def to_dto(self, entity: T) -> D:
        """Convert a domain entity into the configured DTO.

        Supports dataclasses and Pydantic domain models.
        """
        if hasattr(entity, "__dataclass_fields__"):
            payload = asdict(entity)
        elif hasattr(entity, "model_dump"):
            payload = entity.model_dump()
        else:
            # last resort
            payload = dict(getattr(entity, "__dict__", {}))

        # Use model_validate to construct DTO from mapping
        return self.dto_cls.model_validate(payload)

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


class RuleMapper(GenericMapper[HeuristicRule, RuleResponseDTO]):
    def __init__(self):
        super().__init__(dataclass_cls=HeuristicRule, dto_cls=RuleResponseDTO)

    def to_dataclass(self, dto: BaseModel) -> HeuristicRule:
        rule = super().to_dataclass(dto)
        if rule.validation_rules is None:
            return replace(rule, validation_rules=ValidationRules())
        return rule

analysis_report_mapper = AnalysisReportMapper()
log_event_mapper = LogEventMapper()
rule_mapper = RuleMapper()



