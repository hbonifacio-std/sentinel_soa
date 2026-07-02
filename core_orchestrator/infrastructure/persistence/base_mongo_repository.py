from typing import TypeVar, Generic, List, Optional, Dict, Any, cast
from pymongo import InsertOne
from pymongo.asynchronous.collection import AsyncCollection
import asyncio

ModelType = TypeVar("ModelType")


class BaseRepository(Generic[ModelType]):
    def __init__(self, collection: AsyncCollection, model: type[ModelType]):
        self.collection = collection
        self.model = model

    async def insert(self, model_instance: Any, alternative_collection: Optional[AsyncCollection] = None) -> str:
        coll = alternative_collection or self.collection
        doc = model_instance.model_dump(mode="json")
        result = await coll.insert_one(doc)
        return str(result.inserted_id)

    async def find_one(self, query: Dict[str, Any]) -> Optional[ModelType]:
        doc = await self.collection.find_one(query)
        if not doc:
            return None
        dict_doc = cast(Dict[str, Any], doc)
        dict_doc.pop("_id", None)
        return self.model(**dict_doc)

    async def exists(self, query: Dict[str, Any]) -> bool:
        count = await self.collection.count_documents(query, limit=1)
        return count > 0


    async def find_paginated(
            self, query: Optional[Dict[str, Any]] = None, page: int = 1, limit: int = 10, sort_by: Optional[str] = None, descending: bool = True
    ) -> Dict[str, Any]:
        """
        Devuelve los resultados usando la estructura exacta de la interfaz frontend:
        PaginatedResponse<T> { info: PageInfo, results: T[] }
        """
        filter_query = query or {}
        cursor = self.collection.find(filter_query)

        if sort_by:
            direction = -1 if descending else 1
            cursor = cursor.sort(sort_by, direction)

        should_paginate = page is not None and limit is not None
        if should_paginate:
            assert limit is not None
            skip = (page - 1) * limit
            cursor = cursor.skip(skip).limit(limit)

        list_length = limit if should_paginate else None

        total_records, docs = await asyncio.gather(
            self.collection.count_documents(filter_query),
            cursor.to_list(length=list_length)
        )

        results = []
        for doc in docs:
            dict_doc = cast(Dict[str, Any], doc)
            results.append(self.model(**dict_doc))


        if should_paginate:
            total_pages = (total_records + limit - 1) // limit

            next_page = str(page + 1) if page < total_pages else None
            prev_page = str(page - 1) if page > 1 else None

            info_meta = {
                "total_records": total_records,
                "page": page,
                "limit": limit,
                "next_page": next_page,
                "prev_page": prev_page
            }
        else:
            info_meta = {
                "total_records": total_records,
                "page": 1,
                "limit": total_records,
                "next_page": None,
                "prev_page": None
            }
        return {
            "info": info_meta,
            "results": results
        }


    async def update_partial(self, query: Dict[str, Any], updates: Dict[str, Any]) -> bool:
        """
        Aplica un $set de MongoDB usando un diccionario plano.
        Evita tener que escribir update_one manualmente en cada repositorio hijo.
        """
        if not updates:
            return False
        result = await self.collection.update_one(query, {"$set": updates})
        return result.modified_count > 0


    async def delete_physical(self, query: Dict[str, Any]) -> bool:
        """Elimina físicamente los documentos que coincidan con el criterio."""
        result = await self.collection.delete_many(query)
        return result.deleted_count > 0


    async def delete_logical(self, query: Dict[str, Any], deleted_by: str = "system") -> bool:
        """
        En lugar de borrar, marca el registro como inactivo.
        Muy útil para reglas o auditorías que no deben perderse.
        """
        from datetime import datetime, timezone
        soft_updates = {
            "is_active": False,
            "deleted_at": datetime.now(timezone.utc).isoformat(),
            "deleted_by": deleted_by
        }
        return await self.update_partial(query, soft_updates)


    async def bulk_insert(self, model_instances: List[Any]) -> int:
        """Inserta cientos o miles de documentos en un solo viaje de red (Muy eficiente)."""
        if not model_instances:
            return 0
        operations = [InsertOne(model.model_dump(mode="json")) for model in model_instances]
        result = await self.collection.bulk_write(operations)
        return result.inserted_count