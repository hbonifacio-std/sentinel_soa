from dataclasses import asdict
from typing import TypeVar, Generic, List, Optional, Dict, Any, Mapping
from pymongo import InsertOne
from pymongo.asynchronous.collection import AsyncCollection
import asyncio

from core_orchestrator.infrastructure.adapters.helper.map_to_dataclass import map_to_dataclass
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginatedResult, PaginationMeta

ModelType = TypeVar("ModelType")

class BaseRepository(Generic[ModelType]):
    """
    BaseRepository provides a generic implementation for common database operations.

    This class is designed to handle CRUD operations and other database interactions
    for a MongoDB collection. It leverages an abstraction layer to work with multiple
    models, leveraging Python's type system and MongoDB's asynchronous API.
    """
    def __init__(self, collection: AsyncCollection, model: ModelType):
        self.collection = collection
        self.model = model

    def _document_to_dataclass(self, doc: Optional[Mapping[str, Any]]) -> Optional[ModelType]:
        """
        Transforms a dictionary document into a dataclass instance of the specified model.

        This method processes a dictionary object retrieved from a database or other
        source, converting it into a dataclass instance of the specified model type. It
        performs the following transformations:
          1. Maps the "_id" field (ObjectId) to "id" (str) if present.
          2. Filters out keys that are not defined in the dataclass fields of the model,
             ensuring that only valid attributes are included.

        Parameters:
        doc: Optional[Dict[str, Any]]
            The dictionary document to be transformed. If None or an empty dictionary
            is provided, the method will return None.

        Returns:
        Optional[ModelType]
            An instance of the specified dataclass model populated with the filtered
            and transformed data from the document, or None if the input document is
            None or empty.
        """
        if not doc:
            return None

        data = dict(doc)
        if "_id" in data:
            data["id"] = str(data.pop("_id"))

        return map_to_dataclass(self.model, data)

    async def insert(self, model_instance: ModelType) -> str:
        document = asdict(model_instance)

        document.pop("id", None)
        document.pop("_id", None)

        result = await self.collection.insert_one(document)

        if hasattr(model_instance, "id"):
            model_instance.id = str(result.inserted_id)

        return str(result.inserted_id)

    async def find_one(self, query: Dict[str, Any]) -> Optional[ModelType]:
        """
        Finds a single document in the collection based on the provided query and returns it as a model instance.

        Parameters:
        query (Dict[str, Any]): A dictionary representing the query criteria to filter documents.

        Returns:
        Optional[ModelType]: An instance of the model representing the document if found, or None if no document matches
        the query.

        """
        doc = await self.collection.find_one(query)
        return self._document_to_dataclass(doc)

    async def exists(self, query: Dict[str, Any]) -> bool:
        """
        Checks if a document matching the given query exists in the database.

        This method performs an asynchronous operation to query the database for
        a document matching the specified conditions and determines whether at
        least one document satisfies the query.

        Parameters:
            query (Dict[str, Any]): The query criteria to search for in the database.

        Returns:
            bool: True if at least one document matches the query, otherwise False.
        """
        count = await self.collection.count_documents(query, limit=1)
        return count > 0

    async def find_many(self, query: Dict[str, Any]) -> List[ModelType]:
        cursor = self.collection.find(query)
        docs = await cursor.to_list(length=None)

        results = []

        for doc in docs:
            if "_id" in doc:
                doc["id"] = str(doc.pop("_id"))
            results.append(map_to_dataclass(self.model, doc))
        return results


    async def find_paginated(
            self, query: Optional[Dict[str, Any]] = None, page: Optional[int] = 1, limit: Optional[int] = 10,
            sort_by: Optional[str] = None, descending: bool = True) -> PaginatedResult[ModelType]:
        """
        Asynchronously retrieves paginated results from a MongoDB collection based on the provided query,
        pagination parameters, and sorting options. The method calculates pagination metadata, such as the total
        number of records, current page, previous page, and next page.

        Parameters:
            query (Optional[Dict[str, Any]]): A dictionary-defining filtering criteria for the MongoDB query.
                Defaults to None, which retrieves all-record
            page (int): The current page number to retrieve. Defaults to 1
            limit (int): The maximum number of records to return per page. Defaults to 10
            sort_by (Optional[str]): The field by which to sort the results. Defaults to None, meaning results
                will not be sorted
            descending (bool): Indicates whether the sorting should be in descending order if a sort_by field
                is specified. Defaults to True

        Returns:
            Dict[str, Any]: A dictionary containing two keys:
                - "info": An information dictionary with metadata about the pagination that includes total
                  number of records, current page, page size (limit), next page (if applicable), and previous
                  page (if applicable).
                - "results": A list of the documents retrieved from the query, cast as instances of a specified
                  model.

        Raises:
            AssertionError: If pagination is enabled and the limit parameter is None.
        """
        filter_query = query or {}
        cursor = self.collection.find(filter_query)

        if sort_by:
            direction = -1 if descending else 1
            cursor = cursor.sort(sort_by, direction)

        if page is not None and limit is not None:
            skip = (page - 1) * limit
            cursor = cursor.skip(skip).limit(limit)
            list_length: Optional[int] = limit
        else:
            list_length = None

        total_records, docs = await asyncio.gather(
            self.collection.count_documents(filter_query),
            cursor.to_list(length=list_length)
        )

        results = [
            dataclass_inst
            for doc in docs
            if (dataclass_inst := self._document_to_dataclass(doc)) is not None
        ]


        if page is not None and limit is not None and limit > 0:
            total_pages = (total_records + limit - 1) // limit

            next_page = str(page + 1) if page < total_pages else None
            prev_page = str(page - 1) if page > 1 else None

            info_meta = PaginationMeta(
                total_records=total_records,
                page=page,
                limit=limit,
                next_page=next_page,
                prev_page=prev_page
            )
        else:
            info_meta = PaginationMeta(
                total_records=total_records,
                page=1,
                limit=total_records,
                next_page=None,
                prev_page=None
            )
        return PaginatedResult(
            info=info_meta,
            results=results
        )


    async def update_partial(self, query: Dict[str, Any], updates: Dict[str, Any]) -> bool:
        """
        Updates specific fields of a document in the database that match the given query.

        The method applies the provided updates to the first document that matches the query. If no updates
        are provided or no document matches the query, no changes occur, and the method returns False.

        Parameters:
        query: Dict[str, Any]
            The query used to locate the document to be updated. It defines the conditions the
            document must meet to be eligible for an update.

        updates: Dict[str, Any]
            The fields and their new values to update in the document. The key specifies the field,
            and the value is the updated value to be set.

        Returns:
        bool
            True if at least one document was successfully updated, False otherwise.
        """
        if not updates:
            return False
        result = await self.collection.update_one(query, {"$set": updates})
        return result.modified_count > 0


    async def delete_physical(self, query: Dict[str, Any]) -> bool:
        """
        Deletes documents from the collection based on the provided query.

        This asynchronous method removes documents from the associated MongoDB collection
        that match the criteria specified in the query. It returns a boolean indicating whether
        any documents were successfully deleted.

        Args:
            query (Dict[str, Any]): A dictionary specifying the filter conditions for
            the documents to be deleted.

        Returns:
            bool: True if one or more documents were deleted, False otherwise.
        """
        result = await self.collection.delete_many(query)
        return result.deleted_count > 0


    async def delete_logical(self, query: Dict[str, Any], deleted_by: str = "system") -> bool:
        """
        Asynchronously performs a logical delete operation by marking a record as inactive and updating
        related metadata such as deletion timestamp and user.

        Args:
            query (Dict[str, Any]): Query criteria to identify the record(s) to be logically deleted
            deleted_by (str): Identifies the user or system that performed the delete operation
                              Default is "system".

        Returns:
            bool: Indicates whether the logical delete operation was successful or not.
        """
        from datetime import datetime, timezone
        soft_updates = {
            "is_active": False,
            "deleted_at": datetime.now(timezone.utc).isoformat(),
            "deleted_by": deleted_by
        }
        return await self.update_partial(query, soft_updates)


    async def bulk_insert(self, model_instances: List[ModelType]) -> int:
        """
        Performs a bulk insertion of model instances into the database collection.

        This method takes a list of model instances, converts them into insert operations,
        and performs a bulk write operation on the associated collection. It returns the
        count of successfully inserted documents.

        Parameters:
        model_instances (List[Any]): A list of model instances to be inserted into the
                                      database. Each instance is expected to have a
                                      `model_dump` method for conversion into JSON format.

        Returns:
        int: The number of documents successfully inserted into the database.

        Raises:
        TypeError: If `model_instances` is not a list.
        """
        if not model_instances:
            return 0
        operations = [InsertOne(asdict(model)) for model in model_instances]
        result = await self.collection.bulk_write(operations)
        return result.inserted_count