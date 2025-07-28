from functools import wraps
from typing import Callable, Generic, List, Type, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationResponseSchema(BaseModel, Generic[T]):
    items: List[T] = Field(..., description="List of items in the current page")
    total_items: int = Field(..., description="Total number of items across all pages")
    total_pages: int = Field(..., description="Total number of pages available")
    current_page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of items per page")
    has_next: bool = Field(..., description="Indicates if there is a next page")
    has_previous: bool = Field(..., description="Indicates if there is a previous page")


def paginator(schema: Type):
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            page = kwargs.get("page")
            page_size = kwargs.get("page_size")
            if page is None or page_size is None:
                import inspect

                sig = inspect.signature(func)
                params = list(sig.parameters)
                try:
                    page_idx = params.index("page")
                    page_size_idx = params.index("page_size")
                    page = args[page_idx] if len(args) > page_idx else 1
                    page_size = args[page_size_idx] if len(args) > page_size_idx else 10
                except ValueError:
                    page = page or 1
                    page_size = page_size or 10
            query = await func(*args, **kwargs)

            total_items = query.count()
            items = query.offset((page - 1) * page_size).limit(page_size).all()

            return PaginationResponseSchema[schema](
                items=[schema.model_validate(item) for item in items],
                total_items=total_items,
                total_pages=(total_items + page_size - 1) // page_size,
                current_page=page,
                page_size=page_size,
                has_next=page * page_size < total_items,
                has_previous=page > 1,
            )

        return wrapper

    return decorator
