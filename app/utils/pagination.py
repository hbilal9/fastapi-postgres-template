from functools import wraps
from fastapi import HTTPException, status
from typing import Type, Callable, Any
from app.schema.pagination import PaginationResponseSchema

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
