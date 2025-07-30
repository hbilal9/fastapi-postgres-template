import json
from functools import wraps

from aiocache import Cache
from fastapi.encoders import jsonable_encoder

from .config import settings

_cache_instance = None


def _get_cache() -> Cache:
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = Cache.REDIS(
            endpoint=settings.REDIS_HOST,
            port=int(settings.REDIS_PORT),
            db=int(getattr(settings, "REDIS_DB", 0)),
            namespace="main",
        )
    return _cache_instance


def cache_response(ttl: int = 60, namespace: str = "main", key: str = None):
    """
    Caching decorator for FastAPI endpoints.

    :param ttl: Time to live for cache entry in seconds.
    :param namespace: Namespace prefix for cache keys.
    :param key: Optional fixed cache key string.
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            cache_key = key
            if cache_key is None:
                # Fallback key format based on namespace and first arg or user_id kwarg
                user_id = kwargs.get("user_id") or (args[0] if args else None)
                if user_id is None:
                    # No valid key, just call the function
                    return await func(*args, **kwargs)
                cache_key = f"{namespace}:user:{user_id}"

            cache = _get_cache()

            cached_value = await cache.get(cache_key)
            if cached_value:
                return json.loads(cached_value)

            response = await func(*args, **kwargs)
            encoded_response = jsonable_encoder(response)

            await cache.set(cache_key, json.dumps(encoded_response), ttl=ttl)
            return response

        return wrapper

    return decorator


async def invalidate_cache_key(key: str, namespace: str = "main"):
    """
    Invalidate a cache key in Redis.

    :param key: The cache key to delete.
    """
    cache = _get_cache()
    await cache.delete(key)
