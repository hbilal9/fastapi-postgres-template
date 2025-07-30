import json
from functools import wraps

from aiocache import Cache

from .config import settings


def cache_response(ttl: int = 60, namespace: str = "main", key: str = None):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            cache_key = key
            if cache_key is None:
                # fallback cache key, e.g. based on function name and first arg
                user_id = kwargs.get("user_id") or (args[0] if args else None)
                cache_key = f"{namespace}:user:{user_id}"

            cache = Cache.REDIS(
                endpoint=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                namespace=namespace,
            )
            cached_value = await cache.get(cache_key)
            if cached_value:
                return json.loads(cached_value)

            response = await func(*args, **kwargs)
            await cache.set(cache_key, json.dumps(response), ttl=ttl)
            return response

        return wrapper

    return decorator


async def invalidate_cache_key(key: str, namespace: str = "main"):
    cache = Cache.REDIS(
        endpoint=settings.REDIS_HOST, port=settings.REDIS_PORT, namespace=namespace
    )
    await cache.delete(key)
