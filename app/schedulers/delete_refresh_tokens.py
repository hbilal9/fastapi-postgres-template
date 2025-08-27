import logging
from datetime import datetime, timezone

from sqlalchemy import delete

from app.models import RefreshToken
from app.utils.database import async_session  # async_sessionmaker

logger = logging.getLogger(__name__)


async def delete_expired_refresh_tokens() -> None:
    """
    Async job to remove expired refresh tokens.
    """
    logger.info("Scheduler: Running expired refresh token cleanup job.")
    async with async_session() as db:
        try:
            now = datetime.now(timezone.utc)

            # Use a bulk DELETE for efficiency
            result = await db.execute(
                delete(RefreshToken).where(RefreshToken.expires_at < now)
            )
            await db.commit()

            deleted = result.rowcount if result is not None else 0
            if deleted:
                logger.info(f"Scheduler: Deleted {deleted} expired refresh tokens.")
            else:
                logger.info("Scheduler: No expired refresh tokens to delete.")
        except Exception as exc:
            logger.error(f"Scheduler: An error occurred during token cleanup: {exc}")
