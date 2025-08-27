import logging
from datetime import datetime, timezone

from sqlalchemy.future import select
from sqlalchemy.orm import Session

from app.models import RefreshToken
from app.utils.database import DbSession


async def delete_expired_refresh_tokens():
    """
    Queries and deletes all refresh tokens that have expired.
    """
    db: Session = DbSession()
    logging.info("Scheduler: Running expired refresh token cleanup job.")
    try:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(RefreshToken).filter(RefreshToken.expires_at < now)
        )
        expired_tokens = result.scalars().all()
        num_deleted = len(expired_tokens)
        if num_deleted > 0:
            for token in expired_tokens:
                await db.delete(token)
            await db.commit()
            logging.info(f"Scheduler: Deleted {num_deleted} expired refresh tokens.")
        else:
            logging.info("Scheduler: No expired refresh tokens to delete.")
    except Exception as e:
        logging.error(f"Scheduler: An error occurred during token cleanup: {e}")
        db.rollback()
    finally:
        db.close()
