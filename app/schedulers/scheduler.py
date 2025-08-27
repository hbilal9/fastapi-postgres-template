from apscheduler.schedulers.asyncio import AsyncIOScheduler

from .delete_refresh_tokens import delete_expired_refresh_tokens

scheduler = AsyncIOScheduler()

scheduler.add_job(delete_expired_refresh_tokens, "cron", hour=0, minute=0)
# scheduler.add_job(delete_expired_refresh_tokens, "cron", minute="*")

scheduler.add_job(delete_expired_refresh_tokens, "cron", hour=0, minute=0)
# scheduler.add_job(delete_expired_refresh_tokens, "cron", minute="*")
