"""Poll the transactional outbox and recover stale investigation attempts."""

import logging
import time

from app.config import get_settings
from app.database import SessionLocal
from app.logging_config import configure_logging
from app.orchestration import dispatch_pending_outbox, reconcile_stale_investigations
from app.monitoring import enqueue_due_schedules, sync_monitoring_runs
from app.services.attack_catalog_sync import dispatch_pending_catalog_syncs, reconcile_stale_catalog_syncs
from app.services.threat_feeds import dispatch_pending_refreshes, enqueue_due_refresh, reconcile_stale_refreshes

logger = logging.getLogger("cyberlens.dispatcher")
POLL_INTERVAL_SECONDS = 2


def dispatch_once() -> dict[str, object]:
    db = SessionLocal()
    try:
        recovered = reconcile_stale_investigations(db)
        monitoring_updates = sync_monitoring_runs(db)
        scheduled = enqueue_due_schedules(db)
        delivered = dispatch_pending_outbox(db)
        catalog_delivered = dispatch_pending_catalog_syncs(db)
        catalog_recovered = reconcile_stale_catalog_syncs(db)
        feed_recovered = reconcile_stale_refreshes(db)
        feed_scheduled = int(enqueue_due_refresh(db))
        feed_delivered = dispatch_pending_refreshes(db)
        return {"delivered": delivered, "recovered": recovered,
                "monitoring_scheduled": scheduled, "monitoring_updated": monitoring_updates,
                "catalog_syncs_delivered": catalog_delivered, "catalog_syncs_recovered": catalog_recovered,
                "threat_feed_scheduled": feed_scheduled, "threat_feed_delivered": feed_delivered,
                "threat_feed_recovered": feed_recovered}
    finally:
        db.close()


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger.info("CyberLens investigation outbox dispatcher started")
    while True:
        try:
            dispatch_once()
        except Exception:
            # Startup migrations run in the API container; keep retrying if the
            # dispatcher starts first or a service is temporarily unavailable.
            logger.exception("dispatcher cycle failed")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
