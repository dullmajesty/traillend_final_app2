from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import Notification

class Command(BaseCommand):
    help = "Send scheduled notifications (mark is_sent=True and make visible)"

    def handle(self, *args, **kwargs):
        now = timezone.now()

        # Find all notifications that are due but not sent yet
        pending = Notification.objects.filter(
            scheduled_at__lte=now,
            is_sent=False
        )

        if not pending.exists():
            self.stdout.write("No scheduled notifications to send.")
            return

        for notif in pending:
            # Mark as sent so it appears in the app
            notif.is_sent = True
            notif.save(update_fields=['is_sent'])

            self.stdout.write(
                self.style.SUCCESS(
                    f"[SENT] {notif.title} → User: {notif.user.full_name}"
                )
            )
