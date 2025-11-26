from django.utils import timezone
from core.models import Notification, DeviceToken
from firebase_admin import messaging


def send_push(token, title, message):
    """Send push notification using Firebase Admin SDK."""
    try:
        msg = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=message,
            ),
            token=token
        )
        messaging.send(msg)
        print(f"📨 Push sent to token: {token[:10]}...")
    except Exception as e:
        print(f"❌ Error sending push: {e}")


def run():
    now = timezone.now()

    # Get all pending scheduled notifications
    pending = Notification.objects.filter(
        scheduled_at__lte=now,
        is_sent=False
    )

    if not pending.exists():
        print("No scheduled notifications to send.")
        return

    for notif in pending:

        # Get all device tokens for this user
        tokens = DeviceToken.objects.filter(user=notif.user)

        # SEND PUSH NOTIFICATION
        for device in tokens:
            send_push(
                device.token,
                notif.title,
                notif.message
            )

        # Mark as sent
        notif.is_sent = True
        notif.save()

        print(f"✔ Scheduled notif sent → {notif.title}")
