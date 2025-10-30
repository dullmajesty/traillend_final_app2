from .models import UserBorrower

def reset_borrower_status():
    """
    Monthly scheduled task that resets late counts and borrower status.
    Run using django-crontab or Celery beat.
    """
    borrowers = UserBorrower.objects.all()
    for b in borrowers:
        b.late_count = 0
        b.borrower_status = "Good"
        b.save()
    print("✅ Monthly borrower reset completed.")
