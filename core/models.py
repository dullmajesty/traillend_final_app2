from django.db import models
from django.contrib.auth.models import User

class UserBorrower(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=255)
    contact_number = models.CharField(max_length=20)
    address = models.TextField()
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True) 

    def __str__(self):
        return self.user.username
    
    
class Item(models.Model):
    item_id = models.AutoField(primary_key=True, db_column='item_id')
    name = models.CharField(max_length=100)
    qty = models.PositiveIntegerField()
    category = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='items/', blank=True, null=True)
    owner = models.CharField(max_length=100, default="Barangay Kauswagan")
    status = models.CharField(max_length=20, choices=[('Available', 'Available'), ('Not Available', 'Not Available')], default='Available')
    
    class Meta:
        db_table = 'core_item'
        
    def __str__(self):
        return self.name
    
class Reservation(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('borrowed', 'Borrowed'),
        ('returned', 'Returned'),
        ('rejected', 'Rejected'),
    ]

    transaction_id = models.CharField(max_length=20, default="T000000")
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name='reservations')
    userborrower = models.ForeignKey(UserBorrower, on_delete=models.CASCADE, null=True)

    # 🔹 NEW: date range instead of single date
    date_borrowed = models.DateField()
    date_return = models.DateField()

    quantity = models.PositiveIntegerField(default=1)

    PRIORITY_CHOICES = [
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='Low')

    letter_image = models.ImageField(upload_to='reservation_letters/', blank=True, null=True)
    valid_id_image = models.ImageField(upload_to='reservation_ids/', blank=True, null=True)
    message = models.TextField(blank=True, null=True)
    contact = models.CharField(max_length=30, default="N/A", blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    created_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    date_receive = models.DateTimeField(null=True, blank=True)
    date_returned = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.item.name} ({self.date_borrowed} → {self.date_return}) [{self.status}]"


class Notification(models.Model):
    user = models.ForeignKey(UserBorrower, on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    message = models.TextField()
    reason = models.TextField(blank=True, null=True)
    qr_code = models.ImageField(upload_to='qr_codes/', null=True, blank=True)
    type = models.CharField(max_length=50, default='general')
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.full_name} - {self.title}"
    
class DeviceToken(models.Model):
    user = models.ForeignKey(UserBorrower, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.full_name} - {self.token[:20]}..."