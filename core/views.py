# core/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_GET
from django.http import JsonResponse, Http404
from collections import defaultdict
from django.db import transaction
from django.db.models import Sum
import datetime as dt
import json
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated #neww
from rest_framework.authentication import SessionAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.template.loader import render_to_string
from django.utils import timezone

# ✅ import your models (Reservation was missing before)
from .models import UserBorrower, Item, Reservation

# If you need DRF perms later:
# from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated, AllowAny

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

#notifications
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile
from firebase_admin import messaging
from .models import DeviceToken, Notification
from .models import Notification


#FORGOT PASSWORD
from django.core.mail import send_mail
from django.contrib import messages
from django.shortcuts import render, redirect
from django.conf import settings
import random


#logout
from django.shortcuts import redirect
from django.contrib.auth import logout as auth_logout

from .models import Notification, DeviceToken

# -----------------------
# Web views (templates)
# -----------------------

def admin_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_staff:  # Only allow admin/staff
                login(request, user)
                return redirect('dashboard')  # Dashboard URL (to be created)
            else:
                messages.error(request, "You do not have admin access")
        else:
            messages.error(request, "Invalid username or password")

    return render(request, "login.html")


@ensure_csrf_cookie
@login_required
def dashboard(request):
    total_users = UserBorrower.objects.count()
    total_items = Item.objects.count()
    total_transactions = Reservation.objects.count()
    total_borrowed = Reservation.objects.filter(status='approved').count()

    context = {
        'total_users': total_users,
        'total_items': total_items,
        'total_transactions': total_transactions,
        'total_borrowed': total_borrowed,
    }

    return render(request, "dashboard.html", context)


#NEW
def forgot_password(request):
    show_code_container = False
    email_value = ""  # store email to keep it in the input

    if request.method == 'POST':
        # When admin clicks "Send Reset Code"
        if 'send_code' in request.POST:
            email = request.POST.get('email')
            email_value = email  # keep value for re-render

            try:
                user = User.objects.get(email=email)
                code = random.randint(100000, 999999)
                request.session['reset_email'] = email
                request.session['reset_code'] = str(code)

                send_mail(
                    subject="TrailLend Password Reset Code",
                    message=f"Your password reset code is {code}. Please use this code to verify your identity.",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )

                messages.success(request, "A reset code has been sent to your email. Please check your inbox.")
                show_code_container = True

            except User.DoesNotExist:
                messages.error(request, "This email doesn't exist.")

        # When admin clicks "Verify Code"
        elif 'verify_code' in request.POST:
            input_code = request.POST.get('reset_code')
            session_code = request.session.get('reset_code')
            email_value = request.session.get('reset_email', '')

            if input_code == session_code:
                messages.success(request, "Code verified successfully! You can now reset your password.")
                return redirect('verify_reset_code')
            else:
                messages.error(request, "Invalid or incorrect code.")
                show_code_container = True

        # When admin clicks "Resend Code"
        elif 'resend_code' in request.POST:
            email = request.session.get('reset_email')
            email_value = email
            if email:
                code = random.randint(100000, 999999)
                request.session['reset_code'] = str(code)
                send_mail(
                    subject="TrailLend Password Reset Code (Resent)",
                    message=f"Your new password reset code is {code}.",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )
                messages.success(request, "A new code has been sent to your email.")
                show_code_container = True
            else:
                messages.error(request, "No email session found. Please enter your email again.")

    return render(request, "forgot_password.html", {
        'show_code_container': show_code_container,
        'email': email_value or request.session.get('reset_email', '')
    })

#NEW
def verify_reset_code(request):
    """
    Page for entering a new password after verifying the reset code.
    """
    email = request.session.get('reset_email')

    if not email:
        messages.error(request, "Session expired. Please enter your email again.")
        return redirect('forgot_password')

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not new_password or not confirm_password:
            messages.error(request, "Please fill in all fields.")
        elif new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
        else:
            try:
                user = User.objects.get(email=email)
                user.set_password(new_password)
                user.save()

                # Clear session data
                request.session.pop('reset_email', None)
                request.session.pop('reset_code', None)

                # ✅ Show success message (used by popup)
                messages.success(request, "Your password has been successfully changed.")
                return render(request, "verify_reset_code.html")

            except User.DoesNotExist:
                messages.error(request, "User not found. Please try again.")

    return render(request, "verify_reset_code.html", {"email": email})


def inventory(request):
    items = Item.objects.all()

    # Get filter parameters from GET request
    q = request.GET.get('q', '')
    category = request.GET.get('category', '')
    status = request.GET.get('status', '')
    sort = request.GET.get('sort', 'newest')

    # Apply search filter
    if q:
        items = items.filter(name__icontains=q)

    # Apply category filter
    if category:
        items = items.filter(category=category)

    # Apply status filter
    if status:
        items = items.filter(status=status)

    # Apply sorting
    if sort == 'newest':
        items = items.order_by('-item_id')
    else:
        items = items.order_by('item_id')

    total_items = items.count()

    context = {
        'items': items,
        'q': q,
        'category': category,
        'status': status,
        'sort': sort,
        'total_items': total_items
    }

    return render(request, 'inventory.html', context)


def inventory_createitem(request):
    if request.method == "POST":
        name = request.POST.get('item_name')
        qty = request.POST.get('quantity')
        category = request.POST.get('category')
        description = request.POST.get('description', '')
        image = request.FILES.get('item_image')
        status = request.POST.get('item_status', 'Available')
        owner = request.POST.get('item_owner', 'Barangay Kauswagan')

        # Create the item using correct model field names
        Item.objects.create(
            name=name,
            qty=qty,
            category=category,
            description=description,
            image=image,
            owner=owner,
            status=status,
        )

        return redirect('inventory')

    return render(request, "inventory_createitem.html")


def inventory_edit(request, item_id):
    item = Item.objects.get(item_id=item_id)

    if request.method == 'POST':
        item.name = request.POST.get('name')
        item.qty = request.POST.get('qty')
        item.description = request.POST.get('description')
        item.category = request.POST.get('category')
        item.status = request.POST.get('status')
        item.owner = request.POST.get('owner')

        if 'image' in request.FILES:
            item.image = request.FILES['image']

        item.save()
        return redirect('inventory')

    return render(request, "inventory_edit.html", {'item': item})


def inventory_detail(request, item_id):
    item = Item.objects.get(item_id=item_id)
    return render(request, "inventory_detail.html", {'item': item})


def inventory_delete(request):
    return render(request, "inventory_confirm_delete.html")


def block_date(request):
    return render(request, "")  # TODO: supply a template name or remove this view


def verification(request):
    return render(request, 'verification.html')


def transaction_log(request):
    """
    Show all reservations that have progressed past 'pending'.
    You can filter by GET params later (status, dates, search).
    """
    qs = (
        Reservation.objects
        .exclude(status='pending')  # only show approved/denied/returned (if you add)
        .select_related('item', 'userborrower_user')  # userborrower accessed via reverse from User if needed
        .order_by('-id')
    )

    transactions = []
    for r in qs:
        # Prefer full_name from profile; fall back to username
        full_name = ""
        try:
            profile = UserBorrower.objects.select_related('user').get(user=r.user)
            full_name = profile.full_name or ""
        except UserBorrower.DoesNotExist:
            pass

        transactions.append({
            "transaction_id": getattr(r, "id", ""),  # or r.transaction_id if you have it
            "user_name": full_name or (r.user.username if r.user else ""),
            "item_name": r.item.name if r.item else "",
            "date_receive": getattr(r, "date_receive", None),
            "date_returned": getattr(r, "date_returned", None),
            "status": r.status,
        })

    return render(request, 'transaction_history.html', {"transactions": transactions})


def damage_report(request):
    return render(request, 'damage.html')


def statistics(request):
    return render(request, 'statistics.html')


def change_pass(request):
    return render(request, 'change-password.html')


def list_of_users(request):
    profiles = UserBorrower.objects.select_related('user').all()
    return render(request, 'list_of_users.html', {'profiles': profiles})


def logout(request):
    auth_logout(request)
    return redirect('login')


# -----------------------
# API views (JSON)
# -----------------------

@csrf_exempt
def api_register(request):
    """
    API endpoint for mobile users to register
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body or "{}")
            username = data.get("username")
            password = data.get("password")
            confirm_password = data.get("confirmPassword")
            full_name = data.get("name")
            contact_number = data.get("contactNumber")
            address = data.get("address")

            if not username or not password or not confirm_password or not full_name:
                return JsonResponse({"success": False, "message": "Missing required fields"}, status=400)

            # Check if username exists
            if User.objects.filter(username=username).exists():
                return JsonResponse({"success": False, "message": "Username already exists"}, status=400)

            if password != confirm_password:
                return JsonResponse({"success": False, "message": "Passwords do not match"}, status=400)

            # Create User
            user = User.objects.create_user(
                username=username,
                password=password,
                is_staff=False,
                is_active=True
            )

            # Create UserProfile
            UserBorrower.objects.create(
                user=user,
                full_name=full_name,
                contact_number=contact_number,
                address=address
            )

            return JsonResponse({"success": True, "message": "User registered successfully"}, status=201)

        except Exception as e:
            return JsonResponse({"success": False, "message": str(e)}, status=400)

    return JsonResponse({"success": False, "message": "Invalid request method"}, status=405)


@csrf_exempt
def api_login(request):
    """
    API endpoint for mobile users to login and get JWT token
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body or "{}")
            username = data.get("username")
            password = data.get("password")

            if not username or not password:
                return JsonResponse({"success": False, "message": "Username and password required"}, status=400)

            user = authenticate(request, username=username, password=password)

            if user is not None:
                refresh = RefreshToken.for_user(user)
                return JsonResponse({
                    "success": True,
                    "message": "Login successful",
                    "refresh": str(refresh),
                    "access": str(refresh.access_token)
                }, status=200)
            else:
                return JsonResponse({"success": False, "message": "Invalid credentials"}, status=401)
        except Exception as e:
            return JsonResponse({"success": False, "message": str(e)}, status=400)

    return JsonResponse({"success": False, "message": "Invalid request method"}, status=405)


@api_view(['GET'])
@permission_classes([AllowAny])
def pending_requests_api(request):
    qs = (Reservation.objects
          .filter(status='pending')
          .select_related('item', 'userborrower')
          .order_by('-id'))
    html = render_to_string('pending_requests_list.html', {'pending_request': qs}, request=request)
    return Response({'html': html})


@api_view(['GET'])
@authentication_classes([SessionAuthentication, JWTAuthentication])
@permission_classes([IsAuthenticated])
def reservation_detail_api(request, pk: int):
    r = get_object_or_404(Reservation.objects.select_related('item', 'userborrower'), pk=pk)

    def abs_url(filefield):
        if not filefield:
            return ''
        try:
            return request.build_absolute_uri(filefield.url)
        except Exception:
            return ''

    data = {
        'id': r.id,
        'item': {'name': getattr(r.item, 'name', '')},
        'userborrower': {'full_name': getattr(r.userborrower, 'full_name', '')},
        'quantity': r.quantity,
        'date': r.date.strftime('%Y-%m-%d') if getattr(r, 'date', None) else '',
        'message': r.message or '',
        'contact': r.contact or '',
        'status': r.status,
        'priority': r.priority,                       # <--- raw
        'priority_display': pretty_priority(r.priority),  # <--- pretty
        'letter_image': abs_url(getattr(r, 'letter_image', None)),
        'valid_id_image': abs_url(getattr(r, 'valid_id_image', None)),
    }
    return Response(data)

@api_view(['POST'])
@authentication_classes([SessionAuthentication, JWTAuthentication])
@permission_classes([IsAuthenticated])
def reservation_update_api(request, pk: int):
    from django.conf import settings
    r = get_object_or_404(Reservation, pk=pk)
    new_status = (request.data or {}).get('status')

    allowed = {'approved', 'rejected', 'borrowed', 'returned', 'pending'}
    if new_status not in allowed:
        return Response({'status': 'error', 'message': 'Invalid status'}, status=400)

    # Update dates based on new status
    if new_status == 'approved' and hasattr(r, 'approved_at'):
        r.approved_at = timezone.now()
    if new_status == 'borrowed' and hasattr(r, 'date_receive'):
        r.date_receive = timezone.now()
    if new_status == 'returned' and hasattr(r, 'date_returned'):
        r.date_returned = timezone.now()

    r.status = new_status
    r.save()

    # 🧩 If approved — generate QR + create notification + send push
    if new_status == 'approved':
        # 1️⃣ Generate QR Code
        qr_data = f"""
        Transaction ID: {r.transaction_id}
        Borrower: {r.userborrower.full_name}
        Item: {r.item.name}
        Quantity: {r.quantity}
        Date: {r.date}
        Contact: {r.contact}
        """
        qr_img = qrcode.make(qr_data)
        buffer = BytesIO()
        qr_img.save(buffer, format='PNG')
        qr_file = ContentFile(buffer.getvalue(), f"qr_{r.transaction_id}.png")

        # 2️⃣ Create Notification entry
        notif = Notification.objects.create(
            user=r.userborrower,
            title="Reservation Approved",
            message=f"Your reservation for {r.item.name} has been approved! Show this QR code to the admin upon claiming.",
            type="approval"
        )
        notif.qr_code.save(f"qr_{r.transaction_id}.png", qr_file)
        notif.save()

        # 3️⃣ Send Push Notification (if token exists)
        try:
            token_entry = DeviceToken.objects.filter(user=r.userborrower).last()
            if token_entry:
                message = messaging.Message(
                    notification=messaging.Notification(
                        title="Request Approved ✅",
                        body=f"Your QR code for {r.item.name} is ready!"
                    ),
                    token=token_entry.token,
                )
                messaging.send(message)
        except Exception as e:
            print("Error sending push notification:", e)

    return Response({'status': 'success'})




PRIORITY_LABELS = {
    "High":   "High — Bereavement",
    "Medium": "Medium — Event",
    "Low":    "Low — General",
}
def pretty_priority(p: str) -> str:
    if not p:
        return "Low — General"
    return PRIORITY_LABELS.get(str(p), str(p))

   


def api_inventory_list(request):
    items = Item.objects.all().values(
        'item_id', 'name', 'qty', 'category', 'description', 'owner', 'status', 'image'
    )
    data = list(items)
    for item in data:
        if item['image']:
            item['image'] = request.build_absolute_uri(f"/media/{item['image']}")
        else:
            item['image'] = None
    return JsonResponse(data, safe=False, status=200)


def api_inventory_detail(request, id):
    try:
        item = Item.objects.get(item_id=id)
        data = {
            "item_id": item.item_id,
            "item_name": item.name,
            "description": item.description,
            "quantity": item.qty,
            "item_owner": item.owner or "Barangay Kauswagan",
            "item_image": request.build_absolute_uri(f"/media/{item.image}") if item.image else None,
        }
        return JsonResponse(data, status=200)
    except Item.DoesNotExist:
        raise Http404("Item not found")



def total_reserved_qty_for_date(item, day):
    """
    Sum quantity for a specific date for this item, counting only
    statuses that hold stock (pending + approved).
    """
    agg = (Reservation.objects
           .filter(item=item, date=day, status__in=['pending', 'approved'])
           .aggregate(total=Sum('quantity')))
    return agg['total'] or 0

def find_next_available_dates(item, want_qty, start_date, horizon_days=30, limit=3):
    suggestions = []
    d = max(start_date, dt.date.today())
    horizon = d + dt.timedelta(days=horizon_days)
    while d <= horizon and len(suggestions) < limit:
        reserved = total_reserved_qty_for_date(item, d)
        if reserved + want_qty <= item.qty:
            suggestions.append({"date": d.isoformat()})
        d += dt.timedelta(days=1)
    return suggestions


class BlockedDatesView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, item_id):
        import datetime as dt

        days_ahead = int(request.query_params.get('days_ahead', 60))
        if days_ahead < 1 or days_ahead > 365:
            days_ahead = 60

        try:
            item = Item.objects.get(pk=item_id)
        except Item.DoesNotExist:
            return Response({"detail": "Item not found."}, status=404)

        start = dt.date.today()
        end = start + dt.timedelta(days=days_ahead)

        blocked = []
        d = start
        while d <= end:
            reserved = total_reserved_qty_for_date(item, d)  # uses date + quantity
            if reserved >= item.qty:  # item.qty is total stock
                blocked.append(d.isoformat())
            d += dt.timedelta(days=1)

        return Response({"blocked": blocked}, status=200)


class CheckAvailabilityView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        import datetime as dt
        try:
            item_id = int(request.data.get("item_id"))
            want_qty = int(request.data.get("qty"))
            date_str = request.data.get("date")
            reserve_date = dt.date.fromisoformat(date_str)
        except Exception:
            return Response({"detail": "Invalid payload."}, status=400)

        if want_qty < 1:
            return Response({"detail": "qty must be >= 1"}, status=400)

        try:
            item = Item.objects.get(pk=item_id)
        except Item.DoesNotExist:
            return Response({"detail": "Item not found."}, status=404)

        reserved = total_reserved_qty_for_date(item, reserve_date)  # date + quantity
        if reserved + want_qty > item.qty:
            suggestions = find_next_available_dates(item, want_qty, reserve_date, horizon_days=30, limit=3)
            return Response(
                {"detail": "Requested date is not available.",
                 "blocked": [reserve_date.isoformat()],
                 "suggestions": suggestions},
                status=409
            )

        return Response({"ok": True}, status=200)



#UPDATED

class CreateReservationView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]  # accept multipart & JSON

    @transaction.atomic
    def post(self, request):
        import datetime as dt
        data = request.data

        try:
            item_id = int(data.get("itemID"))
            qty = int(data.get("quantity"))
            reserve_date = dt.date.fromisoformat(data.get("date"))
            message = data.get("message", "")
            priority = data.get("priority", "Low")
        except Exception:
            return Response({"detail": "Invalid payload."}, status=400)

        user = request.user
        if not user or not user.is_authenticated:
            return Response({"detail": "Authentication required."}, status=401)

        try:
            borrower = UserBorrower.objects.get(user=user)
        except UserBorrower.DoesNotExist:
            return Response({"detail": "Borrower profile not found for this user."}, status=404)

        try:
            item = Item.objects.select_for_update().get(pk=item_id)
        except Item.DoesNotExist:
            return Response({"detail": "Item not found."}, status=404)

        reserved = total_reserved_qty_for_date(item, reserve_date)
        if reserved + qty > item.qty:
            suggestions = find_next_available_dates(item, qty, reserve_date, 30, 3)
            return Response(
                {
                    "detail": "Requested date is not available.",
                    "blocked": [reserve_date.isoformat()],
                    "suggestions": suggestions,
                },
                status=409,
            )

        # ✅ files & contact
        letter_file = request.FILES.get("letter_image")
        id_file = request.FILES.get("valid_id_image")
        contact = data.get("contact") or borrower.contact_number or "N/A"

        # ✅ Create Reservation
        r = Reservation.objects.create(
            item=item,
            userborrower=borrower,
            quantity=qty,
            date=reserve_date,
            message=message,
            priority=priority,
            letter_image=letter_file,
            valid_id_image=id_file,
            contact=contact,
            status='pending',
        )
        r.transaction_id = f"T{r.id:06d}"
        r.save(update_fields=["transaction_id"])

        # ✅ Create Pending Notification
        create_notification(
            borrower,
            title="Pending Reservation 🕒",
            message=f"Your reservation for {item.name} is pending admin approval.",
            notif_type="pending"
        )

        return Response(
            {"id": r.id, "transaction_id": r.transaction_id, "status": r.status},
            status=201,
        )


@csrf_exempt
def user_profile(request):
    """
    API endpoint to fetch user borrower profile
    """
    if request.method == "GET":
        try:
            username = request.GET.get("username")

            if not username:
                return JsonResponse({"success": False, "message": "Username is required"}, status=400)

            # Find the user
            user = User.objects.filter(username=username).first()
            if not user:
                return JsonResponse({"success": False, "message": "User not found"}, status=404)

            # Find the borrower profile
            borrower = UserBorrower.objects.filter(user=user).first()
            if not borrower:
                return JsonResponse({"success": False, "message": "No profile found"}, status=404)

            # ✅ Get image URL (check if profile_image field exists)
            image_url = borrower.profile_image.url if getattr(borrower, "profile_image", None) else None

            # ✅ Return all user borrower data including image
            return JsonResponse({
                "success": True,
                "data": {
                    "username": user.username,
                    "name": borrower.full_name,
                    "contactNumber": borrower.contact_number,
                    "address": borrower.address,
                    "image": image_url,  # 👈 Added this line
                }
            }, status=200)

        except Exception as e:
            return JsonResponse({"success": False, "message": str(e)}, status=400)

    # ✅ Handle incorrect request methods
    return JsonResponse({"success": False, "message": "Invalid request method"}, status=405)




@csrf_exempt
def update_profile(request):
    if request.method == "POST":
        try:
            username = request.POST.get("username")
            name = request.POST.get("name")
            contact_number = request.POST.get("contactNumber")
            address = request.POST.get("address")
            password = request.POST.get("password")

            user = User.objects.filter(username=username).first()
            if not user:
                return JsonResponse({"success": False, "message": "User not found"}, status=404)

            borrower = UserBorrower.objects.filter(user=user).first()
            if not borrower:
                return JsonResponse({"success": False, "message": "Profile not found"}, status=404)

            # ✅ Update fields
            borrower.full_name = name
            borrower.contact_number = contact_number
            borrower.address = address

            # ✅ Handle image upload
            if "profile_image" in request.FILES:
                borrower.profile_image = request.FILES["profile_image"]

            borrower.save()

            if password:
                user.set_password(password)
                user.save()

            return JsonResponse({"success": True, "message": "Profile updated successfully"})
        except Exception as e:
            return JsonResponse({"success": False, "message": str(e)}, status=400)
    return JsonResponse({"success": False, "message": "Invalid request method"}, status=405)


# NEW

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_device_token(request):
    """Save or update the borrower's device token."""
    user = request.user
    token = request.data.get('token')

    if not token:
        return Response({'success': False, 'message': 'Token required'}, status=400)

    DeviceToken.objects.update_or_create(user=user, defaults={'token': token})
    return Response({'success': True, 'message': 'Token saved'})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_notifications(request):
    """Return list of notifications for the logged-in borrower."""
    user = request.user
    borrower = getattr(user, 'userborrower', None)
    if not borrower:
        return Response({'success': True, 'notifications': []}, status=200)


    notifications = Notification.objects.filter(user=borrower).order_by('-created_at')
    data = [
        {
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'type': n.type,
            'qr_code': request.build_absolute_uri(n.qr_code.url) if n.qr_code else None,
            'is_read': n.is_read,
            'created_at': n.created_at.strftime('%Y-%m-%d %H:%M'),
        }
        for n in notifications
    ]
    return Response({'success': True, 'notifications': data}, status=200)


def create_notification(borrower, title, message, notif_type='general', qr_file=None):
    """Reusable helper to create both in-app + push notification."""
    notif = Notification.objects.create(
        user=borrower,
        title=title,
        message=message,
        type=notif_type
    )

    if qr_file:
        notif.qr_code.save(f"qr_{borrower.user.username}.png", qr_file)

    # 🔔 Optional push notification
    try:
        token_entry = DeviceToken.objects.filter(user=borrower.user).last()
        if token_entry:
            push_message = messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=message
                ),
                token=token_entry.token,
            )
            messaging.send(push_message)
    except Exception as e:
        print("⚠️ Error sending push notification:", e)

    return notif


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def mark_notification_as_read(request, pk):
    """
    Marks a specific notification as read (is_read=True)
    """
    try:
        notif = Notification.objects.get(pk=pk, user__user=request.user)
        notif.is_read = True
        notif.save()
        return Response({'success': True, 'message': 'Notification marked as read'})
    except Notification.DoesNotExist:
        return Response({'success': False, 'message': 'Notification not found'}, status=404)
    

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_reservations(request):
    borrower = getattr(request.user, 'userborrower', None)
    if not borrower:
        return Response({'success': False, 'reservations': []})

    reservations = Reservation.objects.filter(userborrower=borrower).select_related('item').order_by('-created_at')

    data = []
    for r in reservations:
        image_url = request.build_absolute_uri(r.item.image.url) if r.item and r.item.image else None
        data.append({
            'id': r.id,
            'transaction_id': r.transaction_id,
            'item_name': r.item.name if r.item else '',
            'quantity': r.quantity,
            'date': r.date.strftime('%Y-%m-%d'),
            'status': r.status,
            'priority': r.priority,
            'message': r.message or '',
            'image_url': image_url,  # ✅ include image
        })

    return Response({'success': True, 'reservations': data}, status=200)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def cancel_reservation(request, pk):
    """
    Allows the borrower to cancel their own pending reservation.
    """
    borrower = getattr(request.user, 'userborrower', None)
    if not borrower:
        return Response({'success': False, 'message': 'Unauthorized user.'}, status=403)

    try:
        reservation = Reservation.objects.get(pk=pk, userborrower=borrower)

        if reservation.status != 'pending':
            return Response({'success': False, 'message': 'Only pending reservations can be cancelled.'}, status=400)

        reservation.status = 'cancelled'
        reservation.save()

        # ✅ Create Cancellation Notification
        create_notification(
            borrower,
            title="Reservation Cancelled ❌",
            message=f"You cancelled your reservation for {reservation.item.name}.",
            notif_type="cancelled"
        )

        return Response({'success': True, 'message': 'Reservation cancelled successfully.'}, status=200)
    except Reservation.DoesNotExist:
        return Response({'success': False, 'message': 'Reservation not found.'}, status=404)
