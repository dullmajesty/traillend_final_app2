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
from datetime import date, timedelta
from django.db.models import Sum, Q

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
from rest_framework.decorators import api_view, permission_classes, authentication_classes, parser_classes

# ✅ import your models (Reservation was missing before)
from .models import UserBorrower, Item, Reservation, Feedback

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

#stats
from django.db.models import Count
from django.db.models.functions import ExtractMonth
from django.utils.dateparse import parse_date
from django.views.decorators.http import require_GET
import csv
import io
from django.http import HttpResponse
import pandas as pd
from django.template.loader import render_to_string
from xhtml2pdf import pisa


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


@login_required
def dashboard(request):
    # Summary cards
    total_users = UserBorrower.objects.count()
    total_items = Item.objects.count()
    total_transactions = Reservation.objects.count()
    total_borrowed = Reservation.objects.filter(status__iexact='in use').count()

    # 🟢 PIE - Item Category Distribution
    category_data = Item.objects.values("category").annotate(count=Count("item_id"))
    pie_labels = [c["category"] for c in category_data]
    pie_values = [c["count"] for c in category_data]

    # 🟠 BAR - Monthly Transactions (based on date_borrowed)
    current_year = timezone.now().year
    monthly_data = (
        Reservation.objects.filter(date_borrowed__year=current_year)
        .annotate(month=ExtractMonth("date_borrowed"))
        .values("month")
        .annotate(count=Count("id"))
        .order_by("month")
    )

    month_names = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    month_counts = {m["month"]: m["count"] for m in monthly_data}
    bar_labels = month_names
    bar_values = [month_counts.get(i, 0) for i in range(1, 13)]

    # 🟣 DONUT - Borrowed vs Returned
    borrowed = Reservation.objects.filter(status__iexact='in use').count()
    returned = Reservation.objects.filter(status__iexact='returned').count()
    total = borrowed + returned
    borrowed_percent = round((borrowed / total * 100), 1) if total else 0
    returned_percent = round((returned / total * 100), 1) if total else 0
    borrowed_vs_returned = {
        "borrowed": borrowed_percent,
        "returned": returned_percent,
    }

    context = {
        "total_users": total_users,
        "total_items": total_items,
        "total_transactions": total_transactions,
        "total_borrowed": total_borrowed,
        "pie_labels": pie_labels,
        "pie_values": pie_values,
        "bar_labels": bar_labels,
        "bar_values": bar_values,
        "borrowed_vs_returned": borrowed_vs_returned,
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



def verification(request):
    return render(request, 'verification.html')

def transaction_log(request):
    """
    Show all reservations except pending ones (approved, borrowed, returned, rejected, etc.)
    """
    qs = (
        Reservation.objects
        .exclude(status='pending')
        .select_related('item', 'userborrower')
        .order_by('-id')
    )

    transactions = []
    for r in qs:
        borrower_name = getattr(r.userborrower, "full_name", "Unknown")
        item_name = getattr(r.item, "name", "Unknown")
        quantity = getattr(r, "quantity", 1)
        contact = getattr(r, "contact", "N/A")
        
        # 🔹 Contact logic: prefer reservation contact, else borrower's contact_number
        contact = getattr(r, "contact", None)
        if not contact or contact.strip().lower() in ["", "n/a"]:
            contact = getattr(r.userborrower, "contact_number", "N/A")

        # map your model fields properly
        transactions.append({
            "transaction_id": r.transaction_id or f"T{r.id:06d}",
            "user_name": borrower_name,
            "item_name": item_name,
            "quantity": quantity,
            "contact": contact,
            "date": r.date_borrowed,           # 🟢 replaced 'date' with 'date_borrowed'
            "date_receive": r.date_receive,     # existing field, fine
            "date_returned": r.date_returned,   # existing field, fine
            "status": r.status.capitalize(),
        })

    return render(request, "transaction_history.html", {"transactions": transactions})

def damage_report(request):
    return render(request, 'damage.html')


@login_required
def statistics(request):
    # ---- Filter parameters ----
    start_date = request.GET.get('start')
    end_date = request.GET.get('end')
    item_filter = request.GET.get('items')

    # ---- Base queryset ----
    reservations = Reservation.objects.select_related('item', 'userborrower').all()

    # Apply filters
    if start_date:
        reservations = reservations.filter(date_borrowed__gte=parse_date(start_date))
    if end_date:
        reservations = reservations.filter(date_borrowed__lte=parse_date(end_date))
    if item_filter and item_filter != 'all':
        reservations = reservations.filter(item_id=item_filter)

    # ---- Transactions Table ----
    transactions = [
        {
            "transaction_id": r.transaction_id,
            "item_id": r.item.item_id,
            "item_name": r.item.name,
            "borrower_name": r.userborrower.full_name if r.userborrower else "Unknown",
            "borrowed_at": r.date_borrowed.strftime("%Y-%m-%d"),
            "returned_at": r.date_returned.strftime("%Y-%m-%d") if r.date_returned else "—",
            "status": r.status.capitalize(),
        }
        for r in reservations.order_by("-date_borrowed")
    ]

    # ---- Summary ----
    total_borrowings = reservations.count()

    # Most borrowed item
    most_borrowed_item = (
        reservations.values("item__name")
        .annotate(count=Count("id"))
        .order_by("-count")
        .first()
    )
    most_borrowed_item = most_borrowed_item["item__name"] if most_borrowed_item else "—"

    # Top borrower
    top_borrower = (
        reservations.values("userborrower__full_name")
        .annotate(count=Count("id"))
        .order_by("-count")
        .first()
    )
    top_borrower = top_borrower["userborrower__full_name"] if top_borrower else "—"

    # ---- Chart data ----
    borrowings_by_date = (
        reservations.values("date_borrowed")
        .annotate(count=Count("id"))
        .order_by("date_borrowed")
    )
    chart_labels = [r["date_borrowed"].strftime("%Y-%m-%d") for r in borrowings_by_date]
    chart_counts = [r["count"] for r in borrowings_by_date]

    # ---- All items for filter dropdown ----
    all_items = Item.objects.all()

    context = {
        "items": all_items,
        "transactions": transactions,
        "total_borrowings": total_borrowings,
        "most_borrowed_item": most_borrowed_item,
        "top_borrower": top_borrower,
        "chart_labels": chart_labels,
        "chart_counts": chart_counts,
    }

    return render(request, "statistics.html", context)

@require_GET
@login_required
def statistics_data(request):
    """Return filtered statistics as JSON (for AJAX updates)."""
    from django.utils.dateparse import parse_date

    start_date = request.GET.get("start")
    end_date = request.GET.get("end")
    item_filter = request.GET.get("items")

    qs = Reservation.objects.select_related("item", "userborrower").all()

    if start_date:
        qs = qs.filter(date_borrowed__gte=parse_date(start_date))
    if end_date:
        qs = qs.filter(date_borrowed__lte=parse_date(end_date))
    if item_filter and item_filter != "all":
        qs = qs.filter(item_id=item_filter)

    # ---- Transactions ----
    transactions = [
        {
            "transaction_id": r.transaction_id,
            "item_id": r.item.item_id,
            "item_name": r.item.name,
            "borrower_name": r.userborrower.full_name if r.userborrower else "Unknown",
            "borrowed_at": r.date_borrowed.strftime("%Y-%m-%d"),
            "returned_at": r.date_returned.strftime("%Y-%m-%d") if r.date_returned else "—",
            "status": r.status.capitalize(),
        }
        for r in qs.order_by("-date_borrowed")
    ]

    # ---- Summary ----
    total_borrowings = qs.count()
    most_item = (
        qs.values("item__name")
        .annotate(count=Count("id"))
        .order_by("-count")
        .first()
    )
    most_item = most_item["item__name"] if most_item else "—"

    top_borrower = (
        qs.values("userborrower__full_name")
        .annotate(count=Count("id"))
        .order_by("-count")
        .first()
    )
    top_borrower = top_borrower["userborrower__full_name"] if top_borrower else "—"

    # ---- Chart ----
    borrowings_by_date = (
        qs.values("date_borrowed")
        .annotate(count=Count("id"))
        .order_by("date_borrowed")
    )
    labels = [b["date_borrowed"].strftime("%Y-%m-%d") for b in borrowings_by_date]
    counts = [b["count"] for b in borrowings_by_date]

    data = {
        "labels": labels,
        "counts": counts,
        "total_borrowings": total_borrowings,
        "most_item": most_item,
        "top_borrower": top_borrower,
        "transactions": transactions,
    }
    return JsonResponse(data)

@login_required
def export_excel(request):
    start_date = request.GET.get("start")
    end_date = request.GET.get("end")
    item_filter = request.GET.get("items")

    qs = Reservation.objects.select_related("item", "userborrower").all()
    if start_date:
        qs = qs.filter(date_borrowed__gte=start_date)
    if end_date:
        qs = qs.filter(date_borrowed__lte=end_date)
    if item_filter and item_filter != "all":
        qs = qs.filter(item_id=item_filter)

    data = [
        {
            "Transaction ID": r.transaction_id,
            "Item ID": r.item.item_id,
            "Item Name": r.item.name,
            "Borrower Name": r.userborrower.full_name if r.userborrower else "Unknown",
            "Borrowed At": r.date_borrowed.strftime("%Y-%m-%d"),
            "Returned At": r.date_returned.strftime("%Y-%m-%d") if r.date_returned else "—",
            "Status": r.status.capitalize(),
        }
        for r in qs
    ]

    df = pd.DataFrame(data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Transactions")

    response = HttpResponse(
        output.getvalue(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = 'attachment; filename="transactions_report.xlsx"'
    return response


@login_required
def export_pdf(request):
    start_date = request.GET.get("start")
    end_date = request.GET.get("end")
    item_filter = request.GET.get("items")

    qs = Reservation.objects.select_related("item", "userborrower").all()
    if start_date:
        qs = qs.filter(date_borrowed__gte=start_date)
    if end_date:
        qs = qs.filter(date_borrowed__lte=end_date)
    if item_filter and item_filter != "all":
        qs = qs.filter(item_id=item_filter)

    transactions = [
        {
            "transaction_id": r.transaction_id,
            "item_id": r.item.item_id,
            "item_name": r.item.name,
            "borrower_name": r.userborrower.full_name if r.userborrower else "Unknown",
            "borrowed_at": r.date_borrowed.strftime("%Y-%m-%d"),
            "returned_at": r.date_returned.strftime("%Y-%m-%d") if r.date_returned else "—",
            "status": r.status.capitalize(),
        }
        for r in qs
    ]

    html = render_to_string("pdf_template.html", {"transactions": transactions})
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = 'attachment; filename="transactions_report.pdf"'
    pisa.CreatePDF(io.BytesIO(html.encode("utf-8")), dest=response)
    return response

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
        'date_borrowed': r.date_borrowed.strftime('%Y-%m-%d') if getattr(r, 'date_borrowed', None) else '',
        'message': r.message or '',
        'contact_number': getattr(r.userborrower, 'contact_number', '') or '',

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
@transaction.atomic
def reservation_update_api(request, pk: int):
    r = get_object_or_404(
        Reservation.objects.select_related('item', 'userborrower'),
        pk=pk
    )
    new_status = (request.data or {}).get('status')
    reason_text = (request.data or {}).get('reason', '').strip()

    allowed = {'approved', 'rejected', 'borrowed', 'returned', 'pending'}
    if new_status not in allowed:
        return Response({'status': 'error', 'message': 'Invalid status'}, status=400)

    item = r.item
    if not item:
        return Response({'status': 'error', 'message': 'Item not found'}, status=404)

    prev_status = r.status
    qty = r.quantity or 0

    # ✅ Update timestamps
    if new_status == 'approved':
        r.approved_at = timezone.now()
    elif new_status == 'borrowed':
        r.date_receive = timezone.now()
    elif new_status == 'returned':
        r.date_returned = timezone.now()

    # ✅ Stock management
    if prev_status in ['pending', 'approved'] and new_status == 'rejected':
        item.qty += qty
        item.save(update_fields=['qty'])
    elif new_status == 'returned':
        item.qty += qty
        item.save(update_fields=['qty'])
    elif prev_status == 'rejected' and new_status == 'pending':
        if item.qty >= qty:
            item.qty -= qty
            item.save(update_fields=['qty'])
        else:
            return Response({'status': 'error', 'message': 'Not enough stock'}, status=400)
        
    elif prev_status == 'pending' and new_status == 'approved':
        if item.qty >= qty:
            item.qty -= qty
            item.save(update_fields=['qty'])
        else:
            return Response({'status': 'error', 'message': 'Not enough stock'}, status=400)

    # ✅ Save the reservation
    r.status = new_status
    r.save(update_fields=['status', 'approved_at', 'date_receive', 'date_returned'])

    # =========================
    # ✅ Notifications + Debugging
    # =========================
    try:
        if new_status == 'approved':
            print("DEBUG: generating QR")
            qr_data = f"""
            Transaction ID: {r.transaction_id}
            Borrower: {r.userborrower.full_name}
            Item: {r.item.name}
            Quantity: {r.quantity}
            Date: {getattr(r, 'date_borrowed', '')}
            Contact: {getattr(r, 'contact_number', 'N/A')}
            """
            qr_img = qrcode.make(qr_data)
            buffer = BytesIO()
            qr_img.save(buffer, format='PNG')
            qr_file = ContentFile(buffer.getvalue(), f"qr_{r.transaction_id}.png")

            notif = Notification.objects.create(
                user=r.userborrower,
                title="Reservation Approved ✅",
                message=f"Your reservation for {r.item.name} has been approved!",
                type="approval"
            )
            notif.qr_code.save(f"qr_{r.transaction_id}.png", qr_file)
            notif.save()

            # Optional push notification
            try:
                token_entry = DeviceToken.objects.filter(user=r.userborrower).last()
                if token_entry:
                    message = messaging.Message(
                        notification=messaging.Notification(
                            title="Reservation Approved ✅",
                            body=f"Your QR code for {r.item.name} is ready!"
                        ),
                        token=token_entry.token,
                    )
                    messaging.send(message)
            except Exception as e:
                print("Push notification error:", e)

        elif new_status == 'rejected':
            Notification.objects.create(
                user=r.userborrower,
                title="Reservation Declined ❌",
                message=f"Your reservation for {r.item.name} was declined.",
                reason=reason_text or None,
                type="rejection"
            )

            try:
                token_entry = DeviceToken.objects.filter(user=r.userborrower).last()
                if token_entry:
                    body_text = f"Reason: {reason_text or 'No reason provided.'}"
                    message = messaging.Message(
                        notification=messaging.Notification(
                            title="Reservation Declined ❌",
                            body=body_text[:240]
                        ),
                        token=token_entry.token,
                    )
                    messaging.send(message)
            except Exception as e:
                print("Push notification error:", e)

    except Exception as e:
        import traceback
        print("ERROR DURING APPROVAL:", e)
        traceback.print_exc()
        return Response({'status': 'error', 'message': str(e)}, status=500)

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





def total_reserved_qty_for_range(item, start_date, end_date):
    """
    Calculate total quantity reserved for any overlapping date range.
    Includes reservations that overlap the target range and are pending/approved.
    """
    overlap_filter = Q(date_borrowed__lte=end_date, date_return__gte=start_date)
    agg = (
        Reservation.objects
        .filter(item=item, status__in=['pending', 'approved'])
        .filter(overlap_filter)
        .aggregate(total=Sum('quantity'))
    )
    return agg['total'] or 0


def find_next_available_dates(item, want_qty, start_date, horizon_days=30, limit=3):
    """Suggest next future ranges where the item can fit."""
    suggestions = []
    current = start_date
    while len(suggestions) < limit and current < start_date + timedelta(days=horizon_days):
        reserved = total_reserved_qty_for_range(item, current, current)
        total_stock = item.qty + (
            Reservation.objects.filter(item=item, status__in=['pending', 'approved'])
            .aggregate(total=Sum('quantity')).get('total', 0) or 0
        )
        if reserved + want_qty <= total_stock:
            suggestions.append({"date": current.isoformat()})
        current += timedelta(days=1)
    return suggestions



class CheckAvailabilityView(APIView):
    """
    Check if the item is available for a given date range and quantity.
    Returns 409 if not enough available items.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            item_id = int(request.data.get("item_id"))
            want_qty = int(request.data.get("qty"))
            start_date = date.fromisoformat(request.data.get("start_date"))
            end_date = date.fromisoformat(request.data.get("end_date"))
        except Exception:
            return Response({"detail": "Invalid payload."}, status=400)

        if want_qty < 1:
            return Response({"detail": "Quantity must be >= 1"}, status=400)
        if start_date > end_date:
            return Response({"detail": "Invalid date range."}, status=400)

        try:
            item = Item.objects.get(pk=item_id)
        except Item.DoesNotExist:
            return Response({"detail": "Item not found."}, status=404)
        
        # Block date by admin
        
        blocked_exists = BlockedDate.objects.filter(
            item=item,
            date__range=[start_date, end_date]
        ).exists()

        if blocked_exists:
            return Response(
                {
                    "detail": "This date range is blocked by the administrator.",
                    "blocked": True,
                },
                status=409
            )

        # Calculate total reserved qty overlapping with requested range
        reserved = total_reserved_qty_for_range(item, start_date, end_date)
        available = max(item.qty - reserved, 0)

        if available < want_qty:
            suggestions = find_next_available_dates(item, want_qty, start_date)
            return Response(
                {
                    "detail": "Not enough items available for that range.",
                    "available_qty": available,
                    "suggestions": suggestions,
                },
                status=409,
            )

        return Response({"ok": True, "available_qty": available}, status=200)


class CreateReservationView(APIView):
    """
    Create a new reservation only if the requested quantity and dates are available.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    @transaction.atomic
    def post(self, request):
        try:
            item_id = int(request.data.get("itemID"))
            qty = int(request.data.get("quantity"))
            start_date = date.fromisoformat(request.data.get("start_date"))
            end_date = date.fromisoformat(request.data.get("end_date"))
        except Exception:
            return Response({"detail": "Invalid payload."}, status=400)

        if start_date > end_date:
            return Response({"detail": "Invalid date range."}, status=400)

        user = request.user
        borrower = UserBorrower.objects.get(user=user)
        item = Item.objects.select_for_update().get(pk=item_id)

        # 🔹 Compute real-time availability
        reserved = total_reserved_qty_for_range(item, start_date, end_date)
        available = max(item.qty - reserved, 0)

        if available < qty:
            suggestions = find_next_available_dates(item, qty, start_date)
            return Response(
                {
                    "detail": "Requested range not available.",
                    "available_qty": available,
                    "suggestions": suggestions,
                },
                status=409,
            )

        # 🔹 Create reservation record
        reservation = Reservation.objects.create(
            item=item,
            userborrower=borrower,
            quantity=qty,
            date_borrowed=start_date,
            date_return=end_date,
            message=request.data.get("message", ""),
            priority=request.data.get("priority", "Low"),
            letter_image=request.FILES.get("letter_image"),
            valid_id_image=request.FILES.get("valid_id_image"),
            contact=request.data.get("contact", borrower.contact_number),
            status="pending",
        )
        reservation.transaction_id = f"T{reservation.id:06d}"
        reservation.save(update_fields=["transaction_id"])

        # 🔹 Notify borrower
        create_notification(
            borrower,
            title="Pending Reservation 🕒",
            message=f"Your reservation for {item.name} ({start_date}→{end_date}) is pending approval.",
            notif_type="pending",
        )

        return Response(
            {
                "id": reservation.id,
                "transaction_id": reservation.transaction_id,
                "status": reservation.status,
            },
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
            'date_borrowed': r.date_borrowed.strftime('%Y-%m-%d') if r.date_borrowed else None,
            'date_return': r.date_return.strftime('%Y-%m-%d') if r.date_return else None,
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


# ✅ NEW — Dynamic availability for a single date
@api_view(["GET"])
@permission_classes([AllowAny])
def item_availability(request, item_id):
    """
    Returns availability details for a specific date.
    Example: /api/items/5/availability/?date=2025-10-27
    """
    from datetime import datetime, timedelta, date

    date_str = request.GET.get("date")
    if not date_str:
        return Response({"error": "Missing date parameter"}, status=400)

    try:
        selected_date = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return Response({"error": "Invalid date format"}, status=400)

    try:
        item = Item.objects.get(pk=item_id)
    except Item.DoesNotExist:
        return Response({"error": "Item not found"}, status=404)

    # ✅ Find reservations overlapping this date
    overlapping = Reservation.objects.filter(
        item=item,
        status__in=["pending", "approved"],
        date_borrowed__lte=selected_date,
        date_return__gte=selected_date,
    )

    reserved_qty = sum(r.quantity for r in overlapping)
    total_qty = item.qty or 0
    available_qty = max(total_qty - reserved_qty, 0)

    # ✅ If no overlapping reservations, mark as available
    if not overlapping.exists():
        status = "available"
    else:
        status = "fully_reserved" if available_qty <= 0 else "available"

    # ✅ Find the next available date (up to 30 days ahead)
    suggested_date = None
    if status == "fully_reserved":
        next_day = selected_date + timedelta(days=1)
        for _ in range(30):
            overlapping_next = Reservation.objects.filter(
                item=item,
                status__in=["pending", "approved"],
                date_borrowed__lte=next_day,
                date_return__gte=next_day,
            )
            if not overlapping_next.exists():
                suggested_date = next_day.isoformat()
                break
            next_day += timedelta(days=1)

    return Response({
        "item_id": item.item_id,
        "item_name": item.name,
        "date": selected_date.isoformat(),
        "status": status,
        "total_qty": total_qty,
        "available_qty": available_qty,
        "suggested_date": suggested_date,
    }, status=200)

    
@api_view(["GET"])
@permission_classes([AllowAny])
def item_availability_map(request, item_id):
    """
    Returns a 60-day calendar map of reserved/available dates.
    Marks only dates that overlap with existing reservations as 'fully_reserved'.
    """
    from datetime import date, timedelta

    try:
        item = Item.objects.get(pk=item_id)
    except Item.DoesNotExist:
        return Response({"error": "Item not found"}, status=404)

    reservations = list(
        Reservation.objects.filter(
            item=item,
            status__in=["pending", "approved"]
        ).values("date_borrowed", "date_return", "quantity")
    )

    start = date.today()
    end = start + timedelta(days=60)

    days = {}
    current = start
    while current <= end:
        is_reserved = any(
            res["date_borrowed"] <= current <= res["date_return"]
            for res in reservations
        )

        if is_reserved:
            days[current.isoformat()] = {"status": "fully_reserved"}
        else:
            days[current.isoformat()] = {"status": "available"}

        current += timedelta(days=1)

    return Response({
        "item_id": item.item_id,
        "item_name": item.name,
        "calendar": days
    }, status=200)

@csrf_exempt
def verify_qr(request, mode, code):
    """
    Verifies a QR code scanned from ESP32-CAM.
    The QR content may contain the entire formatted text block, so we extract transaction_id.
    """
    try:
        # Extract only the actual transaction code (e.g., T000001)
        if "T" in code:
            parts = code.split("T")
            code = "T" + parts[-1].split()[0]  # handles formatted text blocks

        reservation = Reservation.objects.get(transaction_id=code.strip())
        data = {
            "item": reservation.item.name if reservation.item else "",
            "borrower": reservation.userborrower.full_name if reservation.userborrower else "",
            "status": reservation.status,
        }
        return JsonResponse(data)
    except Reservation.DoesNotExist:
        return JsonResponse({"error": "QR not recognized"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def update_reservation(request, mode, code):
    """
    Updates the reservation status after QR verification and notifies borrower.
    Also records date & time of receiving (claim).
    """
    try:
        if "T" in code:
            parts = code.split("T")
            code = "T" + parts[-1].split()[0]

        reservation = Reservation.objects.get(transaction_id=code.strip())

        # CLAIM MODE → borrower received the item
        if mode.lower() == "claim":
            reservation.status = "in use"
            reservation.date_receive = timezone.now()  # ✅ record Date & Time Receive

            # Notify borrower
            Notification.objects.create(
                user=reservation.userborrower,
                title="Item Claimed Successfully ✅",
                message=f"Your request for '{reservation.item.name}' has been successfully claimed and is now in use.",
                type="claimed",
            )
            message = f"{reservation.userborrower.full_name} has claimed the item '{reservation.item.name}'."

        # RETURN MODE (optional fallback)
        elif mode.lower() == "return":
            reservation.status = "returned"
            reservation.date_returned = timezone.now()  # ✅ record Date & Time Returned
            message = f"{reservation.userborrower.full_name} has returned the item '{reservation.item.name}'."

        else:
            message = "Invalid mode."

        reservation.save()
        return JsonResponse({"message": message})

    except Reservation.DoesNotExist:
        return JsonResponse({"error": "Reservation not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def submit_feedback(request):
    """
    Handles admin feedback submission after a borrower returns an item.
    Updates borrower rating, feedback record, inventory, and records return date/time.
    """
    try:
        if request.method != "POST":
            return JsonResponse({"error": "Invalid request method"}, status=400)

        transaction_id = request.POST.get("transaction_id")
        comment = request.POST.get("comment", "")
        return_status = request.POST.get("return_status")

        if not transaction_id or not return_status:
            return JsonResponse({"error": "Missing required fields"}, status=400)

        reservation = Reservation.objects.get(transaction_id=transaction_id)
        borrower = reservation.userborrower
        item = reservation.item

        # Save feedback
        Feedback.objects.create(
            reservation=reservation,
            userborrower=borrower,
            comment=comment,
            return_status=return_status,
        )

        notif_message = ""
        notif_title = ""
        notif_type = "returned"

        # Update borrower status logic
        if return_status == "Late Return":
            borrower.late_count += 1
            notif_title = "Late Return Notice ⚠️"
            notif_message = f"You returned '{item.name}' late. Please avoid future delays."
            if borrower.late_count >= 3:
                borrower.borrower_status = "Bad"

        elif return_status == "Not Returned":
            borrower.borrower_status = "Bad"
            notif_title = "Item Not Returned ❌"
            notif_message = f"Your borrowed item '{item.name}' was not returned. Please contact GSO immediately."

        else:
            borrower.borrower_status = "Good"
            notif_title = "Returned On Time ✅"
            notif_message = f"Thank you for returning '{item.name}' on time! Keep it up."

        borrower.save()

        # ✅ Update reservation + record actual return time
        reservation.status = "returned"
        reservation.date_returned = timezone.now()  # ✅ Save Date & Time Returned
        reservation.save()

        # ✅ Restore inventory
        item.qty += reservation.quantity
        item.status = "Available"
        item.save()

        # ✅ Notify borrower in mobile app
        Notification.objects.create(
            user=borrower,
            title=notif_title,
            message=notif_message,
            type=notif_type,
        )

        return JsonResponse({"message": "Feedback submitted and borrower notified successfully."})

    except Reservation.DoesNotExist:
        return JsonResponse({"error": "Reservation not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def monthly_reset(request=None):
    """
    Resets all borrower late counts and restores 'Good' status at the start of each month.
    Can be triggered manually or via a cron job.
    """
    try:
        borrowers = UserBorrower.objects.all()
        for b in borrowers:
            b.late_count = 0
            # Only restore if no damage or missing item flags exist
            if b.borrower_status != "Bad":
                b.borrower_status = "Good"
            b.save()
        return JsonResponse({"message": "Monthly reset completed successfully."})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

def damage_report_list(request):
    reports = DamageReport.objects.select_related('reported_by').order_by('-date_reported')

    report_data = []
    for r in reports:
        report_data.append({
            'user_id': r.reported_by.id,
            'user_name': r.reported_by.full_name,
            'address': r.reported_by.address,
            'image': r.image.url if r.image else 'No image',
            'date': r.date_reported.strftime("%Y-%m-%d %H:%M"),
            'description': r.description,
            'quantity': r.quantity_affected,
            'location': r.location,
            'status': r.status,
        })

    return render(request, 'damage_report.html', {'reports': report_data})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def submit_damage_report(request):
    try:
        user_borrower = UserBorrower.objects.get(user=request.user)
        location = request.data.get('location')
        quantity_affected = request.data.get('quantity_affected')
        description = request.data.get('description')
        image = request.data.get('image')

        if not all([location, quantity_affected, description]):
            return Response({'status': 'error', 'message': 'Missing required fields'}, status=400)

        report = DamageReport.objects.create(
            reported_by=user_borrower,
            location=location,
            quantity_affected=quantity_affected,
            description=description,
            image=image
        )
        return Response({'status': 'success', 'message': 'Damage report submitted successfully', 'id': report.id})
    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=500)


# ITEM CALENDAR BLOCKDATE

@api_view(["GET"])
@permission_classes([AllowAny])
def get_item_calendar(request, item_id):
    """
    Return all reservations and blocked dates for the given item.
    Used by both web dashboard and mobile app.
    """
    try:
        item = Item.objects.get(item_id=item_id)
    except Item.DoesNotExist:
        return Response({"error": "Item not found"}, status=404)

    # Fetch reservations
    reservations = Reservation.objects.filter(item=item)
    blocked = BlockedDate.objects.filter(item=item)

    data = {
        "reservations": [
            {
                "name": r.userborrower.full_name if r.userborrower else "Unknown",
                "date": r.date_borrowed.strftime("%Y-%m-%d"),
                "status": r.status,
            }
            for r in reservations
        ],
        "blocked": [b.date.strftime("%Y-%m-%d") for b in blocked],
    }
    return Response(data, status=200)


# ✅ Unified block/unblock (for admin dashboard)
@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def toggle_block_date(request, item_id):
    """
    Toggle a block date for a specific item.
    When blocked, users on the mobile app CANNOT reserve that date.
    """
    try:
        body = json.loads(request.body or "{}")
        date_str = body.get("date")
        reason = body.get("reason", "Blocked manually")

        if not date_str:
            return Response({"error": "Missing date"}, status=400)

        date = parse_date(date_str)
        if not date:
            return Response({"error": "Invalid date format"}, status=400)

        item = Item.objects.get(item_id=item_id)

        existing = BlockedDate.objects.filter(item=item, date=date).first()
        if existing:
            existing.delete()
            return Response({"status": "unblocked", "date": date_str})

        BlockedDate.objects.create(item=item, date=date, reason=reason)
        return Response({"status": "blocked", "date": date_str, "reason": reason})

    except Item.DoesNotExist:
        return Response({"error": "Item not found"}, status=404)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({"error": str(e)}, status=500)
    
    
@api_view(["POST"])
def cancel_reservations_for_date(request, item_id):
    try:
        date_str = request.data.get("date")
        if not date_str:
            return Response({"error": "Missing date"}, status=400)

        item = Item.objects.get(item_id=item_id)
        count = Reservation.objects.filter(item=item, date_borrowed=date_str).exclude(status="cancelled").update(status="cancelled")

        return Response({"message": f"{count} reservation(s) cancelled for {date_str}."})
    except Exception as e:
        return Response({"error": str(e)}, status=500)