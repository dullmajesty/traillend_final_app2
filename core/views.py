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
from django.templatetags.static import static

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

# import your models (Reservation was missing before)
from .models import UserBorrower, Item, Reservation, Feedback, DamageReport, BlockedDate
from django.contrib.auth.hashers import check_password
from django.contrib.auth import update_session_auth_hash

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

from .models import AdminBorrow


#FORGOT PASSWORD
from django.core.mail import send_mail
from django.contrib import messages
from django.shortcuts import render, redirect
from django.conf import settings
import random

#SIGN UP
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.conf import settings

#logout
from django.shortcuts import redirect
from django.contrib.auth import logout as auth_logout

from .models import Notification, DeviceToken
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags



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

    # PIE - Item Category Distribution
    category_data = Item.objects.values("category").annotate(count=Count("item_id"))
    pie_labels = [c["category"] for c in category_data]
    pie_values = [c["count"] for c in category_data]

    # BAR - Monthly Transactions (based on date_borrowed)
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

    # DONUT - Borrowed vs Returned
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

                # Show success message (used by popup)
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
    qs = Reservation.objects.select_related('item', 'userborrower').order_by('-id')

    transactions = []
    for r in qs:
        borrower_name = getattr(r.userborrower, "full_name", "Unknown")
        item_name = getattr(r.item, "name", "Unknown")
        quantity = getattr(r, "quantity", 1)

        # use borrower's contact if reservation contact is blank
        contact = getattr(r, "contact", None)
        if not contact or contact.strip().lower() in ["", "n/a"]:
            contact = getattr(r.userborrower, "contact_number", "N/A")

        transactions.append({
            "transaction_id": r.transaction_id or f"T{r.id:06d}",
            "user_name": borrower_name,
            "item_name": item_name,
            "quantity": quantity,
            "contact": contact,
            "date_borrowed": r.date_borrowed,    
            "date_receive": r.date_receive,
            "date_returned": r.date_returned,
            "status": r.status,
            "created_at": r.created_at,         
            "approved_at": r.approved_at,
        })

    return render(request, "transaction_history.html", {"transactions": transactions})


# Statistics


@login_required
def statistics(request):
    all_items = Item.objects.all()

    context = {
        "items": all_items,
    }
    return render(request, "statistics.html", context)


def statistics_data(request):
    # ===== Filters =====
    start = request.GET.get("start")
    end = request.GET.get("end")
    status_filter = request.GET.get("status", "all")
    category_filter = request.GET.get("category", "all")
    report_type_filter = request.GET.get("report_type", "all")

    reservations = Reservation.objects.select_related("item", "userborrower").all()

    # --- Date filter ---
    if start:
        reservations = reservations.filter(date_borrowed__gte=parse_date(start))
    if end:
        reservations = reservations.filter(date_borrowed__lte=parse_date(end))

    # --- Status filter ---
    if status_filter != "all":
        reservations = reservations.filter(status=status_filter)

    # --- Category filter ---
    if category_filter != "all":
        reservations = reservations.filter(item__category=category_filter)

    # Convert to list we can add damage/loss data into
    results = []

    for r in reservations:
        # Check if the reservation has any damage/loss reports
        report = r.damage_reports.first()

        # Determine report type
        if report:
            report_type = report.report_type.lower()  # "Damage" or "Loss"
        else:
            report_type = "none"

        # Apply the filter (damage/loss only)
        if report_type_filter != "all":
            if report_type_filter == "damage" and report_type != "damage":
                continue
            if report_type_filter == "loss" and report_type != "loss":
                continue

        results.append({
            "item_name": r.item.name,
            "category": r.item.category,
            "borrower_name": r.userborrower.full_name if r.userborrower else "Unknown",
            "borrowed_at": r.date_borrowed.strftime("%Y-%m-%d"),
            "returned_at": r.date_return.strftime("%Y-%m-%d"),
            "report_type": report_type.capitalize(),  # Damage / Loss / None
            "status": r.status,
        })

    return JsonResponse({"transactions": results})


@login_required
def export_excel(request):

    start_date = request.GET.get("start")
    end_date = request.GET.get("end")
    status_filter = request.GET.get("status")
    category_filter = request.GET.get("category")
    report_filter = request.GET.get("report_type")

    qs = Reservation.objects.select_related("item", "userborrower").all()

    # Filters
    if start_date:
        qs = qs.filter(date_borrowed__gte=parse_date(start_date))
    if end_date:
        qs = qs.filter(date_borrowed__lte=parse_date(end_date))
    if status_filter and status_filter != "all":
        qs = qs.filter(status__iexact=status_filter)
    if category_filter and category_filter != "all":
        qs = qs.filter(item__category__iexact=category_filter)

    # Damage/Loss filter
    if report_filter == "damage":
        qs = qs.filter(damage_reports__report_type="Damage")
    elif report_filter == "loss":
        qs = qs.filter(damage_reports__report_type="Loss")

    qs = qs.distinct()

    # Build export data
    data = []
    for r in qs:
        report = r.damage_reports.first()
        report_type = report.report_type if report else "None"

        data.append({
            "Item Name": r.item.name,
            "Category": r.item.category,
            "Borrower": r.userborrower.full_name,
            "Borrowed At": r.date_borrowed.strftime("%Y-%m-%d"),
            "Returned At": r.date_return.strftime("%Y-%m-%d") if r.date_return else "",
            "Report Type": report_type,
            "Status": r.status.capitalize(),
        })

    df = pd.DataFrame(data)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Report")

    response = HttpResponse(
        output.getvalue(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    response["Content-Disposition"] = "attachment; filename=report.xlsx"
    return response


@login_required
def export_pdf(request):
    start_date = request.GET.get("start")
    end_date = request.GET.get("end")
    status_filter = request.GET.get("status")
    category_filter = request.GET.get("category")
    report_filter = request.GET.get("report_type")

    qs = Reservation.objects.select_related("item", "userborrower").all()

    if start_date:
        qs = qs.filter(date_borrowed__gte=parse_date(start_date))
    if end_date:
        qs = qs.filter(date_borrowed__lte=parse_date(end_date))
    if status_filter and status_filter != "all":
        qs = qs.filter(status__iexact=status_filter)
    if category_filter and category_filter != "all":
        qs = qs.filter(item__category__iexact=category_filter)

    if report_filter == "damage":
        qs = qs.filter(damage_reports__report_type="Damage")
    elif report_filter == "loss":
        qs = qs.filter(damage_reports__report_type="Loss")

    qs = qs.distinct()

    transactions = []
    for r in qs:
        report = r.damage_reports.first()
        report_type = report.report_type if report else "None"

        transactions.append({
            "item_name": r.item.name,
            "category": r.item.category,
            "borrower_name": r.userborrower.full_name,
            "borrowed_at": r.date_borrowed.strftime("%Y-%m-%d"),
            "returned_at": r.date_return.strftime("%Y-%m-%d") if r.date_return else "",
            "report_type": report_type,
            "status": r.status.capitalize(),
        })

    # 🔥 Build logo URL
    logo_path = request.build_absolute_uri(static("Barangay Kauswagan Logo.png"))

    html = render_to_string(
        "pdf_template.html",
        {"transactions": transactions, "logo_path": logo_path}
    )

    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = "attachment; filename=report.pdf"

    pisa.CreatePDF(html, dest=response)
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
    API endpoint for registration with HTML email and local dev IP support.
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
            email = data.get("email")


            # Validation
            if not all([username, password, confirm_password, full_name, email]):
                return JsonResponse({"success": False, "message": "Missing required fields"}, status=400)


            if User.objects.filter(username=username).exists():
                return JsonResponse({"success": False, "message": "Username already exists"}, status=400)


            if User.objects.filter(email=email).exists():
                return JsonResponse({"success": False, "message": "Email already registered"}, status=400)


            if password != confirm_password:
                return JsonResponse({"success": False, "message": "Passwords do not match"}, status=400)


            # Create inactive user
            user = User.objects.create_user(
                username=username,
                password=password,
                email=email,
                is_active=False
            )


            UserBorrower.objects.create(
                user=user,
                full_name=full_name,
                contact_number=contact_number,
                address=address
            )


            # Generate verification link (use your local IP for now)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)


            # 🧩 Local development link — works, but user won't see the IP
            verify_url = f"http://172.22.88.165:8000/api/verify-email/{uid}/{token}/"


            # HTML Email Template
            html_message = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8" />
              <meta name="viewport" content="width=device-width, initial-scale=1.0" />
              <title>Verify Your Email - TrailLend</title>
            </head>
            <body style="font-family:'Poppins',Arial,sans-serif; background-color:#f4f6f9; padding:30px;">
              <table align="center" style="max-width:600px; background:#fff; border-radius:12px; overflow:hidden; box-shadow:0 4px 12px rgba(0,0,0,0.1);">
                <tr>
                  <td style="background-color:#1976D2; text-align:center; padding:30px;">
                    <img src="https://i.postimg.cc/pTymgvs2/TRAILLEND-ICON.png" alt="TrailLend Logo" width="80" />
                    <h1 style="color:#fff; margin:10px 0 0;">TrailLend</h1>
                    <p style="color:#cce6ff;">Empowering the Community Together 🌿</p>
                  </td>
                </tr>
                <tr>
                  <td style="padding:30px;">
                    <h2 style="color:#1976D2;">Email Verification Required</h2>
                    <p style="color:#333;">Hi {full_name},</p>
                    <p style="color:#555;">Thank you for registering on <strong>TrailLend</strong>!
                    To activate your account, please verify your email address by clicking the button below:</p>


                    <div style="text-align:center; margin:30px 0;">
                      <a href="{verify_url}"
                         style="background-color:#1976D2; color:#fff; text-decoration:none;
                                padding:14px 28px; border-radius:8px; font-weight:bold; display:inline-block;">
                        Verify My Email
                      </a>
                    </div>


                    <p style="color:#777; font-size:14px;">If you didn’t create this account, please ignore this email.</p>
                    <hr style="border:none; border-top:1px solid #eee; margin:30px 0;">
                    <p style="color:#999; font-size:12px; text-align:center;">
                      © 2025 TrailLend • Barangay General Services Office<br>
                      Please do not reply directly to this message.
                    </p>
                  </td>
                </tr>
              </table>
            </body>
            </html>
            """


            send_mail(
                subject="Verify Your TrailLend Account",
                message="Please verify your TrailLend account.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
                html_message=html_message
            )


            return JsonResponse({
                "success": True,
                "message": "Registration successful! Check your email to verify your account."
            }, status=201)


        except Exception as e:
            import traceback
            traceback.print_exc()
            return JsonResponse({"success": False, "message": str(e)}, status=400)


    return JsonResponse({"success": False, "message": "Invalid request method"}, status=405)




# Verify Email Endpoint
@api_view(["GET"])
@permission_classes([AllowAny])
def verify_email(request, uidb64, token):
    """
    Activates the user's account and hides IP on success.
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)


        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()


            # Deep link to app
            deep_link = "com.traillend.app://verified"


            # Beautiful success page (no visible IP)
            html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Email Verified - TrailLend</title>
              <meta http-equiv="refresh" content="3;url={deep_link}">
              <style>
                body {{
                    font-family: 'Poppins', Arial, sans-serif;
                    background-color: #f4f6f9;
                    text-align: center;
                    padding: 60px;
                }}
                .card {{
                    background: #fff;
                    border-radius: 16px;
                    max-width: 500px;
                    margin: auto;
                    padding: 40px;
                    box-shadow: 0 4px 10px rgba(0,0,0,0.1);
                }}
                .btn {{
                    background-color: #1976D2;
                    color: #fff;
                    text-decoration: none;
                    padding: 12px 24px;
                    border-radius: 8px;
                    display: inline-block;
                    margin-top: 20px;
                    font-weight: bold;
                }}
                .btn:hover {{
                    background-color: #145CA8;
                }}
              </style>
            </head>
            <body>
              <div class="card">
                <img src="https://i.postimg.cc/pTymgvs2/TRAILLEND-ICON.png" width="90" />
                <h1 style="color:#1976D2;">Email Verified!</h1>
                <p style="color:#333;">Your TrailLend account has been successfully verified.</p>
                <p style="color:#555;">You can now log in to your account.</p>
                <a href="{deep_link}" class="btn">Open TrailLend App</a>
              </div>
            </body>
            </html>
            """


            return HttpResponse(html)


        else:
            return JsonResponse({"success": False, "message": "Invalid or expired verification link."}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "message": str(e)}, status=400)



@csrf_exempt
def api_login(request):
    """
    Mobile login API — allows restricted borrowers to login,
    but returns their borrower_status so frontend can show modal.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body or "{}")
            username = data.get("username")
            password = data.get("password")

            if not username or not password:
                return JsonResponse({
                    "success": False,
                    "message": "Username and password required"
                }, status=400)

            user = authenticate(request, username=username, password=password)

            if user is None:
                return JsonResponse({
                    "success": False,
                    "message": "Invalid credentials"
                }, status=401)

            borrower = UserBorrower.objects.get(user=user)

            # ⭐ ALLOW LOGIN FOR RESTRICTED ACCOUNTS
            # DO NOT block login with 403
            # Instead, return borrower_status to app
            refresh = RefreshToken.for_user(user)

            return JsonResponse({
                "success": True,
                "message": "Login successful",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "borrower_status": borrower.borrower_status,   # ⭐ VERY IMPORTANT
                "late_count": borrower.late_count              # ⭐ Add for UI if needed
            }, status=200)

        except Exception as e:
            return JsonResponse({
                "success": False,
                "message": str(e)
            }, status=400)

    return JsonResponse({
        "success": False,
        "message": "Invalid request method"
    }, status=405)



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

    # Update timestamps
    if new_status == 'approved':
        r.approved_at = timezone.now()
    elif new_status == 'borrowed':
        r.date_receive = timezone.now()
    elif new_status == 'returned':
        r.date_returned = timezone.now()

    # Stock management
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

    # Save the reservation
    r.status = new_status
    r.save(update_fields=['status', 'approved_at', 'date_receive', 'date_returned'])

    # =========================
    # Notifications + Debugging
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
                reservation=r,
                title="Reservation Approved",
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
                            title="Reservation Approved",
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
                title="Reservation Declined",
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
                            title="Reservation Declined",
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
        total_capacity = get_total_capacity(item)
        available = max(total_capacity - reserved, 0)


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
    Updates item status automatically to 'Available' or 'Fully Reserved'
    based on real-time overlapping reservations.
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

        # Compute total reserved quantity overlapping this range
        overlapping = Reservation.objects.filter(
            item=item,
            status__in=["pending", "approved", "in use"],
        ).filter(
            Q(date_borrowed__lte=end_date) & Q(date_return__gte=start_date)
        )

        total_reserved = overlapping.aggregate(total=Sum("quantity"))["total"] or 0
        remaining = max(item.qty - total_reserved, 0)

        # Check if enough quantity remains
        if qty > remaining:
            return Response({
                "detail": f"Only {remaining} {item.name}(s) available for the selected date range.",
                "available_qty": remaining,
                "suggestion": "Choose another date or lower the quantity.",
            }, status=409)

        # Create the reservation
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

        # Update item status dynamically
        new_reserved = total_reserved + qty
        item.status = "Fully Reserved" if new_reserved >= item.qty else "Available"
        item.save(update_fields=["status"])

        # Notify borrower
        create_notification(
            borrower,
            title="Pending Reservation",
            message=f"Your reservation for {item.name} ({start_date} → {end_date}) is pending approval.",
            notif_type="pending",
            reservation=reservation
        )

        return Response({
            "id": reservation.id,
            "transaction_id": reservation.transaction_id,
            "status": reservation.status,
            "remaining_qty": item.qty - new_reserved,
            "item_status": item.status
        }, status=201)




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

            #  Get image URL (check if profile_image field exists)
            image_url = borrower.profile_image.url if getattr(borrower, "profile_image", None) else None

            # Return all user borrower data including image
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

    # Handle incorrect request methods
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

            # Update fields
            borrower.full_name = name
            borrower.contact_number = contact_number
            borrower.address = address

            # Handle image upload
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
    """Return list of notifications for the logged-in borrower with reservation + item details."""
    try:
        user = request.user
        borrower = getattr(user, 'userborrower', None)
        if not borrower:
            return Response({'success': True, 'notifications': []}, status=200)

        # Prefetch the linked reservation + item
        notifications = (
            Notification.objects
            .filter(user=borrower)
            .select_related('reservation__item')
            .order_by('-created_at')
        )

        ICONS = {
            "approval": "checkmark-circle-outline",
            "rejection": "close-circle-outline",
            "pending": "time-outline",
            "claimed": "cube-outline",
            "returned": "arrow-undo-outline",
            "cancelled": "close-circle-outline",
            "general": "notifications-outline"
        }

        data = []
        for n in notifications:
            reservation = getattr(n, "reservation", None)
            item = getattr(reservation, "item", None)

            transaction_id = getattr(reservation, "transaction_id", None)
            item_name = getattr(item, "name", None)
            item_image_url = None

            if item and item.image:
                item_image_url = request.build_absolute_uri(item.image.url)
                
            local_time = timezone.localtime(n.created_at)

            data.append({
                "id": n.id,
                "title": n.title,
                "message": n.message,
                "reason": n.reason,
                "type": n.type,
                "icon": ICONS.get(n.type, "notifications-outline"),
                "is_read": n.is_read,
                "created_at": local_time.strftime("%Y-%m-%d %I:%M %p"),
                "qr_code": request.build_absolute_uri(n.qr_code.url) if n.qr_code else None,
                "transaction_id": transaction_id,     # Will now show properly
                "item_name": item_name,               # Will now show properly
                "quantity": getattr(reservation, "quantity", None),
                "image_url": item_image_url,
            })

        return Response({"success": True, "notifications": data}, status=200)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({"success": False, "error": str(e)}, status=500)


def create_notification(borrower, title, message, notif_type='general', qr_file=None, reservation=None):
    """Reusable helper to create both in-app + push notification."""
    notif = Notification.objects.create(
        user=borrower,
        reservation=reservation, 
        title=title,
        message=message,
        type=notif_type
    )

    if qr_file:
        notif.qr_code.save(f"qr_{borrower.user.username}.png", qr_file)

    # Optional push notification
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
        print("Error sending push notification:", e)

    return notif

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_delayed_notification(request):
    """
    Create a new 'delayed' notification for a borrower.
    Expected JSON:
    {
        "user_id": 5,
        "item_name": "Projector",
        "message": "You returned the item late. Please be punctual next time."
    }
    """
    try:
        user_id = request.data.get("user_id")
        message = request.data.get("message", "")
        item_name = request.data.get("item_name", "")

        if not user_id:
            return Response({"success": False, "message": "Missing user_id"}, status=400)

        borrower = UserBorrower.objects.get(id=user_id)

        title = "Delayed Return Notice"
        full_message = message or f"You returned '{item_name}' late. Please avoid future delays."

        # Create the delayed notification
        notif = Notification.objects.create(
            user=borrower,
            title=title,
            message=full_message,
            type="delayed",
        )

        # Optional: push notification
        try:
            token_entry = DeviceToken.objects.filter(user=borrower.user).last()
            if token_entry:
                push_message = messaging.Message(
                    notification=messaging.Notification(
                        title=title,
                        body=full_message[:200],
                    ),
                    token=token_entry.token,
                )
                messaging.send(push_message)
        except Exception as e:
            print("Push notification failed:", e)

        return Response({
            "success": True,
            "message": "Delayed notification sent successfully",
            "notification_id": notif.id
        }, status=201)

    except UserBorrower.DoesNotExist:
        return Response({"success": False, "message": "User not found"}, status=404)
    except Exception as e:
        import traceback; traceback.print_exc()
        return Response({"success": False, "message": str(e)}, status=500)



@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_notification(request, pk):
    """
    Permanently deletes a single notification.
    Only the owner of the notification can delete it.
    """
    try:
        notif = Notification.objects.get(pk=pk, user__user=request.user)
        notif.delete()
        return Response({"success": True, "message": "Notification permanently deleted"}, status=200)
    except Notification.DoesNotExist:
        return Response({"success": False, "message": "Notification not found"}, status=404)



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

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def mark_all_notifications_as_read(request):
    queryset = Notification.objects.filter(user__user=request.user, is_read=False)
    count = queryset.update(is_read=True)
    return Response({
        'success': True,
        'message': f'{count} notifications marked as read'
    })   

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def trigger_due_soon_notifications(request):
    send_due_soon_notifications()
    return Response({'success': True, 'message': 'Return reminders sent successfully'})

def send_due_soon_notifications():
    """
    Creates 'Return Reminder' notifications for items due tomorrow.
    Can be called manually or via a scheduled task.
    """
    today = date.today()
    tomorrow = today + timedelta(days=1)

    due_soon = Reservation.objects.filter(
        date_return=tomorrow,
        status__in=['approved', 'in use']
    ).select_related('userborrower', 'item')

    for r in due_soon:
        borrower = r.userborrower
        item = r.item

        if not borrower or not item:
            continue

        # Avoid duplicates
        already_sent = Notification.objects.filter(
            user=borrower,
            reservation=r,
            type='return_reminder'
        ).exists()
        if already_sent:
            continue

        Notification.objects.create(
            user=borrower,
            reservation=r,
            title="Return Reminder",
            message=f"Your borrowed item '{item.name}' is due for return tomorrow. Please return it on time to avoid penalties.",
            type="return_reminder",
        )
        
        
        
        
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
            'image_url': image_url, 
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

        # Create Cancellation Notification
        create_notification(
            borrower,
            title="Reservation Cancelled",
            message=f"You cancelled your reservation for {reservation.item.name}.",
            notif_type="cancelled"
        )

        return Response({'success': True, 'message': 'Reservation cancelled successfully.'}, status=200)
    except Reservation.DoesNotExist:
        return Response({'success': False, 'message': 'Reservation not found.'}, status=404)


# NEW — Dynamic availability for a single date
@api_view(["GET"])
@permission_classes([AllowAny])
def item_availability(request, item_id):
    from datetime import datetime, timedelta

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

    total_capacity = get_total_capacity(item)

    overlapping = Reservation.objects.filter(
        item=item,
        status__in=["pending", "approved", "in use"],
        date_borrowed__lte=selected_date,
        date_return__gte=selected_date,
    )
    reserved = overlapping.aggregate(total=Sum("quantity"))["total"] or 0
    available_qty = max(total_capacity - reserved, 0)

    status = "fully_reserved" if available_qty == 0 else "available"

    # Next suggested free date (optional)
    suggested_date = None
    if status == "fully_reserved":
        next_day = selected_date + timedelta(days=1)
        for _ in range(30):
            r_next = Reservation.objects.filter(
                item=item,
                status__in=["pending", "approved", "in use"],
                date_borrowed__lte=next_day,
                date_return__gte=next_day,
            ).aggregate(total=Sum("quantity"))["total"] or 0
            if total_capacity - r_next > 0:
                suggested_date = next_day.isoformat()
                break
            next_day += timedelta(days=1)

    return Response({
        "item_id": item.item_id,
        "item_name": item.name,
        "date": selected_date.isoformat(),
        "status": status,
        "available_qty": available_qty,
        "suggested_date": suggested_date,
    }, status=200)

@api_view(["GET"])
@permission_classes([AllowAny])
def item_availability_map(request, item_id):
    from datetime import date, timedelta

    try:
        item = Item.objects.get(pk=item_id)
    except Item.DoesNotExist:
        return Response({"error": "Item not found"}, status=404)

    total_capacity = get_total_capacity(item)

    reservations = list(
        Reservation.objects.filter(
            item=item,
            status__in=["pending", "approved", "in use"]
        ).values("date_borrowed", "date_return", "quantity")
    )

    admin_borrows = list(
        AdminBorrow.objects.filter(item=item).values("date", "return_date", "quantity")
    )

    blocked_dates = set(
        b.date if isinstance(b.date, date) else b.date.date()
        for b in BlockedDate.objects.filter(item=item)
    )

    start = date.today()
    end = start + timedelta(days=60)

    days = {}
    current = start

    while current <= end:

        # BLOCKED DATE
        if current in blocked_dates:
            days[current.isoformat()] = {
                "status": "blocked",
                "reserved_qty": 0,
                "admin_borrowed": 0,
                "available_qty": 0,
            }
            current += timedelta(days=1)
            continue

        # RESERVATIONS
        reserved = 0
        for r in reservations:
            start = r["date_borrowed"]
            end = r["date_return"]

            if isinstance(start, str):
                start = date.fromisoformat(start)
            if isinstance(end, str):
                end = date.fromisoformat(end)

            if start <= current <= end:
                reserved += r["quantity"]

        # ADMIN BORROWS
        admin_used = 0
        for a in admin_borrows:
            start = a["date"]
            end = a["return_date"]

            if isinstance(start, str):
                start = date.fromisoformat(start)
            if isinstance(end, str):
                end = date.fromisoformat(end)

            if start <= current <= end:
                admin_used += a["quantity"]

        # CAP AND COMPUTE
        reserved = min(reserved, total_capacity)
        admin_used = min(admin_used, total_capacity)

        available = max(total_capacity - reserved - admin_used, 0)

        status = "fully_reserved" if available == 0 else "available"

        days[current.isoformat()] = {
            "status": status,
            "reserved_qty": reserved,
            "admin_borrowed": admin_used,
            "available_qty": available,
        }

        current += timedelta(days=1)

    return Response({
        "item_id": item.item_id,
        "item_name": item.name,
        "calendar": days
    }, status=200)




def get_total_capacity(item):
    return item.qty or 0



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
            "quantity": reservation.quantity,
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
            reservation.date_receive = timezone.now()

            # Notify borrower
            Notification.objects.create(
                user=reservation.userborrower,
                reservation=reservation,
                title="Item Claimed Successfully",
                message=f"Your request for '{reservation.item.name}' has been successfully claimed.",
                type="claimed",
            )
            message = f"{reservation.userborrower.full_name} has claimed the item '{reservation.item.name}'."

        # RETURN MODE (optional fallback)
        elif mode.lower() == "return":
            reservation.status = "returned"
            reservation.date_returned = timezone.now()
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

        # Notification defaults
        notif_type = "returned"

        if return_status == "Late Return":
            borrower.late_count += 1

            # ⚠️ EXACTLY 2 LATE RETURNS → WARNING NOTIFICATION
            if borrower.late_count == 2:
                notif_title = "⚠️ Warning: You now have 2 late returns"
                notif_message = (
                    "You now have 2 late return instances.\n"
                    "Once you reach 3, you will be marked as a Bad Borrower and lose access to TrailLend."
                )
                notif_type = "warning"

            # ⛔ 3 LATE RETURNS → BAD BORROWER
            elif borrower.late_count >= 3:
                borrower.borrower_status = "Bad"
                notif_title = "⛔ Account Restricted: Bad Borrower Status"
                notif_message = (
                    "You now have 3 late returns.\n"
                    "Your account is now restricted and you can no longer borrow items."
                )
                notif_type = "restricted"

            # Otherwise just a normal late notification
            else:
                notif_title = "Late Return Notice"
                notif_message = f"You returned '{item.name}' late."
                notif_type = "returned"


        elif return_status == "Not Returned":
            borrower.borrower_status = "Bad"
            borrower.late_count = 3  # auto-max
            notif_title = "⛔ Item Not Returned – Account Restricted"
            notif_message = (
                f"You did not return '{item.name}'. Your account is now restricted.\n"
                "Please contact GSO immediately."
            )
            notif_type = "restricted"

        else:
            # Return on time NEVER decreases late count
            notif_title = "Returned On Time"
            notif_message = f"Thank you for returning '{item.name}' on time!"
            notif_type = "returned"


        borrower.save()

        # Update reservation
        reservation.status = "returned"
        reservation.date_returned = timezone.now()
        reservation.save()

        # Restore inventory
        item.qty += reservation.quantity
        item.status = "Available"
        item.save()

        # 🔥 Notification now includes the reservation FK
        Notification.objects.create(
            user=borrower,
            reservation=reservation,
            title=notif_title,
            message=notif_message,
            type=notif_type,
        )

        return JsonResponse({"message": "Feedback submitted and borrower notified successfully."})

    except Reservation.DoesNotExist:
        return JsonResponse({"error": "Reservation not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

def list_notifications(request):
    user = request.user

    notifications = Notification.objects.filter(user=user).select_related("reservation__item")

    notif_list = []
    for n in notifications:
        notif_list.append({
            "id": n.id,
            "title": n.title,
            "message": n.message,
            "type": n.type,
            "is_read": n.is_read,
            "created_at": n.created_at.strftime("%Y-%m-%d %H:%M:%S"),

            # 🔥 Reservation-based fields
            "transaction_id": n.reservation.transaction_id if n.reservation else None,
            "item_name": n.reservation.item.name if n.reservation else None,
            "quantity": n.reservation.quantity if n.reservation else None,
        })

    return JsonResponse(notif_list, safe=False)


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

def damage_loss_report_list(request):
    reports = DamageReport.objects.select_related('reported_by').order_by('-date_reported')

    report_data = []
    for r in reports:
        local_time = timezone.localtime(r.date_reported)

        report_data.append({
            'user_id': r.reported_by.id,
            'user_name': r.reported_by.full_name,
            'address': r.reported_by.address,
            'type': r.report_type,   # ✅ NEW
            'image': r.image.url if r.image else 'No image',
            'date': local_time.strftime("%Y-%m-%d %I:%M %p"),
            'description': r.description,
            'quantity': r.quantity_affected,
            'location': r.location,
            'status': r.status,
        })

    return render(request, 'damage_report.html', {'reports': report_data})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def submit_damage_loss_report(request):
    """
    Borrower submits a Damage or Loss report for an item currently in use.
    Links to reservation + deducts item qty for Loss reports.
    """
    try:
        borrower = UserBorrower.objects.get(user=request.user)

        transaction_id = request.data.get("reservation_id")
        item_id = request.data.get("item_id")
        report_type = request.data.get("report_type")
        location = request.data.get("location")
        quantity_affected = int(request.data.get("quantity_affected"))
        description = request.data.get("description")
        image = request.data.get("image")

        # Validate
        if not all([transaction_id, item_id, report_type, location, description]):
            return Response({"success": False, "message": "Missing required fields"}, status=400)

        reservation = Reservation.objects.get(id=transaction_id, userborrower=borrower)
        item = Item.objects.get(item_id=item_id)

        # Create the report
        report = DamageReport.objects.create(
            reported_by=borrower,
            report_type=report_type,
            location=location,
            quantity_affected=quantity_affected,
            description=description,
            image=image,
            item=item,                # ✔ Save item
            reservation=reservation,  # ✔ Save reservation
        )


        # -------------------------
        # AUTO DEDUCT FOR LOSS ONLY
        # -------------------------
        if report_type.lower() == "loss":
            if item.qty >= quantity_affected:
                item.qty -= quantity_affected
            else:
                item.qty = 0     # never negative
            item.save()

        return Response({
            "success": True,
            "message": f"{report_type} report submitted successfully!",
            "report_id": report.id
        })

    except Reservation.DoesNotExist:
        return Response({"success": False, "message": "Reservation not found"}, status=404)

    except Item.DoesNotExist:
        return Response({"success": False, "message": "Item not found"}, status=404)

    except Exception as e:
        return Response({"success": False, "message": str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def get_in_use_items(request):
    """Return all items currently in-use for the logged-in borrower."""
    try:
        # SAFER lookup to avoid DoesNotExist crashes
        borrower = UserBorrower.objects.filter(user=request.user).first()
        
        if not borrower:
            return Response({"success": True, "items": []}, status=200)

        # FIX: Case-insensitive matching so database inconsistencies don't break API
        reservations = (
            Reservation.objects
            .filter(userborrower=borrower, status__iexact='in use')
            .select_related('item')
            .order_by('-date_borrowed')
        )

        data = []
        for r in reservations:
            data.append({
                "reservation_id": r.id,
                "transaction_code": r.transaction_id,
                "item_id": r.item.item_id,
                "item_name": r.item.name,
                "quantity": r.quantity,
                "image": request.build_absolute_uri(r.item.image.url) if r.item.image else None,
                "date_borrowed": r.date_borrowed.strftime("%Y-%m-%d"),
                "date_return": r.date_return.strftime("%Y-%m-%d") if r.date_return else None,
            })

        return Response({"success": True, "items": data}, status=200)

    except Exception as e:
        return Response({"success": False, "error": str(e)}, status=500)



# ITEM CALENDAR BLOCKDATE

@api_view(["GET"])
@permission_classes([AllowAny])
def get_item_calendar(request, item_id):
    """
    Return all reservations, blocked dates, and admin borrow data for the given item.
    Includes reservation info grouped by date for frontend rendering.
    """
    try:
        item = Item.objects.get(item_id=item_id)
    except Item.DoesNotExist:
        return Response({"error": "Item not found"}, status=404)

    # Fetch reservations
    reservations = Reservation.objects.filter(
        item=item
    ).exclude(status__in=["cancelled", "rejected"])

    # Fetch blocked dates
    blocked = BlockedDate.objects.filter(item=item)

    # Fetch admin borrows
    admin_borrows = AdminBorrow.objects.filter(item=item)

    # --- GROUP RESERVATIONS BY DATE ---
    reservations_by_date = {}
    for r in reservations:
        if not r.date_borrowed or not r.date_return:
            continue

        current = r.date_borrowed
        while current <= r.date_return:
            key = current.strftime("%Y-%m-%d")

            if key not in reservations_by_date:
                reservations_by_date[key] = []

            reservations_by_date[key].append({
                "name": r.userborrower.full_name if r.userborrower else "Unknown",
                "date_borrowed": r.date_borrowed.strftime("%Y-%m-%d"),
                "date_return": r.date_return.strftime("%Y-%m-%d"),
                "quantity": r.quantity,
                "status": r.status.capitalize(),
            })

            current += timedelta(days=1)

    # --- GROUP ADMIN BORROWS BY DATE ---
    admin_by_date = {}
    for ab in admin_borrows:
        current = ab.date
        while current <= ab.return_date:
            key = current.strftime("%Y-%m-%d")

            if key not in admin_by_date:
                admin_by_date[key] = []

            admin_by_date[key].append({
                "quantity": ab.quantity,
                "start": ab.date.strftime("%Y-%m-%d"),
                "end": ab.return_date.strftime("%Y-%m-%d"),
            })

            current += timedelta(days=1)

    # --- FORMAT OUTPUT ---
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

        "reservations_by_date": reservations_by_date,

        # NEW: Admin borrow grouped by date
        "admin_borrow": admin_by_date,
    }

    return Response(data, status=200)



# Unified block/unblock (for admin dashboard)
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
    
    


#  Cancel Reservation, qty increase and Notification
@api_view(["POST"])
def cancel_reservations_for_date(request, item_id):
    """
    Cancels all active reservations for a given date and item.
    Restores reserved quantities to the item stock.
    Sends notifications to affected borrowers.
    """
    try:
        date_str = request.data.get("date")
        if not date_str:
            return Response({"error": "Missing date"}, status=400)

        date = parse_date(date_str)
        if not date:
            return Response({"error": "Invalid date format"}, status=400)

        # Get the item
        item = Item.objects.get(item_id=item_id)

        # Find reservations overlapping the selected date
        reservations = Reservation.objects.filter(
            item=item,
            date_borrowed__lte=date,
            date_return__gte=date
        ).exclude(status="cancelled")

        if not reservations.exists():
            return Response({"message": "No active reservations found for this date."}, status=200)

        total_restored = 0
        cancelled_count = 0

        for r in reservations:
            borrower = r.userborrower
            total_restored += r.quantity or 0
            r.status = "cancelled"
            r.save(update_fields=["status"])
            cancelled_count += 1

            #  Send a notification to each affected borrower
            if borrower:
                create_notification(
                    borrower,
                    title="Reservation Cancelled by Admin ",
                    message=f"Your reservation for {r.item.name} on {r.date_borrowed.strftime('%Y-%m-%d')} has been cancelled by the admin.",
                    notif_type="cancelled",
                    reservation=r
                )

        # ✅ Update item qty
        if total_restored > 0:
            item.qty = item.qty + total_restored
            item.save(update_fields=["qty"])

        return Response({
            "message": f"{cancelled_count} reservation(s) cancelled for {date_str}.",
            "restored_qty": total_restored,
            "new_item_qty": item.qty
        }, status=200)

    except Item.DoesNotExist:
        return Response({"error": "Item not found"}, status=404)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({"error": str(e)}, status=500)

    
    
@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        user = request.user

        # Validate current password
        if not check_password(current_password, user.password):
            messages.error(request, "Current password is incorrect.")
            return redirect('change_password')

        # Validate new passwords match
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect('change_password')

        # Validate password length (optional)
        if len(new_password) < 8:
            messages.error(request, "New password must be at least 8 characters long.")
            return redirect('change_password')

        # Save new password
        user.set_password(new_password)
        user.save()

        # Keep user logged in after password change
        update_session_auth_hash(request, user)

        messages.success(request, "Password updated successfully!")
        return redirect('change_password')

    return render(request, 'change_password.html')

#NEW
@csrf_exempt
def forgot_password(request):
    show_code_container = False
    email_value = ""  # Store email to keep it in the input

    if request.method == 'POST':
        # === SEND RESET CODE ===
        if 'send_code' in request.POST:
            email = request.POST.get('email')
            email_value = email

            try:
                user = User.objects.get(email=email)
                code = random.randint(100000, 999999)
                request.session['reset_email'] = email
                request.session['reset_code'] = str(code)

                # Build formal HTML email
                subject = "🔐 TrailLend Password Reset Code"
                from_email = settings.DEFAULT_FROM_EMAIL
                to = [email]

                html_content = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                  <meta charset="UTF-8" />
                  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                  <title>Password Reset - TrailLend</title>
                </head>
                <body style="margin:0; padding:0; background-color:#f4f6f9; font-family:'Poppins',Arial,sans-serif;">
                  <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" 
                         style="max-width:600px; background-color:#ffffff; border-radius:10px; overflow:hidden; 
                                box-shadow:0 4px 10px rgba(0,0,0,0.05); margin-top:40px;">
                    <tr>
                      <td style="background-color:#1976D2; text-align:center; padding:30px;">
                        <img src="https://i.ibb.co/T2Hyfdd/TRAILLEND-ICON.png" alt="TrailLend Logo" width="80" style="margin-bottom:10px;" />
                        <h1 style="color:#fff; font-size:22px; margin:0;">TrailLend</h1>
                        <p style="color:#cce6ff; font-size:13px; margin:4px 0 0;">Empowering the Community Together 🌿</p>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:30px;">
                        <h2 style="color:#1976D2; font-size:20px; margin-top:0;">Password Reset Request</h2>
                        <p style="color:#333; font-size:15px;">Hello,</p>
                        <p style="color:#333; font-size:15px;">We received a request to reset your TrailLend account password. 
                        Please use the verification code below to continue:</p>

                        <div style="text-align:center; margin:30px 0;">
                          <span style="display:inline-block; background:#1976D2; color:#fff; font-size:28px; 
                                       letter-spacing:5px; padding:15px 25px; border-radius:8px; font-weight:bold;">
                            {code}
                          </span>
                        </div>

                        <p style="color:#555; font-size:14px;">Enter this code in the TrailLend app to verify your identity. 
                        This code will expire soon for security reasons.</p>

                        <p style="color:#555; font-size:14px;">If you did not request a password reset, please ignore this email. 
                        Your account remains secure.</p>

                        <hr style="border:none; border-top:1px solid #eee; margin:30px 0;" />

                        <p style="color:#999; font-size:12px; text-align:center;">
                          This email was sent by <strong>TrailLend</strong> • Barangay General Services Office<br/>
                          Please do not reply directly to this message.
                        </p>
                      </td>
                    </tr>
                  </table>
                </body>
                </html>
                """

                text_content = strip_tags(html_content)

                email_message = EmailMultiAlternatives(subject, text_content, from_email, to)
                email_message.attach_alternative(html_content, "text/html")
                email_message.send()

                messages.success(request, "A reset code has been sent to your email. Please check your inbox.")
                show_code_container = True

            except User.DoesNotExist:
                messages.error(request, "This email doesn't exist.")

        # === VERIFY CODE ===
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

        # === RESEND CODE ===
        elif 'resend_code' in request.POST:
            email = request.session.get('reset_email')
            email_value = email

            if email:
                code = random.randint(100000, 999999)
                request.session['reset_code'] = str(code)

                # Reuse same HTML layout for the resend email
                subject = "🔐 TrailLend Password Reset Code (Resent)"
                from_email = settings.DEFAULT_FROM_EMAIL
                to = [email]

                html_content = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head><meta charset="UTF-8" /></head>
                <body style="font-family:'Poppins',Arial,sans-serif; background-color:#f4f6f9; padding:30px;">
                  <table align="center" style="max-width:600px; background:#fff; border-radius:10px; padding:30px;">
                    <tr><td style="text-align:center;">
                      <img src="https://i.ibb.co/T2Hyfdd/TRAILLEND-ICON.png" width="70" alt="TrailLend" />
                      <h2 style="color:#1976D2;">TrailLend Password Reset (Resent)</h2>
                      <p style="color:#333;">Here is your new reset code:</p>
                      <div style="margin:20px 0;">
                        <span style="display:inline-block; background:#1976D2; color:#fff; font-size:26px; 
                                     letter-spacing:4px; padding:12px 22px; border-radius:8px; font-weight:bold;">
                          {code}
                        </span>
                      </div>
                      <p style="color:#555;">Enter this code in the TrailLend app to verify your identity.</p>
                      <p style="color:#999; font-size:12px;">If you didn’t request this, you can safely ignore this email.</p>
                    </td></tr>
                  </table>
                </body>
                </html>
                """

                text_content = strip_tags(html_content)

                email_message = EmailMultiAlternatives(subject, text_content, from_email, to)
                email_message.attach_alternative(html_content, "text/html")
                email_message.send()

                messages.success(request, "A new code has been sent to your email.")
                show_code_container = True
            else:
                messages.error(request, "No email session found. Please enter your email again.")

    # === RENDER TEMPLATE ===
    return render(request, "forgot_password.html", {
        'show_code_container': show_code_container,
        'email': email_value or request.session.get('reset_email', '')
    })


@csrf_exempt
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

                # === Send confirmation email ===
                subject = "✅ Your TrailLend Password Has Been Changed"
                from_email = settings.DEFAULT_FROM_EMAIL
                to = [email]

                html_content = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                  <meta charset="UTF-8" />
                  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                  <title>Password Changed - TrailLend</title>
                </head>
                <body style="margin:0; padding:0; background-color:#f4f6f9; font-family:'Poppins',Arial,sans-serif;">
                  <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" 
                         style="max-width:600px; background-color:#ffffff; border-radius:10px; overflow:hidden; 
                                box-shadow:0 4px 10px rgba(0,0,0,0.05); margin-top:40px;">
                    <tr>
                      <td style="background-color:#1976D2; text-align:center; padding:30px;">
                        <img src="https://i.ibb.co/T2Hyfdd/TRAILLEND-ICON.png" alt="TrailLend Logo" width="80" style="margin-bottom:10px;" />
                        <h1 style="color:#fff; font-size:22px; margin:0;">TrailLend</h1>
                        <p style="color:#cce6ff; font-size:13px; margin:4px 0 0;">Empowering the Community Together 🌿</p>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:30px;">
                        <h2 style="color:#1976D2; font-size:20px; margin-top:0;">Password Changed Successfully</h2>
                        <p style="color:#333; font-size:15px;">Hello {user.first_name or user.username},</p>
                        <p style="color:#333; font-size:15px;">
                          This is a confirmation that your password for your TrailLend account 
                          (<strong>{email}</strong>) has been successfully changed.
                        </p>

                        <p style="color:#555; font-size:14px; margin-top:20px;">
                          If you did not make this change, please contact your Barangay General Services Office 
                          immediately to secure your account.
                        </p>

                        <div style="text-align:center; margin:30px 0;">
                          <a href="https://traillend.com/login" 
                             style="display:inline-block; background:#1976D2; color:#fff; 
                                    padding:12px 25px; border-radius:6px; font-weight:bold; text-decoration:none;">
                            Go to TrailLend
                          </a>
                        </div>

                        <hr style="border:none; border-top:1px solid #eee; margin:30px 0;" />

                        <p style="color:#999; font-size:12px; text-align:center;">
                          This email was sent by <strong>TrailLend</strong> • Barangay General Services Office<br/>
                          Please do not reply directly to this message.
                        </p>
                      </td>
                    </tr>
                  </table>
                </body>
                </html>
                """

                text_content = strip_tags(html_content)
                email_message = EmailMultiAlternatives(subject, text_content, from_email, to)
                email_message.attach_alternative(html_content, "text/html")
                email_message.send()

                # Show success message on UI
                messages.success(request, "Your password has been successfully changed.")
                return render(request, "verify_reset_code.html")

            except User.DoesNotExist:
                messages.error(request, "User not found. Please try again.")

    return render(request, "verify_reset_code.html", {"email": email})


@csrf_exempt
def me_borrower(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "Unauthorized"}, status=401)

    try:
        borrower = UserBorrower.objects.get(user=request.user)
        return JsonResponse({
            "user_id": borrower.id,
            "full_name": borrower.full_name,
            "contact_number": borrower.contact_number,
            "address": borrower.address,
            "late_count": borrower.late_count,
            "borrower_status": borrower.borrower_status,
        })
    except UserBorrower.DoesNotExist:
        return JsonResponse({"error": "Borrower profile not found"}, status=404)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def borrower_late_history(request):
    user = request.user
    try:
        borrower = user.userborrower
    except:
        return JsonResponse({"error": "Borrower not found"}, status=404)

    # Get all late returns
    late_feedback = Feedback.objects.filter(
        userborrower=borrower,
        return_status="Late"
    ).select_related("reservation__item")

    history = []
    for fb in late_feedback:
        reservation = fb.reservation
        item = reservation.item if reservation else None

        history.append({
            "reservation_id": reservation.id if reservation else None,
            "item_name": item.name if item else "Unknown Item",
            "date_borrowed": str(reservation.date_borrowed) if reservation else None,
            "date_return": str(reservation.date_return) if reservation else None,
            "feedback_date": fb.created_at.strftime("%Y-%m-%d %H:%M"),
        })

    data = {
        "full_name": borrower.full_name,
        "late_count": borrower.late_count,
        "borrower_status": borrower.borrower_status,
        "late_history": history,
    }

    return JsonResponse(data, safe=False)


def total_admin_borrow_for_date(item, target_date):
    qs = AdminBorrow.objects.filter(
        item=item,
        date__lte=target_date,
        return_date__gte=target_date
    ).aggregate(total=Sum("quantity"))
    return qs["total"] or 0


def total_reservation_qty_for_date(item, target_date):
    qs = Reservation.objects.filter(
        item=item,
        status__in=["pending", "approved", "in use"],
        date_borrowed__lte=target_date,
        date_return__gte=target_date,
    ).aggregate(total=Sum("quantity"))
    return qs["total"] or 0

def compute_daily_availability(item, target_date):
    total = item.qty
    reserved = total_reservation_qty_for_date(item, target_date)
    admin_used = total_admin_borrow_for_date(item, target_date)

    available = max(total - reserved - admin_used, 0)

    return {
        "total": total,
        "reserved": reserved,
        "admin_borrowed": admin_used,
        "available": available
    }

@api_view(["POST"])
@permission_classes([AllowAny])
def create_admin_borrow(request, item_id):
    try:
        item = Item.objects.get(item_id=item_id)

        start_date = parse_date(request.data.get("start_date"))
        return_date = parse_date(request.data.get("return_date"))
        qty = int(request.data.get("quantity"))

        if not start_date or not return_date or qty < 1:
            return Response({"error": "Invalid input"}, status=400)

        if return_date < start_date:
            return Response({"error": "Return date cannot be before start date"}, status=400)

        # Check availability for entire date range
        current = start_date
        while current <= return_date:
            avail = compute_daily_availability(item, current)
            if qty > avail["available"]:
                return Response({
                    "error": "Not enough availability",
                    "date": current.isoformat(),
                    "available": avail["available"]
                }, status=409)
            current += timedelta(days=1)

        # Passed → Save
        ab = AdminBorrow.objects.create(
            item=item,
            date=start_date,
            return_date=return_date,
            quantity=qty
        )

        return Response({
            "success": True,
            "id": ab.id,
            "message": "Admin borrow saved"
        }, status=201)

    except Item.DoesNotExist:
        return Response({"error": "Item not found"}, status=404)


@api_view(["PUT"])
@permission_classes([AllowAny])
def update_admin_borrow(request, pk):
    try:
        ab = AdminBorrow.objects.get(pk=pk)
        item = ab.item

        new_qty = int(request.data.get("quantity"))
        new_return = parse_date(request.data.get("return_date"))

        if new_qty < 1 or new_return < ab.date:
            return Response({"error": "Invalid input"}, status=400)

        # Validate entire new range
        current = ab.date
        while current <= new_return:
            avail = compute_daily_availability(item, current)
            # remove the old quantity first
            avail["available"] += ab.quantity

            if new_qty > avail["available"]:
                return Response({
                    "error": "Not enough availability",
                    "date": current.isoformat(),
                    "available": avail["available"]
                }, status=409)
            current += timedelta(days=1)

        ab.quantity = new_qty
        ab.return_date = new_return
        ab.save()

        return Response({"success": True})

    except AdminBorrow.DoesNotExist:
        return Response({"error": "Not found"}, status=404)

@api_view(["DELETE"])
@permission_classes([AllowAny])
def delete_admin_borrow(request, pk):
    try:
        ab = AdminBorrow.objects.get(pk=pk)
        ab.delete()
        return Response({"success": True})
    except AdminBorrow.DoesNotExist:
        return Response({"error": "Not found"}, status=404)
