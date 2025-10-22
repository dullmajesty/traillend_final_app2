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
    return render(request, "dashboard.html")


def forgot_password(request):
    return render(request, "forgot_password.html")


def verify_reset_code(request):
    return render(request, "verify_reset_code.html")


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
    return render(request, 'logout.html')


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
    r = get_object_or_404(Reservation, pk=pk)
    new_status = (request.data or {}).get('status')

    # align with model: rejected (not declined)
    allowed = {'approved', 'rejected', 'borrowed', 'returned', 'pending'}
    if new_status not in allowed:
        return Response({'status': 'error', 'message': 'Invalid status'}, status=400)

    if new_status == 'approved' and hasattr(r, 'approved_at'):
        r.approved_at = timezone.now()
    if new_status == 'borrowed' and hasattr(r, 'date_receive'):
        r.date_receive = timezone.now()
    if new_status == 'returned' and hasattr(r, 'date_returned'):
        r.date_returned = timezone.now()

    r.status = new_status
    r.save()
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
                {"detail": "Requested date is not available.",
                 "blocked": [reserve_date.isoformat()],
                 "suggestions": suggestions},
                status=409
            )

        # ✅ files & contact
        letter_file = request.FILES.get("letter_image")
        id_file = request.FILES.get("valid_id_image")
        contact = data.get("contact") or borrower.contact_number or "N/A"

        r = Reservation.objects.create(
            item=item,
            userborrower=borrower,
            quantity=qty,
            date=reserve_date,
            message=message,
            priority=priority,
            letter_image=letter_file,          # ImageField from request.FILES
            valid_id_image=id_file,            # "
            contact=contact,
            status='pending',
        )
        r.transaction_id = f"T{r.id:06d}"
        r.save(update_fields=["transaction_id"])

        return Response({"id": r.id, "transaction_id": r.transaction_id, "status": r.status}, status=201)


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