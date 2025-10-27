from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    CheckAvailabilityView, CreateReservationView,
    forgot_password, verify_reset_code  # ✅ make sure these are imported
)
from . import views

urlpatterns = [
    # Web page login
    path("login/", views.admin_login, name="login"),

    # Admin web views
    path("dashboard/", views.dashboard, name="dashboard"),
    
    # ✅ Forgot password + reset code
    path("forgot_password/", views.forgot_password, name="forgot_password"),
    path("verify_reset_code/", views.verify_reset_code, name="verify_reset_code"),


    # Inventory & others
    path("inventory/", views.inventory, name="inventory"),
    path("inventory/create/", views.inventory_createitem, name="inventory-createitem"),
    path("inventory/detail/<int:item_id>/", views.inventory_detail, name="inventory_detail"),
    path("inventory/edit/<int:item_id>/", views.inventory_edit, name="inventory_edit"),
    path("inventory/delete/<int:item_id>/", views.inventory_delete, name="inventory_delete"),

    path("verification/", views.verification, name="verification"),
    path("transaction_history/", views.transaction_log, name="transaction_log"),
    path("damage/", views.damage_report, name="damage_report"),
    path("statistics/", views.statistics, name="statistics"),
    path("change-password/", views.change_pass, name="change_pass"),
    path("list_of_users/", views.list_of_users, name="list_of_users"),
    path("logout/", views.logout, name="logout"),

    # API endpoints
    path("token/login/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    path("api/register/", views.api_register),
    path("api/login/", views.api_login),
    path("api/inventory_list/", views.api_inventory_list),
    path("api/inventory_detail/<int:id>/", views.api_inventory_detail),
    path("api/reservations/check/", CheckAvailabilityView.as_view()),
    path("api/create_reservation/", CreateReservationView.as_view()),
    path("api/items/<int:item_id>/availability/", views.item_availability, name="item-availability"),
    path("api/items/<int:item_id>/availability-map/", views.item_availability_map, name="item-availability-map"),

    path('api/pending-requests/', views.pending_requests_api, name='pending_requests_api'),
    path("api/reservation_detail/<int:pk>/", views.reservation_detail_api, name="reservation_detail_api"),
    path("api/reservation_update/<int:pk>/", views.reservation_update_api, name="reservation_update_api"),
    path("api/user_profile/", views.user_profile, name="api-user-profile"),
    path("api/update_profile/", views.update_profile, name="api-update-profile"),

    path('api/save_token/', views.save_device_token, name='save_device_token'),
    path('api/notifications/', views.get_user_notifications, name='get_user_notifications'),
    path('api/notifications/<int:pk>/read/', views.mark_notification_as_read, name='mark_notification_as_read'),
    #NEW
    path('api/user_reservations/', views.user_reservations, name='user_reservations'),
    path('api/reservations/<int:pk>/cancel/', views.cancel_reservation, name='cancel_reservation'),


]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
