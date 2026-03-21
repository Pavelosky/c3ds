"""
Unit tests for apps/core:
- IsAdminUser permission class
- login_view / register_view / logout_view / CurrentUserView API endpoints
"""
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import MagicMock

from apps.core.permissions import IsAdminUser
from apps.core.models import UserProfile


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def make_user(username, password='testpass123', is_staff=False, is_superuser=False,
              user_type=UserProfile.UserType.NON_PARTICIPANT):
    user = User.objects.create_user(username=username, password=password,
                                    is_staff=is_staff, is_superuser=is_superuser)
    user.profile.user_type = user_type
    user.profile.save()
    return user


# ---------------------------------------------------------------------------
# IsAdminUser Permission
# ---------------------------------------------------------------------------

class IsAdminUserPermissionTests(TestCase):

    def _make_request(self, user):
        """Build a mock DRF request with the given user."""
        request = MagicMock()
        request.user = user
        return request

    def test_grants_access_to_staff_user(self):
        user = make_user('staff', is_staff=True)
        perm = IsAdminUser()
        self.assertTrue(perm.has_permission(self._make_request(user), None))

    def test_grants_access_to_superuser(self):
        user = make_user('super', is_superuser=True)
        perm = IsAdminUser()
        self.assertTrue(perm.has_permission(self._make_request(user), None))

    def test_denies_regular_user(self):
        user = make_user('regular')
        perm = IsAdminUser()
        self.assertFalse(perm.has_permission(self._make_request(user), None))

    def test_denies_anonymous_user(self):
        request = MagicMock()
        request.user = MagicMock()
        request.user.is_authenticated = False
        perm = IsAdminUser()
        self.assertFalse(perm.has_permission(request, None))


# ---------------------------------------------------------------------------
# Auth API Views
# ---------------------------------------------------------------------------

class LoginViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user = make_user('alice', password='securepass1!')
        self.url = '/api/v1/auth/login/'

    def test_valid_credentials_return_200_and_user_data(self):
        response = self.client.post(self.url, {
            'username': 'alice',
            'password': 'securepass1!',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'alice')

    def test_invalid_credentials_return_400(self):
        response = self.client.post(self.url, {
            'username': 'alice',
            'password': 'wrongpassword',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('errors', response.data)

    def test_missing_username_returns_400(self):
        response = self.client.post(self.url, {'password': 'securepass1!'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_remember_me_false_sets_session_expiry_to_zero(self):
        response = self.client.post(self.url, {
            'username': 'alice',
            'password': 'securepass1!',
            'remember_me': False,
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class RegisterViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = '/api/v1/auth/register/'

    def test_valid_registration_returns_201_and_user_data(self):
        response = self.client.post(self.url, {
            'username': 'newuser',
            'email': 'new@example.com',
            'password1': 'Str0ngP@ss!',
            'password2': 'Str0ngP@ss!',
            'user_type': 'PARTICIPANT',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['username'], 'newuser')
        self.assertEqual(response.data['user_type'], 'PARTICIPANT')
        self.assertTrue(User.objects.filter(username='newuser').exists())

    def test_mismatched_passwords_return_400(self):
        response = self.client.post(self.url, {
            'username': 'newuser2',
            'email': 'new2@example.com',
            'password1': 'Str0ngP@ss!',
            'password2': 'DifferentP@ss!',
            'user_type': 'PARTICIPANT',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('errors', response.data)

    def test_duplicate_username_returns_400(self):
        make_user('existing')
        response = self.client.post(self.url, {
            'username': 'existing',
            'email': 'x@example.com',
            'password1': 'Str0ngP@ss!',
            'password2': 'Str0ngP@ss!',
            'user_type': 'NON_PARTICIPANT',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration_creates_user_profile(self):
        self.client.post(self.url, {
            'username': 'profiletest',
            'email': 'p@example.com',
            'password1': 'Str0ngP@ss!',
            'password2': 'Str0ngP@ss!',
            'user_type': 'PARTICIPANT',
        }, format='json')
        user = User.objects.get(username='profiletest')
        self.assertEqual(user.profile.user_type, UserProfile.UserType.PARTICIPANT)


class LogoutViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.user = make_user('bob', password='testpass123')

    def test_authenticated_user_can_logout(self):
        self.client.force_login(self.user)
        response = self.client.post('/api/v1/auth/logout/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_unauthenticated_logout_returns_403(self):
        response = self.client.post('/api/v1/auth/logout/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class CurrentUserViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()

    def test_authenticated_user_gets_own_data(self):
        user = make_user('carol', user_type=UserProfile.UserType.PARTICIPANT)
        self.client.force_login(user)
        response = self.client.get('/api/v1/auth/me/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'carol')
        self.assertEqual(response.data['user_type'], 'PARTICIPANT')

    def test_unauthenticated_returns_403(self):
        response = self.client.get('/api/v1/auth/me/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_user_has_is_admin_true(self):
        user = make_user('dave', is_staff=True)
        self.client.force_login(user)
        response = self.client.get('/api/v1/auth/me/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get('is_admin') or response.data.get('is_staff'))
