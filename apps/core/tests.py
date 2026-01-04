from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from .models import UserProfile


class UserRegistrationTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.register_url = reverse('register')

    def test_registration_page_loads(self):
        """Test that registration page loads successfully"""
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'C3DS Registration')

    def test_user_registration_participant(self):
        """Test successful registration as System Participant"""
        response = self.client.post(self.register_url, {
            'username': 'testparticipant',
            'email': 'participant@test.com',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!',
            'user_type': UserProfile.UserType.PARTICIPANT
        })

        # Should redirect after successful registration
        self.assertEqual(response.status_code, 302)

        # User should be created
        user = User.objects.get(username='testparticipant')
        self.assertEqual(user.email, 'participant@test.com')

        # UserProfile should be created with correct type
        self.assertEqual(user.profile.user_type, UserProfile.UserType.PARTICIPANT)

    def test_user_registration_non_participant(self):
        """Test successful registration as Non-Participant"""
        response = self.client.post(self.register_url, {
            'username': 'testviewer',
            'email': 'viewer@test.com',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!',
            'user_type': UserProfile.UserType.NON_PARTICIPANT
        })

        self.assertEqual(response.status_code, 302)
        user = User.objects.get(username='testviewer')
        self.assertEqual(user.profile.user_type, UserProfile.UserType.NON_PARTICIPANT)

    def test_user_auto_login_after_registration(self):
        """Test that user is automatically logged in after registration"""
        response = self.client.post(self.register_url, {
            'username': 'autologintest',
            'email': 'autologin@test.com',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!',
            'user_type': UserProfile.UserType.NON_PARTICIPANT
        }, follow=True)

        # User should be authenticated
        self.assertTrue(response.context['user'].is_authenticated)


class UserLoginTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.login_url = reverse('login')

        # Create test users
        self.participant_user = User.objects.create_user(
            username='testparticipant',
            password='TestPass123!',
            email='participant@test.com'
        )
        self.participant_user.profile.user_type = UserProfile.UserType.PARTICIPANT
        self.participant_user.profile.save()

        self.viewer_user = User.objects.create_user(
            username='testviewer',
            password='TestPass123!',
            email='viewer@test.com'
        )
        self.viewer_user.profile.user_type = UserProfile.UserType.NON_PARTICIPANT
        self.viewer_user.profile.save()

    def test_login_page_loads(self):
        """Test that login page loads successfully"""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'C3DS Login')

    def test_successful_login_participant(self):
        """Test participant login redirects to participant dashboard"""
        response = self.client.post(self.login_url, {
            'username': 'testparticipant',
            'password': 'TestPass123!',
            'remember_me': False
        })

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('participant:dashboard'))

    def test_successful_login_non_participant(self):
        """Test non-participant login redirects to main dashboard"""
        response = self.client.post(self.login_url, {
            'username': 'testviewer',
            'password': 'TestPass123!',
            'remember_me': False
        })

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('dashboard:index'))

    def test_remember_me_checked(self):
        """Test that remember me checkbox works"""
        response = self.client.post(self.login_url, {
            'username': 'testviewer',
            'password': 'TestPass123!',
            'remember_me': True
        })
        # When remember me is checked, session should have extended expiry
        self.assertGreater(self.client.session.get_expiry_age(), 1000000)  # More than ~11 days

    def test_login_with_next_parameter(self):
        """Test that next parameter is respected"""
        response = self.client.post(self.login_url + '?next=/participant/dashboard/', {
            'username': 'testviewer',
            'password': 'TestPass123!',
            'remember_me': False
        })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/participant/dashboard/')

    def test_invalid_credentials(self):
        """Test login with invalid credentials shows error"""
        response = self.client.post(self.login_url, {
            'username': 'testviewer',
            'password': 'WrongPassword!',
            'remember_me': False
        })

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['user'].is_authenticated)
