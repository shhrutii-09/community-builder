"""Security tests for passwords, login, 2FA, password reset, Google login, admin and migrations.

Run with:  python manage.py test user -v 2
Django creates a separate throw-away test database, so real data is never touched.
"""
import datetime
import shutil
import tempfile
import time
from unittest import mock

from django.contrib.auth.hashers import identify_hasher, is_password_usable, make_password
from django.contrib.auth.models import User as DjangoUser
from django.core import mail
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from django.urls import reverse

from . import security
from .models import UserSettings, city, state, user

GOOD_PW = 'Str0ng!Pass'


def _png_bytes():
    from io import BytesIO
    from PIL import Image
    buf = BytesIO(); Image.new('RGB', (2, 2), 'white').save(buf, 'PNG'); return buf.getvalue()


TINY_PNG = _png_bytes()


def make_user(email='sam@example.com', password=GOOD_PW, **kw):
    s, _ = state.objects.get_or_create(statename='Gujarat')
    c, _ = city.objects.get_or_create(cityname='Surat', stateid=s)
    return user.objects.create(
        username=kw.pop('username', 'sam'), email=email,
        password=make_password(password) if password is not None else make_password(None),
        profile='x.png', bio='b', gender='male', dob=datetime.date(2000, 1, 1), cityid=c, **kw)


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()

    def login_post(self, email, password, ajax=False):
        extra = {'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest'} if ajax else {}
        return self.client.post(reverse('signin'), {'email': email, 'password': password, 'sign-in-btn': '1'}, **extra)


class SignupAndLoginTests(Base):
    def test_signup_stores_a_hash_not_the_password(self):
        s, _ = state.objects.get_or_create(statename='Gujarat')
        c, _ = city.objects.get_or_create(cityname='Surat', stateid=s)
        tmp = tempfile.mkdtemp()
        try:
            with override_settings(MEDIA_ROOT=tmp):
                r = self.client.post(reverse('signup'), {
                    'sign-up-btn': '1', 'name': 'new', 'email': 'new@example.com', 'password': GOOD_PW,
                    'bio': 'hi', 'gender': 'male', 'dob': '2000-01-01', 'city': c.cityid,
                    'fup': SimpleUploadedFile('p.png', TINY_PNG, content_type='image/png')})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(r.status_code, 302, getattr(r, 'context', None) and r.context.get('error_msg'))
        u = user.objects.get(email='new@example.com')
        self.assertNotEqual(u.password, GOOD_PW)
        self.assertEqual(identify_hasher(u.password).algorithm, 'pbkdf2_sha256')
        self.assertEqual(self.login_post('new@example.com', GOOD_PW).status_code, 302)

    def test_signup_rejects_weak_password(self):
        s, _ = state.objects.get_or_create(statename='Gujarat')
        c, _ = city.objects.get_or_create(cityname='Surat', stateid=s)
        r = self.client.post(reverse('signup'), {'sign-up-btn': '1', 'name': 'n', 'email': 'w@example.com',
                                                 'password': 'weak', 'city': c.cityid})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(user.objects.filter(email='w@example.com').exists())

    def test_login_success_wrong_password_unknown_email(self):
        make_user()
        r = self.login_post('sam@example.com', GOOD_PW)
        self.assertEqual(r.status_code, 302)
        self.assertIn('userid', self.client.session)
        c2 = Client()
        c2.post(reverse('signin'), {'email': 'sam@example.com', 'password': 'Wrong!Pass1', 'sign-in-btn': '1'})
        self.assertNotIn('userid', c2.session)
        c2.post(reverse('signin'), {'email': 'nobody@example.com', 'password': GOOD_PW, 'sign-in-btn': '1'})
        self.assertNotIn('userid', c2.session)

    def test_ajax_login_json(self):
        make_user()
        self.assertTrue(self.login_post('sam@example.com', GOOD_PW, ajax=True).json()['success'])
        self.assertFalse(self.login_post('sam@example.com', 'bad', ajax=True).json()['success'])

    def test_google_only_account_cannot_be_logged_into_with_blank_password(self):
        u = make_user(email='g@example.com', password=None)
        self.assertFalse(is_password_usable(u.password))
        for blank in ('', ' '):
            r = self.login_post('g@example.com', blank, ajax=True)
            self.assertFalse(r.json()['success'])
        self.assertNotIn('userid', self.client.session)

    def test_unhashed_legacy_value_is_never_accepted(self):
        make_user().__class__.objects.filter(email='sam@example.com').update(password='Plain@123')
        self.assertFalse(self.login_post('sam@example.com', 'Plain@123', ajax=True).json()['success'])

    def test_session_key_rotates_on_login(self):
        make_user()
        self.client.get(reverse('signin'))
        before = self.client.session.session_key
        self.login_post('sam@example.com', GOOD_PW)
        self.assertNotEqual(before, self.client.session.session_key)


class RateLimitTests(Base):
    def test_lockout_after_five_failures_even_with_correct_password(self):
        make_user()
        for _ in range(security.LOGIN_LIMIT):
            self.assertFalse(self.login_post('sam@example.com', 'bad', ajax=True).json()['success'])
        r = self.login_post('sam@example.com', GOOD_PW, ajax=True).json()
        self.assertFalse(r['success'])
        self.assertIn('Too many', r['msg'])

    def test_other_accounts_are_not_locked(self):
        make_user(); make_user(email='b@example.com', username='b')
        for _ in range(security.LOGIN_LIMIT + 1):
            self.login_post('sam@example.com', 'bad', ajax=True)
        self.assertTrue(self.login_post('b@example.com', GOOD_PW, ajax=True).json()['success'])

    def test_success_resets_the_counter(self):
        make_user()
        for _ in range(security.LOGIN_LIMIT - 1):
            self.login_post('sam@example.com', 'bad', ajax=True)
        self.assertTrue(self.login_post('sam@example.com', GOOD_PW, ajax=True).json()['success'])
        for _ in range(security.LOGIN_LIMIT - 1):
            self.login_post('sam@example.com', 'bad', ajax=True)
        self.assertTrue(self.login_post('sam@example.com', GOOD_PW, ajax=True).json()['success'])

    def test_counter_lives_in_the_shared_database_cache(self):
        from django.conf import settings
        self.assertIn('DatabaseCache', settings.CACHES['default']['BACKEND'])
        self.assertIn('django_cache', connection.introspection.table_names())

    def test_cache_outage_does_not_break_login(self):
        make_user()
        with mock.patch.object(security.cache, 'get', side_effect=RuntimeError('down')), \
             mock.patch.object(security.cache, 'add', side_effect=RuntimeError('down')):
            self.assertTrue(self.login_post('sam@example.com', GOOD_PW, ajax=True).json()['success'])


class TwoFactorTests(Base):
    def setUp(self):
        super().setUp()
        self.u = make_user()
        UserSettings.objects.create(user=self.u, two_factor_auth=True)

    def start(self):
        r = self.login_post('sam@example.com', GOOD_PW)
        self.assertRedirects(r, reverse('verify_2fa'), fetch_redirect_response=False)
        self.assertNotIn('userid', self.client.session)
        self.assertEqual(len(mail.outbox), 1)
        return mail.outbox[0].body.split('code is ')[1][:6]

    def test_2fa_is_enforced_and_code_is_emailed(self):
        otp = self.start()
        self.assertTrue(otp.isdigit() and len(otp) == 6)
        r = self.client.post(reverse('verify_2fa'), {'otp': otp})
        self.assertRedirects(r, reverse('home'), fetch_redirect_response=False)
        self.assertEqual(self.client.session['userid'], self.u.userid)

    def test_wrong_code_then_attempt_cap(self):
        otp = self.start()
        for _ in range(5):
            self.assertEqual(self.client.post(reverse('verify_2fa'), {'otp': '000000' if otp != '000000' else '111111'}).status_code, 200)
        r = self.client.post(reverse('verify_2fa'), {'otp': otp})  # correct code, but cap exceeded
        self.assertNotIn('userid', self.client.session)
        self.assertContains(r, 'Too many incorrect codes')

    def test_code_expires(self):
        otp = self.start()
        s = self.client.session; s['2fa_expires'] = time.time() - 1; s.save()
        r = self.client.post(reverse('verify_2fa'), {'otp': otp})
        self.assertNotIn('userid', self.client.session)
        self.assertContains(r, 'expired')

    def test_non_ascii_code_does_not_crash(self):
        self.start()
        self.assertEqual(self.client.post(reverse('verify_2fa'), {'otp': '١٢٣٤٥٦'}).status_code, 200)

    def test_cannot_open_verify_page_without_password_step(self):
        self.assertRedirects(self.client.get(reverse('verify_2fa')), reverse('signin'), fetch_redirect_response=False)

    def test_email_failure_does_not_log_user_in(self):
        with mock.patch('user.views.send_mail', side_effect=OSError('smtp down')):
            r = self.login_post('sam@example.com', GOOD_PW, ajax=True)
        self.assertFalse(r.json()['success'])
        self.assertNotIn('userid', self.client.session)


class ChangePasswordTests(Base):
    def setUp(self):
        super().setUp()
        self.u = make_user()
        self.login_post('sam@example.com', GOOD_PW)

    def post(self, current, new):
        return self.client.post(reverse('settings'), {'action': 'change_password', 'current_password': current, 'new_password': new})

    def test_success_stores_hash(self):
        self.post(GOOD_PW, 'N3w!Passw0rd')
        self.u.refresh_from_db()
        self.assertTrue(security.verify_password('N3w!Passw0rd', self.u.password))
        self.assertNotEqual(self.u.password, 'N3w!Passw0rd')

    def test_wrong_current_password_rejected(self):
        old = self.u.password
        self.post('Wrong!Pass1', 'N3w!Passw0rd')
        self.u.refresh_from_db()
        self.assertEqual(self.u.password, old)

    def test_weak_new_password_rejected(self):
        old = self.u.password
        self.post(GOOD_PW, 'weak')
        self.u.refresh_from_db()
        self.assertEqual(self.u.password, old)


@override_settings(PASSWORD_RESET_TIMEOUT=1800)
class ForgotPasswordTests(Base):
    def setUp(self):
        super().setUp()
        self.u = make_user()

    def request_link(self, email='sam@example.com'):
        return self.client.post(reverse('forgot_password'), {'email': email})

    def link(self):
        body = mail.outbox[-1].body
        return '/reset-password/' + body.split('/reset-password/')[1].split('/')[0] + '/'

    def test_email_alone_can_never_change_a_password(self):
        old = self.u.password
        self.client.post(reverse('forgot_password'), {'email': 'sam@example.com', 'new_password': 'Hack3d!Pass'})
        self.u.refresh_from_db()
        self.assertEqual(self.u.password, old)
        self.assertFalse(security.verify_password('Hack3d!Pass', self.u.password))

    def test_get_redirects_to_signin(self):
        self.assertRedirects(self.client.get(reverse('forgot_password')), reverse('signin'), fetch_redirect_response=False)

    def test_same_response_for_known_and_unknown_email(self):
        a = self.request_link('sam@example.com').context['simsg']
        b = self.request_link('nobody@example.com').context['simsg']
        self.assertEqual(a, b)
        self.assertEqual(len(mail.outbox), 1)          # only the real account got mail
        self.assertEqual(mail.outbox[0].to, ['sam@example.com'])

    def test_invalid_email_format(self):
        r = self.request_link('not-an-email')
        self.assertIn('valid email', r.context['simsg'])
        self.assertEqual(len(mail.outbox), 0)

    def test_rate_limited(self):
        for _ in range(security.RESET_LIMIT):
            self.request_link()
        self.assertEqual(len(mail.outbox), security.RESET_LIMIT)
        r = self.request_link()
        self.assertIn('Too many', r.context['simsg'])
        self.assertEqual(len(mail.outbox), security.RESET_LIMIT)

    def test_full_reset_flow_and_link_is_single_use(self):
        self.request_link()
        url = self.link()
        self.assertEqual(self.client.get(url).status_code, 200)
        r = self.client.post(url, {'new_password': 'N3w!Passw0rd', 'confirm_password': 'N3w!Passw0rd'})
        self.assertContains(r, 'Password reset successfully')
        self.assertTrue(self.login_post('sam@example.com', 'N3w!Passw0rd').status_code == 302)
        self.assertFalse(self.login_post('sam@example.com', GOOD_PW, ajax=True).json()['success'])
        # second use of the very same link
        self.assertEqual(self.client.get(url).status_code, 400)
        r2 = self.client.post(url, {'new_password': 'An0ther!Pass', 'confirm_password': 'An0ther!Pass'})
        self.assertEqual(r2.status_code, 400)
        self.u.refresh_from_db()
        self.assertTrue(security.verify_password('N3w!Passw0rd', self.u.password))

    def test_validation_errors_keep_the_link_usable(self):
        self.request_link(); url = self.link()
        r = self.client.post(url, {'new_password': 'N3w!Passw0rd', 'confirm_password': 'different'})
        self.assertContains(r, 'do not match')
        r = self.client.post(url, {'new_password': 'weak', 'confirm_password': 'weak'})
        self.assertContains(r, 'at least 8')
        self.u.refresh_from_db()
        self.assertTrue(security.verify_password(GOOD_PW, self.u.password))
        self.assertEqual(self.client.get(url).status_code, 200)

    def test_expired_link(self):
        self.request_link(); url = self.link()
        with override_settings(PASSWORD_RESET_TIMEOUT=-1):
            self.assertEqual(self.client.get(url).status_code, 400)

    def test_expiry_default_is_thirty_minutes(self):
        from django.conf import settings
        self.assertEqual(settings.PASSWORD_RESET_TIMEOUT, 1800)

    def test_tampered_and_garbage_links(self):
        self.request_link(); url = self.link()
        for bad in (url[:-4] + 'AAA/', '/reset-password/garbage/', '/reset-password/' + 'x' * 400 + '/'):
            self.assertEqual(self.client.get(bad).status_code, 400, bad)
            self.assertEqual(self.client.post(bad, {'new_password': GOOD_PW + '1', 'confirm_password': GOOD_PW + '1'}).status_code, 400)

    def test_link_dies_if_password_changed_elsewhere(self):
        self.request_link(); url = self.link()
        user.objects.filter(pk=self.u.pk).update(password=make_password('Other!Pass1'))
        self.assertEqual(self.client.get(url).status_code, 400)

    def test_link_dies_if_email_changed(self):
        self.request_link(); url = self.link()
        user.objects.filter(pk=self.u.pk).update(email='moved@example.com')
        self.assertEqual(self.client.get(url).status_code, 400)

    def test_race_between_two_submissions_only_one_wins(self):
        self.request_link(); url = self.link()
        token = url.split('/')[2]
        stale = security.user_from_reset_token(token)          # both requests "saw" the valid link
        self.client.post(url, {'new_password': 'N3w!Passw0rd', 'confirm_password': 'N3w!Passw0rd'})
        with mock.patch('user.views.user_from_reset_token', return_value=stale):
            r = self.client.post(url, {'new_password': 'Rac3!Passw0rd', 'confirm_password': 'Rac3!Passw0rd'})
        self.assertEqual(r.status_code, 400)
        self.u.refresh_from_db()
        self.assertTrue(security.verify_password('N3w!Passw0rd', self.u.password))

    def test_reset_clears_login_lockout(self):
        for _ in range(security.LOGIN_LIMIT):
            self.login_post('sam@example.com', 'bad', ajax=True)
        self.request_link(); url = self.link()
        self.client.post(url, {'new_password': 'N3w!Passw0rd', 'confirm_password': 'N3w!Passw0rd'})
        self.assertTrue(self.login_post('sam@example.com', 'N3w!Passw0rd', ajax=True).json()['success'])

    def test_google_only_account_can_set_a_password_via_email_link(self):
        g = make_user(email='g@example.com', username='g', password=None)
        self.request_link('g@example.com'); url = self.link()
        self.client.post(url, {'new_password': 'N3w!Passw0rd', 'confirm_password': 'N3w!Passw0rd'})
        g.refresh_from_db()
        self.assertTrue(is_password_usable(g.password))

    def test_reset_page_is_not_cacheable(self):
        self.request_link()
        self.assertIn('no-store', self.client.get(self.link())['Cache-Control'])

    @override_settings(SITE_URL='https://univo.example.com')
    def test_site_url_setting_controls_the_link_host(self):
        self.request_link()
        self.assertIn('https://univo.example.com/reset-password/', mail.outbox[-1].body)

    def test_sign_in_page_popup_is_email_only(self):
        html = self.client.get(reverse('signin')).content.decode()
        self.assertIn('name="email"', html)
        self.assertNotIn('name="new_password"', html)


class GoogleLoginTests(Base):
    def run_callback(self, info):
        s = self.client.session; s['google_oauth_state'] = 'abc'; s.save()
        flow = mock.MagicMock()
        with mock.patch('user.views._build_google_flow', return_value=flow), \
             mock.patch('user.views.id_token.verify_oauth2_token', return_value=info), \
             mock.patch('time.sleep'):
            return self.client.get(reverse('google_callback'), {'state': 'abc'})

    def test_unverified_google_email_is_rejected(self):
        make_user(email='v@example.com')
        r = self.run_callback({'sub': '1', 'email': 'v@example.com', 'email_verified': False, 'name': 'V'})
        self.assertRedirects(r, reverse('signin'), fetch_redirect_response=False)
        self.assertNotIn('userid', self.client.session)
        self.assertIsNone(user.objects.get(email='v@example.com').google_id)

    def test_new_google_user_gets_unusable_password(self):
        make_user(email='other@example.com', username='o')   # provides a default city
        self.run_callback({'sub': '9', 'email': 'new@example.com', 'email_verified': True, 'name': 'New'})
        u = user.objects.get(email='new@example.com')
        self.assertFalse(is_password_usable(u.password))
        self.assertIn('userid', self.client.session)

    def test_verified_google_email_links_existing_account(self):
        u = make_user(email='v@example.com')
        self.run_callback({'sub': '7', 'email': 'v@example.com', 'email_verified': True, 'name': 'V'})
        u.refresh_from_db()
        self.assertEqual(u.google_id, '7')
        self.assertEqual(self.client.session['userid'], u.userid)
        self.assertTrue(security.verify_password(GOOD_PW, u.password))  # existing password untouched


class DjangoAdminTests(TestCase):
    def setUp(self):
        cache.clear()
        DjangoUser.objects.create_superuser('root', 'root@example.com', 'Adm1n!Pass')
        self.client = Client(); self.client.login(username='root', password='Adm1n!Pass')
        # last_seen/last_checked_* are set for any user who has logged in: they must not block saving
        self.u = make_user(last_seen=timezone.now(), last_checked_chats=timezone.now())
        self.url = reverse('admin:user_user_change', args=[self.u.pk])

    def form(self, **over):
        d = {'username': 'sam', 'email': 'sam@example.com', 'profile': '', 'bio': 'b', 'gender': 'male',
             'dob': '2000-01-01', 'cityid': self.u.cityid_id, 'state_select': '', 'new_password': '',
             'google_id': '', 'phone': ''}   # note: no last_* fields, they are not part of the form
        d.update(over); return d

    def test_password_hash_is_never_rendered(self):
        for url in (self.url, reverse('admin:user_user_add')):
            html = self.client.get(url).content.decode()
            self.assertNotIn(self.u.password, html)
            self.assertNotIn('pbkdf2', html)
            self.assertNotIn('name="password"', html)
        self.assertIn('type="password"', self.client.get(self.url).content.decode())  # masked new-password box
        self.assertNotIn('Str0ng', self.client.get(self.url).content.decode())

    def test_saving_without_new_password_keeps_existing_hash(self):
        old = self.u.password
        r = self.client.post(self.url, self.form(bio='changed'))
        self.assertEqual(r.status_code, 302, r.context['adminform'].form.errors if r.context else '')
        self.u.refresh_from_db()
        self.assertEqual((self.u.password, self.u.bio), (old, 'changed'))

    def test_setting_new_password_hashes_it(self):
        self.client.post(self.url, self.form(new_password='N3w!Passw0rd'))
        self.u.refresh_from_db()
        self.assertTrue(security.verify_password('N3w!Passw0rd', self.u.password))
        self.assertNotEqual(self.u.password, 'N3w!Passw0rd')

    def test_weak_password_rejected_in_admin(self):
        old = self.u.password
        r = self.client.post(self.url, self.form(new_password='weak'))
        self.assertEqual(r.status_code, 200)
        self.u.refresh_from_db()
        self.assertEqual(self.u.password, old)

    def test_admin_created_user_without_password_is_unusable(self):
        tmp = tempfile.mkdtemp()
        try:
            with override_settings(MEDIA_ROOT=tmp):
                d = self.form(username='fresh', email='fresh@example.com',
                              profile=SimpleUploadedFile('p.png', TINY_PNG, content_type='image/png'))
                r = self.client.post(reverse('admin:user_user_add'), d)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(r.status_code, 302, r.context['adminform'].form.errors if r.context else '')
        self.assertFalse(is_password_usable(user.objects.get(username='fresh').password))

    def test_admin_requires_staff_login(self):
        c = Client()
        self.assertEqual(c.get(self.url).status_code, 302)
        self.assertEqual(c.get('/custom-admin/users/').status_code, 302)


class PasswordMigrationTests(TransactionTestCase):
    """Runs the real migrations on pre-existing plain-text rows."""
    before = [('user', '0032_alter_blog_image_alter_chat_image_and_more')]
    after = [('user', '0035_create_cache_table')]

    def migrate(self, targets):
        ex = MigrationExecutor(connection)
        ex.loader.build_graph()
        ex.migrate(targets)
        return ex.loader.project_state(targets).apps

    def tearDown(self):
        self.migrate(MigrationExecutor(connection).loader.graph.leaf_nodes())

    def test_plaintext_rows_are_hashed_safely(self):
        old = self.migrate(self.before)
        State, City, User = old.get_model('user', 'state'), old.get_model('user', 'city'), old.get_model('user', 'user')
        c = City.objects.create(cityname='Surat', stateid=State.objects.create(statename='G'))
        def mk(n, pw):
            return User.objects.create(username=n, email=n + '@x.com', password=pw, bio='', gender='m',
                                       dob=datetime.date(2000, 1, 1), cityid=c, profile='')
        plain, blank, hashed = mk('plain', 'Isha@123'), mk('blank', ''), mk('hashed', make_password('Kept@123'))
        stamps = {u.pk: u.registrationdt for u in (plain, blank, hashed)}
        hashed_before = hashed.password

        new = self.migrate(self.after)
        U = new.get_model('user', 'user')
        p, b, h = U.objects.get(pk=plain.pk), U.objects.get(pk=blank.pk), U.objects.get(pk=hashed.pk)
        self.assertTrue(security.verify_password('Isha@123', p.password))
        self.assertNotEqual(p.password, 'Isha@123')
        self.assertFalse(is_password_usable(b.password))
        self.assertFalse(security.verify_password('', b.password))
        self.assertEqual(h.password, hashed_before)                      # already-hashed row untouched
        self.assertTrue(security.verify_password('Kept@123', h.password))
        for u in (p, b, h):                                              # nothing else modified
            self.assertEqual(u.registrationdt, stamps[u.pk])
        self.assertIn('django_cache', connection.introspection.table_names())

    def test_migration_is_idempotent(self):
        old = self.migrate(self.before)
        State, City, User = old.get_model('user', 'state'), old.get_model('user', 'city'), old.get_model('user', 'user')
        c = City.objects.create(cityname='Surat', stateid=State.objects.create(statename='G'))
        User.objects.create(username='a', email='a@x.com', password='Isha@123', bio='', gender='m',
                            dob=datetime.date(2000, 1, 1), cityid=c, profile='')
        new = self.migrate(self.after)
        first = new.get_model('user', 'user').objects.get(username='a').password
        import importlib
        mod = importlib.import_module('user.migrations.0034_hash_user_passwords')
        mod.hash_existing_passwords(new, None)
        self.assertEqual(new.get_model('user', 'user').objects.get(username='a').password, first)
