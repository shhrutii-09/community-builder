from django.contrib.auth.hashers import identify_hasher, make_password, is_password_usable
from django.db import migrations


def hash_existing_passwords(apps, schema_editor):
    User = apps.get_model('user', 'user')

    for pk, raw in User.objects.values_list('pk', 'password').iterator():
        # Empty passwords should remain unusable.
        if not raw:
            User.objects.filter(pk=pk).update(
                password=make_password(None)
            )
            continue

        # Skip passwords that are already unusable.
        if not is_password_usable(raw):
            continue

        # Skip passwords that are already hashed.
        try:
            identify_hasher(raw)
            continue
        except ValueError:
            pass

        # Hash plain-text passwords.
        User.objects.filter(pk=pk).update(
            password=make_password(raw)
        )


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0033_alter_user_password_length'),
    ]

    operations = [
        migrations.RunPython(
            hash_existing_passwords,
            migrations.RunPython.noop
        ),
    ]