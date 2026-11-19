
from django.contrib.auth.hashers import check_password, make_password
from django.db import migrations


def fix_empty_password_hashes(apps, schema_editor):
    User = apps.get_model('user', 'user')

    for pk, password in User.objects.values_list('pk', 'password').iterator():
        if password and check_password('', password):
            User.objects.filter(pk=pk).update(
                password=make_password(None)
            )


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0035_create_cache_table'),
    ]

    operations = [
        migrations.RunPython(
            fix_empty_password_hashes,
            migrations.RunPython.noop
        ),
    ]
