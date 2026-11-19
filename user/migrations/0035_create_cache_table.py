from django.core.management import call_command
from django.db import migrations


def create_cache_table(apps, schema_editor):
    """Create the table behind CACHES['default'] (used for login rate limits).

    A shared database cache is needed because gunicorn runs several worker
    processes; the default in-memory cache is separate in each one.
    Idempotent: createcachetable skips tables that already exist.
    """
    call_command('createcachetable', 'django_cache', database=schema_editor.connection.alias, verbosity=0)


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0034_hash_user_passwords'),
    ]

    operations = [
        migrations.RunPython(create_cache_table, migrations.RunPython.noop),
    ]
