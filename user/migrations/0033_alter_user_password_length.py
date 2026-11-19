from django.db import migrations, models


class Migration(migrations.Migration):
    """Widen user.password so it can hold a salted hash (was max_length=50)."""

    dependencies = [
        ('user', '0032_alter_blog_image_alter_chat_image_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='password',
            field=models.CharField(max_length=128),
        ),
    ]
