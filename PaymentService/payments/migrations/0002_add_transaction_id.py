from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('payments', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='payment',
            name='transaction_id',
            field=models.CharField(
                max_length=22,
                null=True,
                blank=True,
                db_index=True,
            ),
        ),
    ]
