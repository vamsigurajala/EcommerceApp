from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('payments', '0003_backfill_transaction_ids'),
    ]

    operations = [
        migrations.AlterField(
            model_name='payment',
            name='transaction_id',
            field=models.CharField(
                max_length=22,
                unique=True,         # ← now unique
                null=True, blank=True,
                db_index=True,
            ),
        ),
    ]
