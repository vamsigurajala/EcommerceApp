from django.db import migrations, connection
import random, time

PREFIX = "TX"
def make_txn_id():
    # 20 digits + prefix -> max length 22 fits your CharField
    return f"{PREFIX}{int(time.time() * 1000):013d}{random.randint(0, 99999):05d}"

def backfill(apps, schema_editor):
    Payment = apps.get_model('payments', 'Payment')
    seen = set()

    # Collect existing non-empty values to avoid accidental dupes
    for (val,) in Payment.objects.exclude(transaction_id__isnull=True).exclude(transaction_id='') \
                                 .values_list('transaction_id'):
        seen.add(val)

    batch = []
    for p in Payment.objects.all().only('pk', 'transaction_id'):
        if p.transaction_id:
            continue
        code = make_txn_id()
        while code in seen:
            code = make_txn_id()
        seen.add(code)
        p.transaction_id = code
        batch.append(p)

        if len(batch) >= 500:
            Payment.objects.bulk_update(batch, ['transaction_id'])
            batch.clear()

    if batch:
        Payment.objects.bulk_update(batch, ['transaction_id'])

def noop(apps, schema_editor):
    pass

class Migration(migrations.Migration):
    dependencies = [
        ('payments', '0002_add_transaction_id'),
    ]
    operations = [
        migrations.RunPython(backfill, noop),
    ]
