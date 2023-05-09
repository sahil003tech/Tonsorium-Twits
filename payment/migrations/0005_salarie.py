# Generated by Django 2.2.6 on 2020-03-19 04:48

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_auto_20200317_1216'),
        ('payment', '0004_invoice_paid'),
    ]

    operations = [
        migrations.CreateModel(
            name='Salarie',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('MONTHLY', 'MONTHLY'), ('HOURLY', 'HOURLY')], max_length=10)),
                ('amount', models.DecimalField(decimal_places=2, default=0.0, max_digits=10)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='accounts.Employee')),
            ],
        ),
    ]
