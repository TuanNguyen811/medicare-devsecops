"""initial

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('audit_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('actor_id', sa.Integer(), nullable=False),
    sa.Column('action', sa.String(length=50), nullable=False),
    sa.Column('entity_type', sa.String(length=50), nullable=False),
    sa.Column('entity_id', sa.Integer(), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=True),
    sa.Column('at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_logs'))
    )
    op.create_table('departments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('code', sa.String(length=20), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_departments')),
    sa.UniqueConstraint('code', name=op.f('uq_departments_code'))
    )
    op.create_table('medicines',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('code', sa.String(length=20), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('unit', sa.String(length=20), nullable=False),
    sa.Column('unit_price', sa.Numeric(precision=12, scale=0), nullable=False),
    sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_medicines')),
    sa.UniqueConstraint('code', name=op.f('uq_medicines_code'))
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('full_name', sa.String(length=100), nullable=False),
    sa.Column('role', sa.Enum('ADMIN', 'RECEPTIONIST', 'DOCTOR', 'NURSE', 'PATIENT', name='role', native_enum=False, create_constraint=True, length=20), nullable=False),
    sa.Column('department_id', sa.Integer(), nullable=True),
    sa.Column('patient_id', sa.Integer(), nullable=True),
    sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
    sa.Column('failed_login_count', sa.Integer(), server_default='0', nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['department_id'], ['departments.id'], name=op.f('fk_users_department_id_departments')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    sa.UniqueConstraint('patient_id', name=op.f('uq_users_patient_id')),
    sa.UniqueConstraint('username', name=op.f('uq_users_username'))
    )
    op.create_table('patients',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('code', sa.String(length=20), nullable=False),
    sa.Column('full_name', sa.String(length=100), nullable=False),
    sa.Column('date_of_birth', sa.Date(), nullable=False),
    sa.Column('gender', sa.String(length=1), nullable=False),
    sa.Column('national_id', sa.String(length=12), nullable=False),
    sa.Column('insurance_number', sa.String(length=15), nullable=True),
    sa.Column('phone', sa.String(length=20), nullable=False),
    sa.Column('address', sa.String(length=255), nullable=False),
    sa.Column('department_id', sa.Integer(), nullable=True),
    sa.Column('attending_doctor_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("gender IN ('M', 'F')", name=op.f('ck_patients_gender')),
    sa.CheckConstraint("national_id ~ '^[0-9]{12}$'", name=op.f('ck_patients_national_id_format')),
    sa.ForeignKeyConstraint(['attending_doctor_id'], ['users.id'], name=op.f('fk_patients_attending_doctor_id_users')),
    sa.ForeignKeyConstraint(['department_id'], ['departments.id'], name=op.f('fk_patients_department_id_departments')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_patients')),
    sa.UniqueConstraint('code', name=op.f('uq_patients_code')),
    sa.UniqueConstraint('national_id', name=op.f('uq_patients_national_id'))
    )
    # users and patients reference each other: this FK is added once both tables exist.
    op.create_foreign_key(op.f('fk_users_patient_id_patients'), 'users', 'patients', ['patient_id'], ['id'])
    op.create_table('appointments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('patient_id', sa.Integer(), nullable=False),
    sa.Column('doctor_id', sa.Integer(), nullable=False),
    sa.Column('scheduled_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('reason', sa.String(length=500), nullable=False),
    sa.Column('status', sa.Enum('REQUESTED', 'CONFIRMED', 'CANCELLED', 'COMPLETED', name='appointment_status', native_enum=False, create_constraint=True, length=20), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_appointments_created_by_id_users')),
    sa.ForeignKeyConstraint(['doctor_id'], ['users.id'], name=op.f('fk_appointments_doctor_id_users')),
    sa.ForeignKeyConstraint(['patient_id'], ['patients.id'], name=op.f('fk_appointments_patient_id_patients')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_appointments'))
    )
    op.create_index('uq_doctor_slot_active', 'appointments', ['doctor_id', 'scheduled_at'], unique=True, postgresql_where=sa.text("status <> 'CANCELLED'"))
    op.create_table('medical_records',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('patient_id', sa.Integer(), nullable=False),
    sa.Column('doctor_id', sa.Integer(), nullable=False),
    sa.Column('visit_date', sa.Date(), nullable=False),
    sa.Column('symptoms', sa.Text(), nullable=False),
    sa.Column('diagnosis_code', sa.String(length=20), nullable=False),
    sa.Column('diagnosis_text', sa.String(length=500), nullable=False),
    sa.Column('notes', sa.Text(), server_default='', nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['doctor_id'], ['users.id'], name=op.f('fk_medical_records_doctor_id_users')),
    sa.ForeignKeyConstraint(['patient_id'], ['patients.id'], name=op.f('fk_medical_records_patient_id_patients')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_medical_records'))
    )
    op.create_table('invoices',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('record_id', sa.Integer(), nullable=False),
    sa.Column('patient_id', sa.Integer(), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=False),
    sa.Column('total_amount', sa.Numeric(precision=12, scale=0), nullable=False),
    sa.Column('coverage_rate', sa.Numeric(precision=3, scale=2), nullable=False),
    sa.Column('insurance_amount', sa.Numeric(precision=12, scale=0), nullable=False),
    sa.Column('patient_amount', sa.Numeric(precision=12, scale=0), nullable=False),
    sa.Column('status', sa.Enum('UNPAID', 'PAID', name='invoice_status', native_enum=False, create_constraint=True, length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('coverage_rate >= 0 AND coverage_rate <= 1', name=op.f('ck_invoices_coverage_rate_range')),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_invoices_created_by_id_users')),
    sa.ForeignKeyConstraint(['patient_id'], ['patients.id'], name=op.f('fk_invoices_patient_id_patients')),
    sa.ForeignKeyConstraint(['record_id'], ['medical_records.id'], name=op.f('fk_invoices_record_id_medical_records')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_invoices')),
    sa.UniqueConstraint('record_id', name=op.f('uq_invoices_record_id'))
    )
    op.create_table('prescriptions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('record_id', sa.Integer(), nullable=False),
    sa.Column('patient_id', sa.Integer(), nullable=False),
    sa.Column('doctor_id', sa.Integer(), nullable=False),
    sa.Column('note', sa.String(length=500), server_default='', nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['doctor_id'], ['users.id'], name=op.f('fk_prescriptions_doctor_id_users')),
    sa.ForeignKeyConstraint(['patient_id'], ['patients.id'], name=op.f('fk_prescriptions_patient_id_patients')),
    sa.ForeignKeyConstraint(['record_id'], ['medical_records.id'], name=op.f('fk_prescriptions_record_id_medical_records')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_prescriptions'))
    )
    op.create_table('prescription_items',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('prescription_id', sa.Integer(), nullable=False),
    sa.Column('medicine_id', sa.Integer(), nullable=False),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('dosage', sa.String(length=200), nullable=False),
    sa.CheckConstraint('quantity > 0', name=op.f('ck_prescription_items_quantity_positive')),
    sa.ForeignKeyConstraint(['medicine_id'], ['medicines.id'], name=op.f('fk_prescription_items_medicine_id_medicines')),
    sa.ForeignKeyConstraint(['prescription_id'], ['prescriptions.id'], name=op.f('fk_prescription_items_prescription_id_prescriptions')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_prescription_items'))
    )


def downgrade() -> None:
    op.drop_table('prescription_items')
    op.drop_table('prescriptions')
    op.drop_table('invoices')
    op.drop_table('medical_records')
    op.drop_index('uq_doctor_slot_active', table_name='appointments', postgresql_where=sa.text("status <> 'CANCELLED'"))
    op.drop_table('appointments')
    op.drop_constraint(op.f('fk_users_patient_id_patients'), 'users', type_='foreignkey')
    op.drop_table('patients')
    op.drop_table('users')
    op.drop_table('medicines')
    op.drop_table('departments')
    op.drop_table('audit_logs')
