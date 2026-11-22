"""appointments.duration_minutes: 15-minute quick visits next to 30-minute visits

Appointments no longer all have the same length, so a unique (doctor_id, scheduled_at)
index cannot tell that a 30-minute visit at 09:00 and a 15-minute one at 09:15 clash.
Overlap is checked when booking (appointment.service); the plain index serves that lookup.

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'appointments',
        sa.Column('duration_minutes', sa.Integer(), server_default='30', nullable=False),
    )
    op.drop_index(
        'uq_doctor_slot_active', table_name='appointments',
        postgresql_where=sa.text("status <> 'CANCELLED'"),
    )
    op.create_index(
        'ix_appointments_doctor_id_scheduled_at', 'appointments', ['doctor_id', 'scheduled_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_appointments_doctor_id_scheduled_at', table_name='appointments')
    op.create_index(
        'uq_doctor_slot_active', 'appointments', ['doctor_id', 'scheduled_at'], unique=True,
        postgresql_where=sa.text("status <> 'CANCELLED'"),
    )
    op.drop_column('appointments', 'duration_minutes')
