"""slip_templates: per-doctor examination slip layout

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
    op.create_table('slip_templates',
    sa.Column('doctor_id', sa.Integer(), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['doctor_id'], ['users.id'], name=op.f('fk_slip_templates_doctor_id_users')),
    sa.PrimaryKeyConstraint('doctor_id', name=op.f('pk_slip_templates'))
    )


def downgrade() -> None:
    op.drop_table('slip_templates')
