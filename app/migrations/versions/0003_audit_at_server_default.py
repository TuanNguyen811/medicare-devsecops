"""audit_logs.at defaults to the database clock

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column('audit_logs', 'at', server_default=sa.text('now()'))


def downgrade() -> None:
    op.alter_column('audit_logs', 'at', server_default=None)
