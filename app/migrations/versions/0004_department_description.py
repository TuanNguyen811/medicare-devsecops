"""departments.description shown on the department admin pages

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
    op.add_column('departments', sa.Column('description', sa.String(length=500), nullable=True))


def downgrade() -> None:
    op.drop_column('departments', 'description')
