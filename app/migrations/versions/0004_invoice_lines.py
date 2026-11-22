"""invoice_lines: billed services on an invoice

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
    op.create_table('invoice_lines',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('invoice_id', sa.Integer(), nullable=False),
    sa.Column('service_code', sa.String(length=20), nullable=False),
    sa.Column('description', sa.String(length=100), nullable=False),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('unit_price', sa.Numeric(precision=12, scale=0), nullable=False),
    sa.Column('amount', sa.Numeric(precision=12, scale=0), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_invoice_lines_created_by_id_users')),
    sa.ForeignKeyConstraint(['invoice_id'], ['invoices.id'], name=op.f('fk_invoice_lines_invoice_id_invoices')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_invoice_lines'))
    )
    op.create_index(op.f('ix_invoice_lines_invoice_id'), 'invoice_lines', ['invoice_id'])


def downgrade() -> None:
    op.drop_index(op.f('ix_invoice_lines_invoice_id'), table_name='invoice_lines')
    op.drop_table('invoice_lines')
