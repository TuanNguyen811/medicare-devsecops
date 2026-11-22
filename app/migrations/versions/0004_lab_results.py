"""lab_results: lab reports attached to a medical record

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
    op.create_table('lab_results',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('record_id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('source_url', sa.String(length=500), nullable=False),
    sa.Column('content_type', sa.String(length=50), nullable=False),
    sa.Column('content', sa.LargeBinary(), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_lab_results_created_by_id_users')),
    sa.ForeignKeyConstraint(['record_id'], ['medical_records.id'], name=op.f('fk_lab_results_record_id_medical_records')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_lab_results'))
    )
    op.create_index(op.f('ix_lab_results_record_id'), 'lab_results', ['record_id'])


def downgrade() -> None:
    op.drop_index(op.f('ix_lab_results_record_id'), table_name='lab_results')
    op.drop_table('lab_results')
