"""record_notes: formatted doctor notes on a medical record

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
    op.create_table('record_notes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('record_id', sa.Integer(), nullable=False),
    sa.Column('author_id', sa.Integer(), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['author_id'], ['users.id'], name=op.f('fk_record_notes_author_id_users')),
    sa.ForeignKeyConstraint(['record_id'], ['medical_records.id'], name=op.f('fk_record_notes_record_id_medical_records')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_record_notes'))
    )
    op.create_index(op.f('ix_record_notes_record_id'), 'record_notes', ['record_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_record_notes_record_id'), table_name='record_notes')
    op.drop_table('record_notes')
