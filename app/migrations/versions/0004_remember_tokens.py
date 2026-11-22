"""remember_tokens for "Ghi nhớ đăng nhập"

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
    op.create_table('remember_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_remember_tokens_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remember_tokens')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_remember_tokens_token_hash'))
    )
    op.create_index(op.f('ix_remember_tokens_user_id'), 'remember_tokens', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_remember_tokens_user_id'), table_name='remember_tokens')
    op.drop_table('remember_tokens')
