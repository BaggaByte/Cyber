"""Add response_actions table

Revision ID: d2c3d4e5f6g7
Revises: c1b2c3d4e5f6
Create Date: 2026-06-28 12:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd2c3d4e5f6g7'
down_revision = 'c1b2c3d4e5f6'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table('response_actions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('script', sa.String(), nullable=True),
        sa.Column('ticket_payload', sa.JSON(), nullable=True),
        sa.Column('slack_notified', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_response_actions_id'), 'response_actions', ['id'], unique=False)

def downgrade() -> None:
    op.drop_index(op.f('ix_response_actions_id'), table_name='response_actions')
    op.drop_table('response_actions')
