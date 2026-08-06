"""Add scheduled_scans table

Revision ID: e3d4e5f6g7h8
Revises: d2c3d4e5f6g7
Create Date: 2026-06-28 12:40:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e3d4e5f6g7h8'
down_revision = 'd2c3d4e5f6g7'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table('scheduled_scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=True),
        sa.Column('target', sa.String(), nullable=True),
        sa.Column('tool', sa.String(), nullable=True),
        sa.Column('cron_expression', sa.String(), nullable=True),
        sa.Column('last_run', sa.DateTime(), nullable=True),
        sa.Column('next_run', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scheduled_scans_id'), 'scheduled_scans', ['id'], unique=False)
    op.create_index(op.f('ix_scheduled_scans_target'), 'scheduled_scans', ['target'], unique=False)

def downgrade() -> None:
    op.drop_index(op.f('ix_scheduled_scans_target'), table_name='scheduled_scans')
    op.drop_index(op.f('ix_scheduled_scans_id'), table_name='scheduled_scans')
    op.drop_table('scheduled_scans')
