"""Add pgvector and scan_finding_embeddings

Revision ID: c1b2c3d4e5f6
Revises: b5a94e574c9b
Create Date: 2026-06-28 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

# revision identifiers, used by Alembic.
revision = 'c1b2c3d4e5f6'
down_revision = '550b6e8a1bdb'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # 1. Create the vector extension natively in Postgres
    op.execute('CREATE EXTENSION IF NOT EXISTS vector')

    # 2. Create the scan_finding_embeddings table
    op.create_table('scan_finding_embeddings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('target', sa.String(), nullable=True),
        sa.Column('tool', sa.String(), nullable=True),
        sa.Column('risk', sa.String(), nullable=True),
        sa.Column('text_content', sa.String(), nullable=True),
        sa.Column('embedding', Vector(384), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_finding_embeddings_id'), 'scan_finding_embeddings', ['id'], unique=False)
    op.create_index(op.f('ix_scan_finding_embeddings_target'), 'scan_finding_embeddings', ['target'], unique=False)

def downgrade() -> None:
    op.drop_index(op.f('ix_scan_finding_embeddings_target'), table_name='scan_finding_embeddings')
    op.drop_index(op.f('ix_scan_finding_embeddings_id'), table_name='scan_finding_embeddings')
    op.drop_table('scan_finding_embeddings')
    op.execute('DROP EXTENSION IF EXISTS vector')
