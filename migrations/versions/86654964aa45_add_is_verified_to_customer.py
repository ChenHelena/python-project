"""Add is_verified to Customer

Revision ID: 86654964aa45
Revises: 
Create Date: 2024-09-17 23:11:02.705942

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '86654964aa45'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('Customer', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('is_verified', sa.Boolean(), nullable=True))


def downgrade():
    with op.batch_alter_table('Customer', schema=None) as batch_op:
        batch_op.drop_column('is_verified')
    # ### end Alembic commands ###
