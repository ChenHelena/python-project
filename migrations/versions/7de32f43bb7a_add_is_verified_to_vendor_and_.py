"""Add is_verified to Vendor and DeliveryPerson

Revision ID: 7de32f43bb7a
Revises: d33b4501780b
Create Date: 2024-10-02 16:34:50.552929

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '7de32f43bb7a'
down_revision = 'd33b4501780b'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('Vendor', sa.Column(
        'is_verified', sa.Boolean(), nullable=True, server_default='0'))
    op.add_column('DeliveryPerson', sa.Column(
        'is_verified', sa.Boolean(), nullable=True, server_default='0'))


def downgrade():
    op.drop_column('Vendor', 'is_verified')
    op.drop_column('DeliveryPerson', 'is_verified')