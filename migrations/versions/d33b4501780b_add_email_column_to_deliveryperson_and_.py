"""Add email column to DeliveryPerson and Vendor

Revision ID: d33b4501780b
Revises: 3247d3c7779b
Create Date: 2024-10-01 22:02:56.206870

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'd33b4501780b'
down_revision = '3247d3c7779b'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    # 添加 DeliveryPerson 表的 email 列
    with op.batch_alter_table('DeliveryPerson') as batch_op:
        batch_op.add_column(
            sa.Column('email', sa.String(length=255), nullable=False, unique=True))

    # 添加 Vendor 表的 email 列
    with op.batch_alter_table('Vendor') as batch_op:
        batch_op.add_column(
            sa.Column('email', sa.String(length=255), nullable=False, unique=True))


def downgrade():
    with op.batch_alter_table('DeliveryPerson') as batch_op:
        batch_op.drop_column('email')

    with op.batch_alter_table('Vendor') as batch_op:
        batch_op.drop_column('email')
