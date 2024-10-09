"""Added DeliveryPerson, Vendor, Address models with phone, role, created_at, and address_id

Revision ID: 3247d3c7779b
Revises: 86654964aa45
Create Date: 2024-10-01 21:18:34.010267

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '3247d3c7779b'
down_revision = '86654964aa45'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    
    # 新增 DeliveryPerson 模型
    if not conn.dialect.has_table(conn, 'DeliveryPerson'):
       op.create_table('DeliveryPerson',
                     sa.Column('id', sa.Integer(), primary_key=True,
                                   autoincrement=True),
                     sa.Column('name', sa.String(length=255), nullable=False),
                     sa.Column('email', sa.String(length=255), nullable=False),
                     sa.Column('phone', sa.String(length=20),
                                   nullable=True),
                     sa.Column('role', sa.String(length=50),
                                   nullable=False),
                     sa.Column('is_verified', sa.Boolean(), nullable=True),
                     sa.Column('created_at', sa.DateTime(), nullable=False,
                                   server_default=sa.func.now()),
                     sa.UniqueConstraint('email')
                     )

    # 新增 Vendor 模型
    if not conn.dialect.has_table(conn, 'Vendor'):
       op.create_table('Vendor',
                     sa.Column('id', sa.Integer(), primary_key=True,
                                   autoincrement=True),
                     sa.Column('name', sa.String(length=255), nullable=False),
                     sa.Column('email', sa.String(length=255), nullable=False),
                     sa.Column('phone', sa.String(length=20),
                                   nullable=True),
                     sa.Column('role', sa.String(length=50),
                                   nullable=False),
                     sa.Column('address_id', sa.Integer(), sa.ForeignKey(
                            'Address.id'), nullable=True),
                     sa.Column('is_verified', sa.Boolean(), nullable=True),
                     sa.Column('created_at', sa.DateTime(), nullable=False,
                                   server_default=sa.func.now()),
                     sa.UniqueConstraint('email')
                     )

    # 新增 Address 模型
    if not conn.dialect.has_table(conn, 'Address'):
       op.create_table('Address',
                     sa.Column('id', sa.Integer(), primary_key=True,
                                   autoincrement=True),
                     sa.Column('street', sa.String(length=255), nullable=False),
                     sa.Column('city', sa.String(length=100), nullable=False),
                     sa.Column('postal_code', sa.String(
                            length=20), nullable=False),
                     sa.Column('created_at', sa.DateTime(), nullable=False,
                                   server_default=sa.func.now())
                     )


def downgrade():
    # 刪除新增的表
    op.drop_table('DeliveryPerson')
    op.drop_table('Vendor')
    op.drop_table('Address')
