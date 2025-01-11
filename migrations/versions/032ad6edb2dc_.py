from alembic import op
import sqlalchemy as sa

# Revision identifiers, used by Alembic.
revision = 'a66b148176e6'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Benennen Sie alle Constraints
    with op.batch_alter_table('order_tracking', schema=None) as batch_op:
        batch_op.create_unique_constraint('uq_order_number', ['order_number'])

    op.add_column('user', sa.Column('role', sa.String(length=50), nullable=False, server_default='user'))

def downgrade():
    op.drop_column('user', 'role')

    with op.batch_alter_table('order_tracking', schema=None) as batch_op:
        batch_op.drop_constraint('uq_order_number', type_='unique')