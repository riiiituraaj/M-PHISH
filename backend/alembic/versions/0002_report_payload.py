"""add serialized report payload for local compatibility"""
from alembic import op
import sqlalchemy as sa

revision = "0002_report_payload"
down_revision = "0001_core_tables"
branch_labels = None
depends_on = None

def upgrade():
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("investigations")}
    if "report" not in existing:
        op.add_column("investigations", sa.Column("report", sa.Text(), nullable=True))

def downgrade():
    op.drop_column("investigations", "report")
