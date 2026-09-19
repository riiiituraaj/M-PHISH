"""create core investigation tables"""
from alembic import op
import sqlalchemy as sa

revision = "0001_core_tables"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    inspector = sa.inspect(op.get_bind())
    if "investigations" not in inspector.get_table_names():
        op.create_table("investigations", sa.Column("id", sa.String(36), primary_key=True), sa.Column("url", sa.Text(), nullable=False), sa.Column("status", sa.String(20), nullable=False), sa.Column("risk_score", sa.Integer()), sa.Column("classification", sa.String(30)), sa.Column("summary", sa.Text()), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True)))
        op.create_index("ix_investigations_created_at", "investigations", ["created_at"])
    else:
        existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("investigations")}
        if "summary" not in existing: op.add_column("investigations", sa.Column("summary", sa.Text()))
        if "completed_at" not in existing: op.add_column("investigations", sa.Column("completed_at", sa.DateTime(timezone=True)))
    if "evidence" not in inspector.get_table_names():
        op.create_table("evidence", sa.Column("id", sa.String(36), primary_key=True), sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False), sa.Column("category", sa.String(20), nullable=False), sa.Column("title", sa.String(200), nullable=False), sa.Column("description", sa.Text()), sa.Column("source", sa.String(100)), sa.Column("confidence", sa.Float()), sa.Column("severity", sa.String(20)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
        op.create_index("ix_evidence_investigation_id", "evidence", ["investigation_id"])

def downgrade():
    op.drop_table("evidence")
    op.drop_index("ix_investigations_created_at", table_name="investigations")
    op.drop_table("investigations")
