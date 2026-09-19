"""persist queued investigation lifecycle state"""
from alembic import op
import sqlalchemy as sa

revision = "0003_investigation_jobs"
down_revision = "0002_report_payload"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if "investigation_jobs" not in inspector.get_table_names():
        op.create_table(
            "investigation_jobs",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("url", sa.Text(), nullable=False),
            sa.Column("status", sa.String(30), nullable=False),
            sa.Column("context", sa.Text(), nullable=False),
            sa.Column("error", sa.Text()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True)),
        )
        op.create_index("ix_investigation_jobs_status", "investigation_jobs", ["status"])


def downgrade():
    op.drop_index("ix_investigation_jobs_status", table_name="investigation_jobs")
    op.drop_table("investigation_jobs")