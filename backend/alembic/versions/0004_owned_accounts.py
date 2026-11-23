"""Private accounts, expiring sessions and transactional job outbox.

Legacy anonymous tables are intentionally quarantined: there is no safe owner to
assign existing records to automatically. They remain available to offline admins.
"""
from alembic import op
from backend.app.core.storage import metadata
revision = '0004_owned_accounts'
down_revision = '0003_investigation_jobs'
branch_labels = None
depends_on = None
def upgrade():
    metadata.create_all(op.get_bind())
def downgrade():
    metadata.drop_all(op.get_bind())
