"""Ajout download_url

Revision ID: a2d9c2eb4879
Revises: d90d043a8651
Create Date: 2025-09-20 18:02:10.513768
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = 'a2d9c2eb4879'
down_revision = 'd90d043a8651'
branch_labels = None
depends_on = None

def upgrade():
    # 1. Ajouter la colonne en autorisant temporairement les NULL
    op.add_column('ressource', sa.Column('download_url', sa.String(length=500), nullable=True))

    # 2. Mettre à jour les anciennes lignes avec une valeur par défaut
    # Ici, on copie file_url → logique pour les anciens fichiers
    op.execute("UPDATE ressource SET download_url = file_url WHERE download_url IS NULL")

    # 3. Rendre la colonne NOT NULL maintenant que toutes les lignes ont une valeur
    op.alter_column('ressource', 'download_url', nullable=False)

def downgrade():
    # Supprimer la colonne à la rollback
    op.drop_column('ressource', 'download_url')