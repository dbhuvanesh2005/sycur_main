from sycur_rag.core.config import get_settings
from sycur_rag.database import _connect


def main() -> None:
    settings = get_settings()

    dimension = settings.EMBEDDING_DIMENSION

    if dimension <= 0:
        raise ValueError(
            "EMBEDDING_DIMENSION must be positive."
        )

    with _connect() as connection:
        with connection.cursor() as cursor:
            print("Ensuring required extensions...")

            cursor.execute(
                """
                CREATE EXTENSION IF NOT EXISTS vector
                """
            )

            print("Adding scalable knowledge columns...")

            cursor.execute(
                """
                ALTER TABLE policy_chunks
                    ADD COLUMN IF NOT EXISTS domain TEXT,
                    ADD COLUMN IF NOT EXISTS layer TEXT,
                    ADD COLUMN IF NOT EXISTS framework TEXT,
                    ADD COLUMN IF NOT EXISTS language TEXT,
                    ADD COLUMN IF NOT EXISTS topic TEXT,
                    ADD COLUMN IF NOT EXISTS subtopic TEXT,
                    ADD COLUMN IF NOT EXISTS cwe_ids TEXT[]
                        DEFAULT ARRAY[]::TEXT[],
                    ADD COLUMN IF NOT EXISTS chunk_index INTEGER,
                    ADD COLUMN IF NOT EXISTS content_hash TEXT,
                    ADD COLUMN IF NOT EXISTS source_path TEXT,
                    ADD COLUMN IF NOT EXISTS active BOOLEAN
                        NOT NULL DEFAULT TRUE,
                    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ
                        NOT NULL DEFAULT CURRENT_TIMESTAMP
                """
            )

            print("Backfilling safe metadata defaults...")

            cursor.execute(
                """
                UPDATE policy_chunks
                SET
                    domain = COALESCE(
                        domain,
                        'web_application_security'
                    ),
                    framework = COALESCE(
                        framework,
                        'generic'
                    ),
                    language = COALESCE(
                        language,
                        'generic'
                    ),
                    cwe_ids = COALESCE(
                        cwe_ids,
                        ARRAY[]::TEXT[]
                    )
                """
            )

            print("Ensuring embedding dimension...")

            cursor.execute(
                f"""
                ALTER TABLE policy_chunks
                ALTER COLUMN embedding
                TYPE vector({dimension})
                USING embedding::vector({dimension})
                """
            )

            print("Creating full-text search column...")

            cursor.execute(
                """
                ALTER TABLE policy_chunks
                DROP COLUMN IF EXISTS search_vector
                """
            )

            cursor.execute(
                """
                ALTER TABLE policy_chunks
                ADD COLUMN search_vector TSVECTOR
                GENERATED ALWAYS AS (
                    to_tsvector(
                        'english'::regconfig,
                        COALESCE(title, '')
                        || ' '
                        || COALESCE(content, '')
                        || ' '
                        || COALESCE(section, '')
                        || ' '
                        || COALESCE(control_id, '')
                    )
                ) STORED
                """
            )

            print("Creating B-tree indexes...")

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_policy_chunks_document_name
                ON policy_chunks (document_name)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_policy_chunks_control_id
                ON policy_chunks (control_id)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_policy_chunks_content_hash
                ON policy_chunks (content_hash)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_policy_chunks_retrieval_metadata
                ON policy_chunks (
                    domain,
                    layer,
                    framework,
                    language,
                    topic
                )
                """
            )

            print("Creating GIN indexes...")

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_policy_chunks_search_vector_gin
                ON policy_chunks
                USING GIN (search_vector)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_policy_chunks_cwe_ids_gin
                ON policy_chunks
                USING GIN (cwe_ids)
                """
            )

            print("Creating HNSW vector index...")

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_policy_chunks_embedding_hnsw
                ON policy_chunks
                USING hnsw (
                    embedding vector_cosine_ops
                )
                WHERE embedding IS NOT NULL
                """
            )

    print()
    print(
        "🔥 SYCUR scalable knowledge "
        "schema migration completed"
    )


if __name__ == "__main__":
    main()