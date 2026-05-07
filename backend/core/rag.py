"""
Shared ChromaDB client and collection accessor.
Used by both the RAG agent (at scan time) and the ingest script (setup).
"""
import os

COLLECTION_NAME = "nvd_cves"
EMBED_MODEL = "all-MiniLM-L6-v2"


def get_collection():
    """Return the ChromaDB NVD collection, creating it if absent."""
    import chromadb
    from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

    host = os.getenv("CHROMA_HOST", "localhost")
    port = int(os.getenv("CHROMA_PORT", "8001"))

    client = chromadb.HttpClient(host=host, port=port)
    ef = SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL)

    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )


def is_available() -> bool:
    """Return True if ChromaDB is reachable."""
    try:
        import chromadb
        host = os.getenv("CHROMA_HOST", "localhost")
        port = int(os.getenv("CHROMA_PORT", "8001"))
        chromadb.HttpClient(host=host, port=port).heartbeat()
        return True
    except Exception:
        return False
