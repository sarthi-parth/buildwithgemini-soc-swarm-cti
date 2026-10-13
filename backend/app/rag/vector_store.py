import sqlite3
import json
import math
import os
from typing import List, Dict, Any, Optional
from google.genai import Client
from app.config import settings

class VectorStore:
    def __init__(self, db_path: str = "./vector_store.db"):
        self.db_path = db_path
        self._init_db()

    def _get_genai_client(self) -> Optional[Client]:
        try:
            os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
            os.environ["GOOGLE_CLOUD_PROJECT"] = settings.GOOGLE_CLOUD_PROJECT
            os.environ["GOOGLE_CLOUD_LOCATION"] = settings.GOOGLE_CLOUD_LOCATION
            return Client()
        except Exception as e:
            print(f"[VectorStore] Failed to initialize Google GenAI Client: {e}")
            return None

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_documents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                source_url TEXT,
                doc_type TEXT,
                incident_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_chunks (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                content TEXT NOT NULL,
                embedding_json TEXT NOT NULL,
                metadata_json TEXT,
                FOREIGN KEY (document_id) REFERENCES knowledge_documents(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
        conn.close()

    def get_embedding(self, text: str) -> List[float]:
        client = self._get_genai_client()
        if client:
            try:
                resp = client.models.embed_content(
                    model=settings.EMBEDDING_MODEL,
                    contents=text[:8000]
                )
                if hasattr(resp, "embedding") and resp.embedding.values:
                    return resp.embedding.values
                elif hasattr(resp, "embeddings") and resp.embeddings:
                    return resp.embeddings[0].values
            except Exception as e:
                print(f"[VectorStore] GenAI embedding error: {e}. Falling back to pseudo-hash embedding.")
        
        # Deterministic fallback embedding for testing / offline resilience (dimension 128)
        dim = 128
        vec = [0.0] * dim
        for i, word in enumerate(text.lower().split()[:200]):
            idx = abs(hash(word)) % dim
            vec[idx] += 1.0 / (1.0 + (i * 0.05))
        norm = math.sqrt(sum(v*v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def add_document(self, doc_id: str, title: str, content: str, source_url: str = "", doc_type: str = "report", incident_id: str = "") -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO knowledge_documents (id, title, source_url, doc_type, incident_id)
            VALUES (?, ?, ?, ?, ?)
        """, (doc_id, title, source_url, doc_type, incident_id))

        # Chunk content (~600 chars with 100 overlap)
        chunks = []
        chunk_size = 600
        overlap = 100
        start = 0
        idx = 0
        while start < len(content):
            end = min(start + chunk_size, len(content))
            chunk_text = content[start:end].strip()
            if chunk_text:
                chunks.append((idx, chunk_text))
                idx += 1
            start += (chunk_size - overlap)
            if start >= len(content):
                break

        for c_idx, c_text in chunks:
            c_id = f"{doc_id}_{c_idx}"
            emb = self.get_embedding(c_text)
            meta = json.dumps({"source_url": source_url, "doc_type": doc_type, "incident_id": incident_id, "title": title})
            cursor.execute("""
                INSERT OR REPLACE INTO knowledge_chunks (id, document_id, chunk_index, content, embedding_json, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (c_id, doc_id, c_idx, c_text, json.dumps(emb), meta))

        conn.commit()
        conn.close()
        return len(chunks)

    def similarity_search(self, query: str, top_k: int = 4, filter_doc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        query_emb = self.get_embedding(query)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, document_id, chunk_index, content, embedding_json, metadata_json FROM knowledge_chunks")
        rows = cursor.fetchall()
        conn.close()

        scored = []
        for r_id, doc_id, c_idx, c_text, emb_json, meta_json in rows:
            meta = json.loads(meta_json) if meta_json else {}
            if filter_doc_type and meta.get("doc_type") != filter_doc_type:
                continue

            target_emb = json.loads(emb_json)
            # Cosine similarity
            if len(query_emb) == len(target_emb):
                dot = sum(a * b for a, b in zip(query_emb, target_emb))
                norm_a = math.sqrt(sum(a * a for a in query_emb)) or 1.0
                norm_b = math.sqrt(sum(b * b for b in target_emb)) or 1.0
                sim = dot / (norm_a * norm_b)
            else:
                sim = 0.0

            scored.append({
                "chunk_id": r_id,
                "document_id": doc_id,
                "content": c_text,
                "similarity": round(sim, 4),
                "metadata": meta,
            })

        scored.sort(key=lambda x: x["similarity"], reverse=True)
        return scored[:top_k]

    def count_stats(self) -> Dict[str, int]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM knowledge_documents")
        docs = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM knowledge_chunks")
        chunks = cursor.fetchone()[0]
        conn.close()
        return {"documents": docs, "chunks": chunks}

vector_store = VectorStore(settings.VECTOR_DB_PATH)
