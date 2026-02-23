// Keystone — Intelligence Layer (Embeddings)
//
// Leverages fastembed to generate local text embeddings for semantic search.
// We use a small, efficient embedding model (e.g., all-MiniLM-L6-v2) that
// runs entirely on CPU without requiring an external API or GPU setup.

use fastembed::{InitOptions, TextEmbedding, EmbeddingModel};
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};
use uuid::Uuid;
use crate::error::KeystoneError;

/// High-level service for semantic operations
#[derive(Clone)]
pub struct SemanticService {
    // Arc to allow cheap cloning across async tasks
    model: Arc<Mutex<TextEmbedding>>,
}

// Global cached instance to avoid loading the model multiple times
static SHARED_MODEL: OnceCell<Arc<Mutex<TextEmbedding>>> = OnceCell::const_new();

impl SemanticService {
    /// Initialize or retrieve the shared text embedding model
    pub async fn get_or_init() -> Result<Self, KeystoneError> {
        let model = SHARED_MODEL.get_or_try_init(|| async {
            tracing::info!("Initializing local AI embedding model (this may take a moment on first run)...");
            
            // We use the default model (BGE-Small-EN-v1.5 or all-MiniLM-L6-v2 depending on fastembed version)
            // It's downloaded to cache on first use.
            let init_options = InitOptions::new(EmbeddingModel::AllMiniLML6V2)
                .with_show_download_progress(true);
                
            let model = TextEmbedding::try_new(init_options)
                .map_err(|e| KeystoneError::Internal(format!("Failed to initialize embedding model: {}", e)))?;
                
            tracing::info!("Embedding model initialized successfully");
            Ok::<_, KeystoneError>(Arc::new(Mutex::new(model)))
        }).await?;

        Ok(Self { model: model.clone() })
    }

    /// Generate embeddings for a single piece of text
    pub async fn embed_text(&self, text: &str) -> Result<Vec<f32>, KeystoneError> {
        let mut locked_model = self.model.lock().await;
        let embeddings = locked_model
            .embed(vec![text], None)
            .map_err(|e| KeystoneError::Internal(format!("Failed to generate embedding: {}", e)))?;
            
        // embed() always returns a Vec of embeddings corresponding to the input vector
        embeddings.into_iter()
            .next()
            .ok_or_else(|| KeystoneError::Internal("No embedding generated".to_string()))
    }

    /// Calculate the cosine similarity between two unit vectors.
    /// Fastembed's models typically return normalized vectors, so
    /// dot product is mathematically equivalent to cosine similarity.
    pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return 0.0;
        }
        
        // Compute dot product
        let mut dot = 0.0;
        let mut norm_a = 0.0;
        let mut norm_b = 0.0;
        
        for (idx, &val_a) in a.iter().enumerate() {
            let val_b = b[idx];
            dot += val_a * val_b;
            norm_a += val_a * val_a;
            norm_b += val_b * val_b;
        }

        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }

        dot / (norm_a.sqrt() * norm_b.sqrt())
    }

    /// Rank candidates by semantic similarity to the query
    pub async fn search_best_matches(
        &self,
        query: &str,
        candidates: &[(Uuid, Vec<f32>)],
        limit: usize,
    ) -> Result<Vec<(Uuid, f32)>, KeystoneError> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let query_embedding = self.embed_text(query).await?;

        let mut results: Vec<(Uuid, f32)> = candidates
            .iter()
            .map(|(id, emb)| {
                let score = Self::cosine_similarity(&query_embedding, emb);
                (*id, score)
            })
            // Filter out wildly irrelevant matches (optional threshold)
            .filter(|&(_, score)| score > 0.1)
            .collect();

        // Sort descending by score
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        // Truncate to limit
        results.truncate(limit);

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((SemanticService::cosine_similarity(&a, &b) - 1.0).abs() < f32::EPSILON);
        
        let c = vec![0.0, 1.0, 0.0];
        assert!(SemanticService::cosine_similarity(&a, &c).abs() < f32::EPSILON);
        
        let d = vec![-1.0, 0.0, 0.0];
        assert!((SemanticService::cosine_similarity(&a, &d) - (-1.0)).abs() < f32::EPSILON);
    }
}
