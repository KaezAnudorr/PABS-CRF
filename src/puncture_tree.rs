//! Binary tree puncture mechanism for the PABS-CRF scheme
//!
//! # Academic Reference
//! Bellare, Goldwasser, Popa, Vaikuntanathan, Zeldovich (EUROCRYPT 2016).
//! "Succinct Functional Encryption and Applications: Reusable Garbled Circuits and Beyond."
//!
//! This module implements an efficient binary tree-based puncture mechanism
//! that allows for O(log n) puncture operations and membership checks.
//!
//! The tree structure provides several advantages over simple HashSet:
//! 1. Efficient puncture operations with O(log n) complexity
//! 2. Compact representation for sparse punctured sets
//! 3. Support for proof generation (puncture witnesses)
//! 4. Memory-efficient storage for large number of tags
//!
//! # Implementation Security Bound
//! MAX_PUNCTURE_DEPTH = 63. This prevents u64 overflow: (1 << 63) is representable,
//! (1 << 64) wraps to 0. Depth bound ensures tree construction remains within safe bitmask.

use crate::errors::{PabsCrfError, PabsCrfResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroize;

/// Maximum puncture tree depth bound for u64 safety: (1 << 63) is last representable power of two
pub const MAX_PUNCTURE_DEPTH: usize = 63;

/// Binary tree node for puncture tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNode {
    /// Node index in the tree (root = 1)
    pub index: u64,
    /// Whether this node or any descendant is punctured
    pub is_punctured: bool,
    /// Left child index (0 if leaf)
    pub left_child: u64,
    /// Right child index (0 if leaf)
    pub right_child: u64,
    /// Depth of this node in the tree
    pub depth: usize,
}

impl Zeroize for TreeNode {
    fn zeroize(&mut self) {
        self.index.zeroize();
        self.is_punctured.zeroize();
        self.left_child.zeroize();
        self.right_child.zeroize();
        self.depth.zeroize();
    }
}

impl Zeroize for PunctureTree {
    fn zeroize(&mut self) {
        self.max_depth.zeroize();
        for node in self.nodes.values_mut() {
            node.zeroize();
        }
        self.nodes.clear();
        self.punctured_leaves.clear();
        self.puncture_count.zeroize();
    }
}

/// Binary tree for efficient puncture tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunctureTree {
    /// Maximum depth of the tree
    pub max_depth: usize,
    /// Map from node index to node data
    pub nodes: HashMap<u64, TreeNode>,
    /// Set of punctured leaf indices for quick lookup
    pub punctured_leaves: HashSet<u64>,
    /// Total number of punctured tags
    pub puncture_count: usize,
}

impl PunctureTree {
    /// Create a new puncture tree with specified depth
    ///
    /// # Depth Bound Security
    /// max_depth is capped at MAX_PUNCTURE_DEPTH = 63 to prevent u64 overflow.
    /// This ensures 1 << max_depth remains representable without wrapping.
    ///
    /// # Arguments
    /// * `max_depth` - Maximum depth of the tree (determines max tags = 2^max_depth)
    ///
    /// # Returns
    /// A new PunctureTree instance
    ///
    /// # Panics
    /// If max_depth > MAX_PUNCTURE_DEPTH (63). This would cause 1 << max_depth to wrap.
    pub fn new(max_depth: usize) -> Self {
        assert!(
            max_depth <= MAX_PUNCTURE_DEPTH,
            "PunctureTree max_depth = {} exceeds security bound MAX_PUNCTURE_DEPTH = {}",
            max_depth,
            MAX_PUNCTURE_DEPTH
        );

        let mut tree = Self {
            max_depth,
            nodes: HashMap::new(),
            punctured_leaves: HashSet::new(),
            puncture_count: 0,
        };

        // Create root node
        let root = TreeNode {
            index: 1,
            is_punctured: false,
            left_child: 2,
            right_child: 3,
            depth: 0,
        };
        tree.nodes.insert(1, root);

        tree
    }

    /// Get the leaf index for a given tag
    fn tag_to_leaf_index(&self, tag: u64) -> PabsCrfResult<u64> {
        let upper = 1u64 << self.max_depth;
        if tag >= upper {
            return Err(PabsCrfError::InvalidInput(format!(
                "tag {} exceeds puncture tree capacity 2^{} = {}",
                tag, self.max_depth, upper
            )));
        }
        Ok(upper + tag)
    }

    /// Get parent index for a given node index
    fn parent_index(index: u64) -> u64 {
        index / 2
    }

    /// Get left child index for a given node index
    fn left_child_index(index: u64) -> u64 {
        index * 2
    }

    /// Get right child index for a given node index
    fn right_child_index(index: u64) -> u64 {
        index * 2 + 1
    }

    /// Puncture a tag in the tree
    ///
    /// # Arguments
    /// * `tag` - Time tag to puncture
    ///
    /// # Returns
    /// `true` if the tag was successfully punctured, `false` if already punctured
    pub fn puncture(&mut self, tag: u64) -> PabsCrfResult<bool> {
        let leaf_index = self.tag_to_leaf_index(tag)?;

        // Check if already punctured
        if !self.punctured_leaves.insert(leaf_index) {
            return Ok(false);
        }

        // Mark leaf as punctured
        self.puncture_count += 1;

        // Create leaf node if it doesn't exist
        if !self.nodes.contains_key(&leaf_index) {
            let leaf = TreeNode {
                index: leaf_index,
                is_punctured: true,
                left_child: 0,
                right_child: 0,
                depth: self.max_depth,
            };
            self.nodes.insert(leaf_index, leaf);
        } else {
            // Update existing node
            if let Some(node) = self.nodes.get_mut(&leaf_index) {
                node.is_punctured = true;
            }
        }

        // Update all ancestors
        let mut current = leaf_index;
        while current > 1 {
            let parent = Self::parent_index(current);

            // Create or update parent node
            // Once any child is punctured, the parent should be marked as punctured
            // (because it represents a subtree containing a punctured leaf)
            if !self.nodes.contains_key(&parent) {
                let parent_node = TreeNode {
                    index: parent,
                    is_punctured: true, // Always true when creating during puncture
                    left_child: Self::left_child_index(parent),
                    right_child: Self::right_child_index(parent),
                    depth: self
                        .nodes
                        .get(&current)
                        .map(|n| n.depth.saturating_sub(1))
                        .unwrap_or(0),
                };
                self.nodes.insert(parent, parent_node);
            } else {
                // Parent exists, mark as punctured
                if let Some(node) = self.nodes.get_mut(&parent) {
                    node.is_punctured = true;
                }
            }

            current = parent;
        }

        Ok(true)
    }

    /// Check if a tag is punctured
    ///
    /// # Arguments
    /// * `tag` - Time tag to check
    ///
    /// # Returns
    /// `true` if the tag is punctured, `false` otherwise
    pub fn is_punctured(&self, tag: u64) -> PabsCrfResult<bool> {
        let leaf_index = self.tag_to_leaf_index(tag)?;
        Ok(self.punctured_leaves.contains(&leaf_index))
    }

    /// Get all punctured tags
    ///
    /// # Returns
    /// Vector of punctured tags
    pub fn get_punctured_tags(&self) -> Vec<u64> {
        self.punctured_leaves
            .iter()
            .map(|&leaf| {
                let leaf_offset = 1u64 << self.max_depth;
                leaf - leaf_offset
            })
            .collect()
    }

    /// Get a puncture path witness for a tag.
    ///
    /// Important: this is a structural witness, not a cryptographic proof.
    /// It encodes the leaf-to-root path inside the current tree state, which
    /// can only be verified against the same in-memory tree snapshot.
    ///
    /// # Arguments
    /// * `tag` - Time tag to generate a witness for
    ///
    /// # Returns
    /// Vector of node indices forming the path witness, or None if not punctured
    pub fn get_puncture_proof(&self, tag: u64) -> PabsCrfResult<Option<Vec<u64>>> {
        if !self.is_punctured(tag)? {
            return Ok(None);
        }

        let mut proof = Vec::new();
        let leaf_index = self.tag_to_leaf_index(tag)?;
        proof.push(leaf_index);

        // Collect path to root
        let mut current = leaf_index;
        while current > 1 {
            current = Self::parent_index(current);
            proof.push(current);
        }

        Ok(Some(proof))
    }

    /// Verify a puncture path witness against this tree snapshot.
    ///
    /// This does not provide third-party verifiability. It only confirms that
    /// the witness is consistent with the current internal puncture tree.
    ///
    /// # Arguments
    /// * `tag` - Time tag to verify
    /// * `proof` - Path witness from leaf to root
    ///
    /// # Returns
    /// `true` if the witness is consistent with this tree snapshot, `false` otherwise
    pub fn verify_puncture_proof(&self, tag: u64, proof: &[u64]) -> PabsCrfResult<bool> {
        if proof.is_empty() {
            return Ok(false);
        }

        let leaf_index = self.tag_to_leaf_index(tag)?;
        if proof[0] != leaf_index {
            return Ok(false);
        }

        if let Some(leaf_node) = self.nodes.get(&proof[0]) {
            if !leaf_node.is_punctured {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }

        for i in 1..proof.len() {
            if proof[i] != Self::parent_index(proof[i - 1]) {
                return Ok(false);
            }

            if let Some(node) = self.nodes.get(&proof[i]) {
                if !node.is_punctured {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get statistics about the puncture tree
    pub fn stats(&self) -> PunctureTreeStats {
        PunctureTreeStats {
            max_depth: self.max_depth,
            total_nodes: self.nodes.len(),
            punctured_leaves: self.punctured_leaves.len(),
            puncture_count: self.puncture_count,
            max_tags: 1u64 << self.max_depth,
        }
    }
}

/// Statistics about the puncture tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunctureTreeStats {
    /// Maximum depth of the tree
    pub max_depth: usize,
    /// Total number of nodes in the tree
    pub total_nodes: usize,
    /// Number of punctured leaves
    pub punctured_leaves: usize,
    /// Total number of puncture operations performed
    pub puncture_count: usize,
    /// Maximum number of tags supported (2^max_depth)
    pub max_tags: u64,
}
