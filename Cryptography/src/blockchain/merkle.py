"""
Merkle tree implementation for transaction verification
"""

import hashlib
from typing import List, Optional


class MerkleTree:
    """
    Merkle tree for efficient transaction verification.
    
    Features:
    - Build tree from transaction hashes
    - Generate Merkle proofs
    - Verify transaction inclusion
    - Handle odd number of leaves
    """
    
    def __init__(self, leaves: List[str]):
        """
        Initialize Merkle tree.
        
        Args:
            leaves: List of transaction hashes
        """
        self.leaves = leaves
        self.tree = self._build_tree(leaves)
        self.root = self.tree[-1][0] if self.tree else '0' * 64
    
    def _hash_pair(self, left: str, right: str) -> str:
        """
        Hash a pair of nodes.
        
        Args:
            left: Left node hash
            right: Right node hash
            
        Returns:
            Hash of concatenated pair
        """
        combined = left + right
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def _build_tree(self, leaves: List[str]) -> List[List[str]]:
        """
        Build Merkle tree from leaves.
        
        Args:
            leaves: List of leaf hashes
            
        Returns:
            Tree as list of levels (each level is a list of hashes)
        """
        if not leaves:
            return []
        
        tree = [leaves.copy()]
        current_level = leaves.copy()
        
        while len(current_level) > 1:
            next_level = []
            
            # Process pairs
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                next_level.append(self._hash_pair(left, right))
            
            tree.append(next_level)
            current_level = next_level
        
        return tree
    
    def get_root(self) -> str:
        """
        Get Merkle root hash.
        
        Returns:
            Root hash
        """
        return self.root
    
    def generate_proof(self, leaf_hash: str) -> List[dict]:
        """
        Generate Merkle proof for a leaf.
        
        Args:
            leaf_hash: Hash of leaf to prove
            
        Returns:
            List of proof nodes, each with 'hash' and 'position' ('left' or 'right')
        """
        if leaf_hash not in self.leaves:
            return []
        
        proof = []
        leaf_index = self.leaves.index(leaf_hash)
        current_index = leaf_index
        
        for level in self.tree[:-1]:  # Exclude root
            # Determine sibling position
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                position = 'right'
            else:
                sibling_index = current_index - 1
                position = 'left'
            
            # Handle odd-numbered levels: if sibling doesn't exist, duplicate current node
            if sibling_index >= len(level):
                # Last node in odd-numbered level - use itself as sibling (duplicated)
                sibling_index = current_index
                # If we're even-indexed and at the end, we're the right node, sibling is left (duplicate)
                if position == 'right':
                    position = 'left'
            
            # Add sibling to proof
            proof.append({
                'hash': level[sibling_index],
                'position': position
            })
            
            # Move to parent level
            current_index = current_index // 2
        
        return proof
    
    def verify_proof(self, leaf_hash: str, root_hash: str, proof: List[dict]) -> bool:
        """
        Verify Merkle proof.
        
        Args:
            leaf_hash: Hash of leaf being proven
            root_hash: Expected root hash
            proof: Merkle proof
            
        Returns:
            True if proof is valid, False otherwise
        """
        current_hash = leaf_hash
        
        for node in proof:
            if node['position'] == 'left':
                current_hash = self._hash_pair(node['hash'], current_hash)
            else:
                current_hash = self._hash_pair(current_hash, node['hash'])
        
        return current_hash == root_hash

