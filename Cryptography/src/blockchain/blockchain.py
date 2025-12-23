"""
Blockchain implementation for immutable audit trail
"""

import hashlib
import json
import time
from typing import List, Optional, Dict
from dataclasses import dataclass, asdict
from .merkle import MerkleTree


@dataclass
class Transaction:
    """Transaction in the blockchain"""
    type: str  # e.g., 'AUTH_LOGIN', 'FILE_ENCRYPT'
    data: dict  # Transaction data
    timestamp: float
    
    def to_dict(self) -> dict:
        """Convert transaction to dictionary"""
        return {
            'type': self.type,
            'data': self.data,
            'timestamp': self.timestamp
        }
    
    def hash(self) -> str:
        """Compute hash of transaction"""
        tx_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(tx_str.encode()).hexdigest()


@dataclass
class Block:
    """Block in the blockchain"""
    index: int
    previous_hash: str
    transactions: List[Transaction]
    timestamp: float
    nonce: int
    merkle_root: str
    hash: str = None
    
    def __post_init__(self):
        """Compute block hash after initialization"""
        if self.hash is None:
            self.hash = self.compute_hash()
    
    def compute_hash(self) -> str:
        """Compute block hash"""
        block_string = json.dumps({
            'index': self.index,
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'timestamp': self.timestamp,
            'nonce': self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def to_dict(self) -> dict:
        """Convert block to dictionary"""
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'merkle_root': self.merkle_root,
            'hash': self.hash
        }


class BlockchainModule:
    """
    Blockchain module for immutable audit trail.
    
    Features:
    - Block structure with previous hash and Merkle root
    - Merkle tree for transaction verification
    - Proof of Work consensus
    - Chain integrity verification
    """
    
    def __init__(self, difficulty: int = 4):
        """
        Initialize blockchain.
        
        Args:
            difficulty: Proof of Work difficulty (number of leading zeros)
        """
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.difficulty = difficulty
        self.target = '0' * difficulty + 'f' * (64 - difficulty)
        
        # Create genesis block
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_tx = Transaction(
            type='GENESIS',
            data={'message': 'CryptoVault Genesis Block'},
            timestamp=time.time()
        )
        
        genesis_block = Block(
            index=0,
            previous_hash='0' * 64,
            transactions=[genesis_tx],
            timestamp=time.time(),
            nonce=0,
            merkle_root=self._compute_merkle_root([genesis_tx])
        )
        
        # Mine genesis block
        genesis_block = self.mine_block(genesis_block)
        self.chain.append(genesis_block)
    
    def _compute_merkle_root(self, transactions: List[Transaction]) -> str:
        """
        Compute Merkle root of transactions.
        
        Args:
            transactions: List of transactions
            
        Returns:
            Merkle root hash
        """
        if not transactions:
            return '0' * 64
        
        tx_hashes = [tx.hash() for tx in transactions]
        merkle_tree = MerkleTree(tx_hashes)
        return merkle_tree.get_root()
    
    def add_transaction(self, transaction: Transaction):
        """
        Add transaction to pending pool.
        
        Args:
            transaction: Transaction to add
        """
        self.pending_transactions.append(transaction)
    
    def mine_block(self, block: Block) -> Block:
        """
        Mine block using Proof of Work.
        
        Finds nonce such that block hash < target.
        
        Args:
            block: Block to mine
            
        Returns:
            Mined block with valid nonce
        """
        while int(block.hash, 16) >= int(self.target, 16):
            block.nonce += 1
            block.hash = block.compute_hash()
        
        return block
    
    def create_block(self) -> Optional[Block]:
        """
        Create new block from pending transactions.
        
        Returns:
            New block, or None if no pending transactions
        """
        if not self.pending_transactions:
            return None
        
        previous_block = self.chain[-1]
        
        new_block = Block(
            index=len(self.chain),
            previous_hash=previous_block.hash,
            transactions=self.pending_transactions.copy(),
            timestamp=time.time(),
            nonce=0,
            merkle_root=self._compute_merkle_root(self.pending_transactions)
        )
        
        # Mine block
        new_block = self.mine_block(new_block)
        
        # Add to chain
        self.chain.append(new_block)
        
        # Clear pending transactions
        self.pending_transactions = []
        
        return new_block
    
    def verify_block(self, block: Block, previous_block: Block) -> bool:
        """
        Verify block validity.
        
        Args:
            block: Block to verify
            previous_block: Previous block in chain
            
        Returns:
            True if block is valid, False otherwise
        """
        # Check previous hash
        if block.previous_hash != previous_block.hash:
            return False
        
        # Check Merkle root
        computed_merkle_root = self._compute_merkle_root(block.transactions)
        if block.merkle_root != computed_merkle_root:
            return False
        
        # Check Proof of Work
        if int(block.hash, 16) >= int(self.target, 16):
            return False
        
        # Verify hash
        if block.hash != block.compute_hash():
            return False
        
        return True
    
    def verify_chain(self) -> bool:
        """
        Verify entire blockchain integrity.
        
        Returns:
            True if chain is valid, False otherwise
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            if not self.verify_block(current_block, previous_block):
                return False
        
        return True
    
    def get_block_by_index(self, index: int) -> Optional[Block]:
        """Get block by index"""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def get_transaction_proof(self, transaction: Transaction, block_index: int) -> Optional[dict]:
        """
        Generate Merkle proof for transaction inclusion.
        
        Args:
            transaction: Transaction to prove
            block_index: Index of block containing transaction
            
        Returns:
            Merkle proof dictionary, or None if transaction not found
        """
        block = self.get_block_by_index(block_index)
        if not block:
            return None
        
        tx_hashes = [tx.hash() for tx in block.transactions]
        if transaction.hash() not in tx_hashes:
            return None
        
        merkle_tree = MerkleTree(tx_hashes)
        proof = merkle_tree.generate_proof(transaction.hash())
        
        return {
            'proof': proof,
            'merkle_root': block.merkle_root,
            'block_index': block_index
        }
    
    def verify_transaction_proof(self, transaction: Transaction, proof: dict) -> bool:
        """
        Verify transaction inclusion proof.
        
        Args:
            transaction: Transaction to verify
            proof: Merkle proof dictionary
            
        Returns:
            True if proof is valid, False otherwise
        """
        tx_hash = transaction.hash()
        merkle_tree = MerkleTree([])
        return merkle_tree.verify_proof(tx_hash, proof['merkle_root'], proof['proof'])
    
    def log_event(self, event_type: str, event_data: dict):
        """
        Log security event to blockchain.
        
        Args:
            event_type: Type of event (e.g., 'AUTH_LOGIN')
            event_data: Event data dictionary
        """
        transaction = Transaction(
            type=event_type,
            data=event_data,
            timestamp=time.time()
        )
        
        self.add_transaction(transaction)
        
        # Auto-mine block if we have enough transactions
        # Changed to 1 so blocks are created immediately for demo purposes
        if len(self.pending_transactions) >= 1:
            self.create_block()
    
    def get_chain_data(self) -> List[dict]:
        """Get entire chain as list of dictionaries"""
        return [block.to_dict() for block in self.chain]
    
    def get_latest_block(self) -> Block:
        """Get latest block in chain"""
        return self.chain[-1]

