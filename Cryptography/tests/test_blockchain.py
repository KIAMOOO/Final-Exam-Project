"""
Tests for blockchain module
"""

import sys
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pytest
from src.blockchain.blockchain import BlockchainModule, Transaction, Block
import time


class TestBlockchain:
    """Test blockchain functionality"""
    
    def test_create_blockchain(self):
        """Test blockchain creation"""
        chain = BlockchainModule(difficulty=2)
        assert len(chain.chain) == 1  # Genesis block
        assert chain.chain[0].index == 0
    
    def test_add_transaction(self):
        """Test adding transaction"""
        chain = BlockchainModule(difficulty=2)
        tx = Transaction(
            type='TEST',
            data={'test': 'data'},
            timestamp=time.time()
        )
        chain.add_transaction(tx)
        assert len(chain.pending_transactions) == 1
    
    def test_create_block(self):
        """Test block creation"""
        chain = BlockchainModule(difficulty=2)
        tx = Transaction(
            type='TEST',
            data={'test': 'data'},
            timestamp=time.time()
        )
        chain.add_transaction(tx)
        block = chain.create_block()
        assert block is not None
        assert len(chain.chain) == 2
        assert len(chain.pending_transactions) == 0
    
    def test_verify_chain(self):
        """Test chain verification"""
        chain = BlockchainModule(difficulty=2)
        tx = Transaction(
            type='TEST',
            data={'test': 'data'},
            timestamp=time.time()
        )
        chain.add_transaction(tx)
        chain.create_block()
        assert chain.verify_chain()
    
    def test_log_event(self):
        """Test event logging"""
        chain = BlockchainModule(difficulty=2)
        initial_block_count = len(chain.chain)
        chain.log_event('TEST_EVENT', {'data': 'test'})
        # log_event auto-mines blocks, so pending_transactions should be empty
        # but a new block should have been created
        assert len(chain.pending_transactions) == 0
        assert len(chain.chain) == initial_block_count + 1
        # Verify the event was logged in the latest block
        latest_block = chain.get_latest_block()
        assert len(latest_block.transactions) > 0
        assert latest_block.transactions[-1].type == 'TEST_EVENT'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

