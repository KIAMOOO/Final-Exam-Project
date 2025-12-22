"""
Tests for blockchain module
"""

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
        chain.log_event('TEST_EVENT', {'data': 'test'})
        assert len(chain.pending_transactions) == 1

