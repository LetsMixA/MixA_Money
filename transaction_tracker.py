import uuid
import time
from datetime import datetime
from web3 import Web3

class TransactionTracker:
    def __init__(self):
        self.transactions = {}
        self.web3 = Web3(Web3.HTTPProvider('https://api.avax-test.network/ext/bc/C/rpc'))
    
    def fund_wallet(self, user_address, admin_private_key, amount_ether=0.1):
        """
        Send funds to a user wallet from the admin wallet
        """
        tx_id = str(uuid.uuid4())
        self.transactions[tx_id] = {
            'type': 'fund',
            'status': 'pending',
            'created_at': datetime.utcnow(),
            'user_address': user_address,
            'amount_ether': amount_ether,
            'error': None
        }
        
        try:
            # Validate address
            user_address = Web3.to_checksum_address(user_address)
            
            # Create admin account from private key
            admin_account = self.web3.eth.account.from_key(admin_private_key)
            admin_address = admin_account.address
            
            # Check admin balance
            admin_balance = self.web3.eth.get_balance(admin_address)
            amount_wei = self.web3.to_wei(amount_ether, 'ether')
            
            if admin_balance < amount_wei + self.web3.to_wei(0.01, 'ether'):
                self.transactions[tx_id]['status'] = 'failed'
                self.transactions[tx_id]['error'] = 'Insufficient admin balance'
                return {
                    'success': False, 
                    'error': 'Insufficient admin balance', 
                    'tx_id': tx_id
                }
            
            # Get nonce for admin account
            nonce = self.web3.eth.get_transaction_count(admin_address, 'pending')
            
            # Build transaction
            tx = {
                'nonce': nonce,
                'to': user_address,
                'value': amount_wei,
                'gas': 21000,
                'maxFeePerGas': self.web3.to_wei('50', 'gwei'),
                'maxPriorityFeePerGas': self.web3.to_wei('2', 'gwei'),
                'chainId': 43113,  # Avalanche Fuji Testnet
                'type': 2  # EIP-1559
            }
            
            # Sign transaction
            signed_tx = self.web3.eth.account.sign_transaction(tx, admin_account.key)
            
            # Send transaction
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            
            # Update transaction record
            self.transactions[tx_id]['tx_hash'] = tx_hash_hex
            self.transactions[tx_id]['status'] = 'submitted'
            
            return {
                'success': True,
                'tx_hash': tx_hash_hex,
                'tx_id': tx_id,
                'message': f'Funding transaction submitted: {tx_hash_hex}'
            }
            
        except Exception as e:
            self.transactions[tx_id]['status'] = 'failed'
            self.transactions[tx_id]['error'] = str(e)
            return {'success': False, 'error': str(e), 'tx_id': tx_id}
    
    def get_transaction_status(self, tx_id):
        """
        Get status of a transaction by its internal ID
        """
        if tx_id not in self.transactions:
            return {'error': 'Transaction not found'}
        
        tx_data = self.transactions[tx_id].copy()
        
        # If transaction is submitted but not confirmed, check blockchain
        if tx_data['status'] == 'submitted' and 'tx_hash' in tx_data:
            try:
                receipt = self.web3.eth.get_transaction_receipt(tx_data['tx_hash'])
                if receipt:
                    if receipt['status'] == 1:
                        tx_data['status'] = 'confirmed'
                        self.transactions[tx_id]['status'] = 'confirmed'
                        self.transactions[tx_id]['block_number'] = receipt['blockNumber']
                        self.transactions[tx_id]['confirmed_at'] = datetime.utcnow()
                    else:
                        tx_data['status'] = 'failed'
                        self.transactions[tx_id]['status'] = 'failed'
                        self.transactions[tx_id]['error'] = 'Transaction failed on chain'
            except Exception as e:
                # Don't update status if we can't get the receipt - likely still pending
                tx_data['blockchain_error'] = str(e)
        
        # Convert datetime to string for JSON
        if 'created_at' in tx_data:
            tx_data['created_at'] = tx_data['created_at'].isoformat()
        if 'confirmed_at' in tx_data:
            tx_data['confirmed_at'] = tx_data['confirmed_at'].isoformat()
            
        return tx_data
