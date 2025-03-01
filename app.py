import time

import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps
import base64
from PIL import Image
import io
from web3 import Web3
import requests
import json

# Import MixANFT ABI
with open('artifacts/contracts/MixANFT.sol/MixANFT.json', 'r') as f:
    contract_json = json.load(f)
    MixANFTABI = contract_json['abi']

app = Flask(__name__)
app.secret_key = 'mixanft-secure-key-12345'  # Using a fixed key instead of random
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to False for development
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Allow cookies to be sent with redirects
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_USE_SIGNER'] = False  # Disable signing for compatibility
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions in files for reliability
app.config['SESSION_FILE_DIR'] = '/tmp/flask_session'
app.config['SESSION_FILE_THRESHOLD'] = 500  # Maximum number of sessions stored

# Create session directory if it doesn't exist
import os
if not os.path.exists('/tmp/flask_session'):
    os.makedirs('/tmp/flask_session')

# Configure SQLAlchemy
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'pending_mints.db')
os.makedirs(os.path.dirname(db_path), exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Configure Web3
AVALANCHE_TESTNET_RPC = "https://api.avax-test.network/ext/bc/C/rpc"
web3 = Web3(Web3.HTTPProvider(AVALANCHE_TESTNET_RPC))
CONTRACT_ADDRESS = "0x1E8461598caf86db994a0395A9389716e99f6d87"

# Pinata Configuration
PINATA_JWT = os.getenv('PINATA_JWT')

def validate_mint_request(data):
    try:
        if not Web3.is_address(data['owner']):
            return {'success': False, 'error': 'Invalid wallet address'}

        if not data['tokenURI'].startswith('ipfs://'):
            return {'success': False, 'error': 'Invalid tokenURI format'}

        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        app.logger.info(f"Session in decorator: {dict(session)}")

        # Check if the user is authenticated in session
        if 'wallet_address' in session:
            app.logger.info(f"User authenticated with wallet: {session['wallet_address']}")
            return f(*args, **kwargs)

        # Check for wallet in cookies as a backup auth method
        wallet_from_cookie = request.cookies.get('user_wallet')
        if wallet_from_cookie and Web3.is_address(wallet_from_cookie):
            app.logger.info(f"User authenticated via cookie: {wallet_from_cookie}")
            session['wallet_address'] = wallet_from_cookie
            session.modified = True
            return f(*args, **kwargs)

        # Check for wallet address in query parameters (alternative authentication)
        wallet_addr = request.args.get('wallet')
        if wallet_addr and Web3.is_address(wallet_addr):
            app.logger.info(f"User authenticated via query param: {wallet_addr}")
            session['wallet_address'] = wallet_addr
            session.modified = True
            return f(*args, **kwargs)

        # Check localStorage via JS redirect
        if not request.args.get('noLocalStorage'):
            return redirect(url_for('check_local_storage'))

        # No session, redirect to login page directly
        app.logger.warning("No wallet_address in session, redirecting to login")
        return redirect(url_for('login', noAutoLogin='true'))

    return decorated_function

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/check-local-storage')
def check_local_storage():
    """Route to check localStorage for wallet address through JS"""
    return render_template('check_local_storage.html')

@app.route('/auth/login', methods=['POST'])
def auth_login():
    if not request.is_json:
        return jsonify({'error': 'Missing JSON data'}), 400

    data = request.get_json()
    if 'address' not in data:
        return jsonify({'error': 'Missing wallet address'}), 400

    user_address = data['address']

    # Set session with max age and secure flags
    session.clear()  # Clear any existing session data
    session['wallet_address'] = user_address
    session.permanent = True

    # Create a session cookie that works better with browsers
    app.config['SESSION_COOKIE_SECURE'] = False  # Disable for testing
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Set a strong session cookie
    session.permanent = True

    # Log the login attempt
    app.logger.info(f'User logged in with wallet: {user_address}')
    app.logger.info(f'Session data after setting: {dict(session)}')

    # Ensure session is saved immediately
    session.modified = True

    # Return a standard JSON response
    response = jsonify({
        'success': True,
        'message': 'Login successful',
        'wallet_address': user_address,
        'redirect': url_for('camera')
    })

    # Add specific headers to prevent caching
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    # Set an explicit cookie to help with session persistence
    response.set_cookie('user_wallet', user_address, max_age=3600, httponly=True, samesite='Lax')

    app.logger.info(f'Auth login completed successfully for {user_address}')
    return response

@app.route('/')
def index():
    if 'wallet_address' in session:
        return redirect(url_for('camera'))
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # Clear specific session variables
    session.pop('wallet_address', None)
    # Force session to be removed
    session.modified = True
    session.clear()
    return redirect(url_for('login'), code=302)

@app.route('/camera')
@login_required
def camera():
    try:
        if not os.path.exists(UPLOAD_DIR):
            os.makedirs(UPLOAD_DIR, exist_ok=True)

        # Debug log to verify wallet address is in session
        wallet_address = session.get("wallet_address")
        app.logger.info(f'Loading camera page for user: {wallet_address}')

        # Ensure session is properly saved
        session.modified = True

        return render_template('camera.html',
                            pinata_jwt=PINATA_JWT,
                            wallet_address=wallet_address)
    except Exception as e:
        app.logger.error(f'Error accessing camera page: {str(e)}')
        return jsonify({'error': f'Camera initialization error: {str(e)}'}), 500

@app.route('/capture-video', methods=['POST'])
@login_required
def capture_video():
    try:
        if 'video' not in request.files:
            return jsonify({'error': 'No video file'}), 400

        video_file = request.files['video']
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'video_{timestamp}.webm'
        filepath = os.path.join(UPLOAD_DIR, filename)

        video_file.save(filepath)

        return jsonify({
            'path': f'/static/uploads/{filename}',
            'message': 'Video captured successfully'
        })
    except Exception as e:
        app.logger.error(f"Error capturing video: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/capture', methods=['POST'])
@login_required
def capture():
    try:
        # Check if the file is in the request
        if 'file' not in request.files:
            app.logger.error("No file part in the request")
            return jsonify({'error': 'No image file provided'}), 400

        # Get file from request
        file = request.files['file']
        
        # Basic validation
        if file.filename == '':
            app.logger.error("Empty filename")
            return jsonify({'error': 'No selected file'}), 400
            
        # Check content type
        content_type = file.content_type
        if not content_type or not content_type.startswith('image/'):
            app.logger.error(f"Invalid content type: {content_type}")
            return jsonify({'error': f'Invalid content type: {content_type}'}), 400
            
        app.logger.info(f"Received file: {file.filename}, content type: {content_type}")
        
        # Read file data directly
        image_bytes = file.read()
        
        if len(image_bytes) < 100:  # Arbitrary minimum size check
            app.logger.error(f"Image data too small: {len(image_bytes)} bytes")
            return jsonify({'error': 'Image data too small to be valid'}), 400
                
        try:
            # Reset file pointer to start
            file.seek(0)
            
            # Open with PIL to validate image
            image = Image.open(file)
            
            # Try to load the image to verify it's valid
            image.load()
            
            app.logger.info(f"Successfully opened image: format={image.format}, size={image.size}, mode={image.mode}")
            
            # Additional validation
            if not image.format:
                app.logger.error("Image format not detected")
                return jsonify({'error': 'Unknown image format'}), 400
                
            if image.format.lower() not in ['jpeg', 'jpg', 'png']:
                app.logger.error(f"Unsupported image format: {image.format}")
                return jsonify({'error': f'Unsupported image format: {image.format}'}), 400
                
        except Exception as img_error:
            app.logger.error(f"Image processing error: {str(img_error)}")
            return jsonify({'error': f'Invalid image data: {str(img_error)}'}), 400

        # Create the upload directory if it doesn't exist
        if not os.path.exists(UPLOAD_DIR):
            os.makedirs(UPLOAD_DIR, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'capture_{timestamp}.jpg'
        filepath = os.path.join(UPLOAD_DIR, filename)

        # Reset file pointer again and save the file
        file.seek(0)
        file.save(filepath)
        
        # Also save with PIL for consistency (provides better control)
        image.save(filepath, format='JPEG', quality=95)
        app.logger.info(f"Photo captured successfully: {filename}")

        return jsonify({
            'path': f'/static/uploads/{filename}',
            'message': 'Photo captured successfully'
        })
    except Exception as e:
        app.logger.error(f"Error capturing photo: {str(e)}")
        return jsonify({'error': f'Error capturing photo: {str(e)}'}), 500

@app.route('/prepare-mint', methods=['POST'])
@login_required
def prepare_mint():
    try:
        # Check environment variables
        admin_key = os.getenv('ADMIN_PRIVATE_KEY')
        pinata_jwt = os.getenv('PINATA_JWT')

        if not admin_key or not pinata_jwt:
            app.logger.error('Missing required environment variables')
            return jsonify({'error': 'Server configuration error'}), 500

        if 'image' not in request.files:
            return jsonify({'error': 'No image file'}), 400

        if 'userAddress' not in request.form:
            return jsonify({'error': 'No user address provided'}), 400

        app.logger.info(f'Starting mint process for address: {request.form["userAddress"]}')

        # Create pending mint record first
        pending_mint = PendingMint(
            owner=request.form['userAddress'],
            ipfs_hash='pending',
            metadata_url='pending',  # Initialize with pending value
            status='uploading'
        )
        db.session.add(pending_mint)
        db.session.commit()

        image_file = request.files['image']
        user_address = web3.to_checksum_address(request.form['userAddress'])

        # Upload to IPFS using Pinata with JWT
        # Reset file pointer
        image_file.seek(0)
        
        # Create a temporary file for Pinata upload if needed
        temp_file_path = os.path.join(UPLOAD_DIR, f'temp_{datetime.now().strftime("%Y%m%d_%H%M%S")}.jpg')
        image_file.save(temp_file_path)
        
        # Use multipart/form-data with the actual file
        with open(temp_file_path, 'rb') as f:
            files = {
                'file': ('image.jpg', f, 'image/jpeg')
            }
            headers = {
                'Authorization': f'Bearer {PINATA_JWT}'
            }
            
            pinata_response = requests.post(
                'https://api.pinata.cloud/pinning/pinFileToIPFS',
                files=files,
                headers=headers,
                timeout=30
            )
            
        # Clean up temporary file
        try:
            os.remove(temp_file_path)
        except:
            pass

        if not pinata_response.ok:
            app.logger.error(f'Pinata upload failed: {pinata_response.text}')
            raise Exception(f'Failed to upload image to IPFS: {pinata_response.text}')

        if not pinata_response.ok:
            raise Exception('Failed to upload image to IPFS')

        ipfs_result = pinata_response.json()
        ipfs_hash = ipfs_result['IpfsHash']
        image_ipfs_url = f'ipfs://{ipfs_hash}'

        # Verify content is accessible
        verify_url = f'https://gateway.pinata.cloud/ipfs/{ipfs_hash}'
        verify_response = requests.get(verify_url, timeout=30)
        if not verify_response.ok:
            raise Exception('Content not accessible on IPFS')

        # Create metadata following ERC721 standard strictly
        timestamp = int(datetime.utcnow().timestamp())
        content_type = verify_response.headers.get('content-type', '')
        is_video = content_type.startswith('video/')

        metadata = {
            'name': f'PixA NFT #{timestamp}',
            'description': f'Captured with PixA Camera ({content_type})',
            'image': image_ipfs_url,
            'external_url': f'https://gateway.pinata.cloud/ipfs/{ipfs_hash}',
            'attributes': [],
            'background_color': '',
            'animation_url': image_ipfs_url if is_video else '',
            'youtube_url': ''
        }

        # Upload metadata to IPFS
        metadata_headers = {
            'Authorization': f'Bearer {PINATA_JWT}',
            'Content-Type': 'application/json'
        }

        metadata_response = requests.post(
            'https://api.pinata.cloud/pinning/pinJSONToIPFS',
            json=metadata,
            headers=metadata_headers
        )

        if not metadata_response.ok:
            app.logger.error(f'Metadata upload failed: {metadata_response.text}')
            raise Exception('Failed to upload metadata to IPFS')

        metadata_result = metadata_response.json()
        metadata_url = f'ipfs://{metadata_result["IpfsHash"]}'

        # Log the IPFS data for verification
        app.logger.info(f'Content IPFS Hash: {ipfs_hash}')
        app.logger.info(f'Content IPFS URL: {image_ipfs_url}')
        app.logger.info(f'Metadata IPFS Hash: {metadata_result["IpfsHash"]}')

        # Verify content type is image or video
        content_type = verify_response.headers.get('content-type', '')
        is_video = content_type.startswith('video/')
        is_image = content_type.startswith('image/')
        if not (is_video or is_image):
            raise Exception(f'Invalid content type: {content_type}')

        # Use multiple gateways for verification
        gateways = [
            "https://gateway.pinata.cloud/ipfs/",
            "https://ipfs.io/ipfs/",
            "https://dweb.link/ipfs/"
        ]
        # Longer timeouts and more retries for videos
        max_retries = 5 if is_video else 3
        retry_delay = 5 if is_video else 2
        timeout = 30 if is_video else 10
        verified = False

        for gateway in gateways:
            verify_url = f"{gateway}{metadata_result['IpfsHash']}"
            for attempt in range(max_retries):
                try:
                    verify_response = requests.get(verify_url, timeout=timeout)
                    if verify_response.ok:
                        verified_metadata = verify_response.json()
                        # Verify required fields
                        if all(key in verified_metadata for key in ['name', 'description', 'image']):
                            # Verify image accessibility
                            image_hash = verified_metadata['image'].replace('ipfs://', '')
                            content_verified = False
                            for img_gateway in gateways:
                                content_url = f"{img_gateway}{image_hash}"
                                content_check = requests.head(content_url, timeout=timeout)
                                content_type = content_check.headers.get('content-type', '')
                                if content_check.ok and (content_type.startswith(('image/')) or content_type.startswith(('video/', 'application/octet-stream'))):
                                    content_verified = True
                                    break
                            if content_verified:
                                verified = True
                                break
                except Exception as e:
                    app.logger.warning(f"Verification attempt failed: {str(e)}")
                time.sleep(retry_delay)
            if verified:
                break

        if not verified:
            raise Exception('Failed to verify complete metadata and image accessibility')

        # Add extra propagation delay
        time.sleep(5)

        # Validate metadata format
        verified_metadata = verify_response.json()
        if not all(key in verified_metadata for key in ['name', 'description', 'image']):
            raise Exception('Metadata missing required fields')

        app.logger.info(f'Verified metadata: {verified_metadata}')

        # Update pending mint record with verified metadata
        pending_mint.ipfs_hash = ipfs_hash
        pending_mint.metadata_url = metadata_url
        pending_mint.status = 'verified'
        db.session.commit()

        # Initialize contract with admin wallet for minting
        contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=MixANFTABI)
        admin_address = '0xe3Bf624f20C5a1991B7185eAcA4c30da3C831698'
        admin_account = web3.eth.account.from_key(os.getenv('ADMIN_PRIVATE_KEY'))

        if admin_account.address.lower() != admin_address.lower():
            raise Exception('Invalid admin wallet - must use contract deployer wallet')

        # Get latest nonce and gas price
        # Get latest nonce for admin account
        latest_nonce = web3.eth.get_transaction_count(admin_address, 'pending')
        gas_price = web3.eth.gas_price

        # First handle funding transaction if needed
        user_balance = web3.eth.get_balance(user_address)
        if user_balance < web3.to_wei(0.009, 'ether'):
            funding_tx = {
                'nonce': latest_nonce,
                'to': user_address,
                'value': web3.to_wei(0.1, 'ether'),
                'gas': 21000,
                'gasPrice': gas_price,
                'chainId': 43113
            }
            # Sign and send funding transaction
            signed_funding_tx = web3.eth.account.sign_transaction(funding_tx, admin_account.key)
            funding_tx_hash = web3.eth.send_raw_transaction(signed_funding_tx.rawTransaction)
            web3.eth.wait_for_transaction_receipt(funding_tx_hash)
            latest_nonce += 1

        # Then build mint transaction with updated nonce
        mint_txn = contract.functions.mint(
            web3.to_checksum_address(user_address),  # Recipient is the connected user

            metadata_url
        ).build_transaction({
            'from': admin_address,  # Explicitly set sender as admin
            'chainId': 43113,  # Avalanche Fuji Testnet
            'gas': 300000,
            'maxFeePerGas': web3.to_wei('50', 'gwei'),
            'maxPriorityFeePerGas': web3.to_wei('2', 'gwei'),
            'nonce': latest_nonce,
            'type': 2  # EIP-1559 transaction
        })

        # Get latest nonce for mint transaction
        latest_nonce = web3.eth.get_transaction_count(admin_account.address, 'pending')
        mint_txn['nonce'] = latest_nonce

        # Sign and send mint transaction
        signed_txn = web3.eth.account.sign_transaction(mint_txn, admin_account.key)
        tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        app.logger.info(f'Mint transaction sent with hash: {tx_hash.hex()}')

        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        app.logger.info(f'Mint transaction confirmed: {tx_receipt["status"]}')

        # Update pending mint status after successful minting
        pending_mint.status = 'minted'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'NFT minted successfully',
            'transactionHash': tx_receipt['transactionHash'].hex(),
            'tokenURI': metadata_url,
            'mintId': pending_mint.id
        })

    except Exception as e:
        app.logger.error(f'Error minting NFT: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/photo/details', methods=['GET'])
def get_photo_details():
    try:
        photo_path = request.args.get('path')
        if not photo_path:
            return jsonify({'error': 'No photo path provided'}), 400

        # Query the pending_mints table for this photo
        pending_mint = PendingMint.query.filter_by(ipfs_hash=photo_path.split('_')[1].split('.')[0]).first()

        if pending_mint:
            return jsonify({
                'token_id': pending_mint.id,
                'minter_address': pending_mint.owner,
                'status': pending_mint.status
            })

        return jsonify({
            'token_id': None,
            'minter_address': None,
            'status': 'not_minted'
        })

    except Exception as e:
        app.logger.error(f'Error getting photo details: {str(e)}')
        return jsonify({'error': str(e)}), 500

# Create upload directory with proper permissions
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
try:
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.chmod(UPLOAD_DIR, 0o777)
except Exception as e:
    app.logger.error(f"Error setting up upload directory: {str(e)}")

# Define PendingMint model
class PendingMint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(42), nullable=False)
    ipfs_hash = db.Column(db.String(64), nullable=False)
    metadata_url = db.Column(db.String(128))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verification_attempts = db.Column(db.Integer, default=0)

# Create tables
with app.app_context():
    try:
        db.create_all()
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'pending_mints.db')
        if os.path.exists(db_path):
            os.chmod(db_path, 0o666)
    except Exception as e:
        app.logger.error(f"Database initialization error: {str(e)}")


@app.route('/photos')
def get_photos():
    try:
        media = []
        if not os.path.exists(UPLOAD_DIR):
            return jsonify([])

        for filename in os.listdir(UPLOAD_DIR):
            if filename.startswith(('capture_', 'video_')):
                filepath = os.path.join(UPLOAD_DIR, filename)
                if os.path.isfile(filepath):
                    media_type = 'video' if filename.startswith('video_') else 'photo'
                    try:
                        media.append({
                            'id': filename.split('_')[1].split('.')[0],
                            'path': f'/static/uploads/{filename}',
                            'type': media_type,
                            'timestamp': os.path.getctime(filepath)
                        })
                    except Exception as e:
                        app.logger.error(f'Error processing file {filename}: {str(e)}')
                        continue

        return jsonify(sorted(media, key=lambda x: x['timestamp'], reverse=True))
    except Exception as e:
        app.logger.error(f'Error getting photos: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/gallery')
@login_required
def gallery():
    return render_template('gallery.html', wallet_address=session.get('wallet_address'))

@app.route('/profile/<wallet_address>')
def profile(wallet_address):
    return render_template('profile.html', wallet_address=wallet_address)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Use environment variables or default to production settings
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=debug_mode)

def validate_mint_request(data):
    try:
        if not Web3.is_address(data['owner']):
            return {'success': False, 'error': 'Invalid wallet address'}

        if not data['tokenURI'].startswith('ipfs://'):
            return {'success': False, 'error': 'Invalid tokenURI format'}

        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

# Initialize transaction tracker
from transaction_tracker import TransactionTracker
transaction_tracker = TransactionTracker()

@app.route('/check_admin_wallet', methods=['GET'])
def check_admin_wallet():
    try:
        web3 = Web3(Web3.HTTPProvider('https://api.avax-test.network/ext/bc/C/rpc'))
        admin_private_key = os.getenv('ADMIN_PRIVATE_KEY')

        if not admin_private_key:
            return jsonify({'error': 'Admin private key not configured'}), 500

        admin_account = web3.eth.account.from_key(admin_private_key)
        admin_balance = web3.eth.get_balance(admin_account.address)

        # Also check if we can fetch current gas prices
        try:
            gas_price = web3.eth.gas_price
            gas_price_gwei = web3.from_wei(gas_price, 'gwei')
        except Exception as e:
            gas_price_gwei = f"Error fetching gas price: {str(e)}"

        return jsonify({
            'admin_address': admin_account.address,
            'admin_balance_avax': web3.from_wei(admin_balance, 'ether'),
            'admin_balance_wei': admin_balance,
            'gas_price_gwei': gas_price_gwei,
            'network_connected': True
        })
    except Exception as e:
        return jsonify({'error': str(e), 'network_connected': False}), 500

@app.route('/fund_wallet', methods=['POST'])
def fund_wallet():
    try:
        if not request.is_json:
            return jsonify({'error': 'Missing JSON data'}), 400

        data = request.get_json()
        if 'address' not in data:
            return jsonify({'error': 'Missing wallet address'}), 400

        # Get the admin private key
        admin_private_key = os.getenv('ADMIN_PRIVATE_KEY')
        if not admin_private_key:
            return jsonify({'error': 'Admin private key not configured'}), 500

        # Use the transaction tracker
        result = transaction_tracker.fund_wallet(
            user_address=data['address'],
            admin_private_key=admin_private_key,
            amount_ether=0.1
        )

        if result['success']:
            return jsonify({
                'success': True,
                'transaction_hash': result.get('tx_hash'),
                'tx_id': result['tx_id'],
                'message': result.get('message', 'Funding transaction submitted')
            })
        else:
            app.logger.error(f'Funding failed: {result["error"]}')
            return jsonify({
                'success': False,
                'error': result['error'],
                'tx_id': result['tx_id']
            }), 500

    except Exception as e:
        app.logger.error(f'Failed to fund wallet: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/transaction_status/<tx_id>', methods=['GET'])
def transaction_status(tx_id):
    status = transaction_tracker.get_transaction_status(tx_id)
    if 'error' in status:
        return jsonify(status), 404
    return jsonify(status)

MixANFTABI = [
    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "to",
                "type": "address"
            },
            {
                "internalType": "string",
                "name": "tokenURI",
                "type": "string"
            }
        ],
        "name": "mint",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]
@app.route('/check_wallet_status', methods=['POST'])
def check_wallet_status():
    if not request.is_json:
        return jsonify({'error': 'Missing JSON data'}), 400

    data = request.get_json()
    if 'address' not in data:
        return jsonify({'error': 'Missing wallet address'}), 400

    user_address = Web3.to_checksum_address(data['address'])
    web3 = Web3(Web3.HTTPProvider('https://api.avax-test.network/ext/bc/C/rpc'))

    try:
        balance = web3.eth.get_balance(user_address)
        return jsonify({
            'success': True,
            'address': user_address,
            'balance': web3.from_wei(balance, 'ether'),
            'has_funds': balance >= web3.to_wei(0.05, 'ether')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
def verify_transaction_success(web3, user_address, tx_hash, expected_amount_wei):
    # Wait longer for the transaction to be mined
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)

    if receipt.status != 1:
        raise Exception("Transaction failed on-chain")

    # Wait a bit more for balance to update
    time.sleep(5)

    # Check balance multiple times to ensure it's stable
    balance_checks = []
    for i in range(3):
        balance = web3.eth.get_balance(user_address)
        balance_checks.append(balance)
        time.sleep(2)

    # If balances are inconsistent, something is wrong
    if len(set(balance_checks)) > 1:
        app.logger.warning(f"Inconsistent balance readings: {balance_checks}")

    final_balance = balance_checks[-1]
    return final_balance >= expected_amount_wei
