import uuid
import boto3
from flask import Flask, request, jsonify
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from web3 import Web3
from yaml import safe_load

app = Flask(__name__)
with open('config.yaml', 'r') as config_file:
    config = safe_load(config_file)
AWS_ACCESS_KEY_ID = config["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = config["AWS_SECRET_ACCESS_KEY"]
AWS_REGION = config["AWS_REGION"]
AWS_BUCKET_NAME = config["AWS_BUCKET_NAME"]
goerli_private_key = config["goerli_private_key"]
alchemy_url = config["alchemy_url"]

w3 = Web3(Web3.HTTPProvider(alchemy_url))
nonce = w3.eth.get_transaction_count('0x46Bf8D6392cA4b7D0AE5De6B30b51d4c3852F93A')
ABI_exam = [{"inputs": [{"internalType": "string", "name": "_scheduling", "type": "string"},
                        {"internalType": "uint256", "name": "_duration", "type": "uint256"},
                        {"internalType": "string", "name": "_gradingPolicy", "type": "string"},
                        {"internalType": "string", "name": "_identities", "type": "string"}],
             "stateMutability": "nonpayable", "type": "constructor"},
            {"inputs": [{"internalType": "address", "name": "student", "type": "address"}], "name": "getStudentAnswers",
             "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view",
             "type": "function"},
            {"inputs": [{"internalType": "string", "name": "_hash", "type": "string"}], "name": "setQuizHash",
             "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable",
             "type": "function"},
            {"inputs": [{"internalType": "string", "name": "_answers", "type": "string"}], "name": "setStudentAnswers",
             "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable",
             "type": "function"}, {"inputs": [], "name": "showQuizHash",
                                   "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                                   "stateMutability": "view", "type": "function"}]
quiz = w3.eth.contract(address="0x40a6F836e5B6310CC4f2187BDd134fe13697355e", abi=ABI_exam)

s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)


@app.route('/send_exam_s3', methods=['POST'])
def upload_file_to_s3():
    try:
        # Get file path from the request data
        file_path = request.json.get('filePath')  # Assuming you send the file path in JSON data
        public_key_pem = request.json.get('publicKey')
        if not file_path:
            return jsonify({'error': 'File path or publicKey is missing'}), 400

        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        # Read the file content
        with open(file_path, 'rb') as file:
            file_contents = file.read()

        # Encrypt the file content with RSA
        encrypted_contents = public_key.encrypt(
            file_contents,
            padding.PKCS1v15()
        )
        # Generate a unique key for the file in the S3 bucket
        file_name = file_path.split('/')[-1]
        file_key = f'uploads/{uuid.uuid4().hex}/{file_name}'

        # Upload the encrypted file to S3
        s3_client.put_object(
            Bucket=AWS_BUCKET_NAME,
            Key=file_key,
            Body=encrypted_contents,
            ContentType='application/octet-stream'
        )

        s3_url = f'https://{AWS_BUCKET_NAME}.s3.amazonaws.com/{file_key}'

        return jsonify({'message': 'Encrypted file uploaded successfully', 'url': s3_url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/set_exam_hash')
def set_exam_hash_():
    item_key = f'response.json'
    response = s3_client.get_object(Bucket=AWS_BUCKET_NAME, Key=item_key)
    item_data = response['Body'].read().decode('utf-8')
    a = '33'
    exam_hash = sha256(a.encode('utf-8')).hexdigest()
    quiz_tx = quiz.functions.setQuizHash(exam_hash).build_transaction({

        'chainId': 5,

        'gas': 70000,

        'maxFeePerGas': w3.to_wei('2', 'gwei'),

        'maxPriorityFeePerGas': w3.to_wei('1', 'gwei'),

        'nonce': nonce,

    })
    signed_tx = w3.eth.account.sign_transaction(quiz_tx, private_key=goerli_private_key)
    w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    return exam_hash


if __name__ == '__main__':
    app.run(debug=True, port=5000)
