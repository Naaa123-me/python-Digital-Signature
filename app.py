from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import hashlib
import os

#flask : Framework Python untuk membuat aplikasi web.
#request: Memproses data yang diterima dari klien (misalnya file atau data JSON).
#jsonify: Mengubah data Python menjadi format JSON untuk dikirimkan ke klien.
#render_template: Merender file HTML untuk ditampilkan di browser.
#secure_filename: Mengamankan nama file agar tidak mengandung karakter berbahaya.
#cryptography: Digunakan untuk membuat kunci RSA, tanda tangan digital, dan proses verifikasi.
#base64: Mengenkode tanda tangan dalam format Base64 agar mudah dikirimkan melalui JSON.
#hashlib: Menghasilkan hash MD5 dari dokumen atau pesan.
#os: Mengelola sistem file (misalnya membuat folder atau mengecek keberadaan file).


app = Flask(__name__) #os: Mengelola sistem file (misalnya membuat folder atau mengecek keberadaan file).



# Penyimpanan dokumen sementara di memori
documents = {}

# Konfigurasi untuk upload file
UPLOAD_FOLDER = 'uploaded_files'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx', 'xlsx', 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 1. Membuat Kunci (Private/Public)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# 2. Membuat Tanda Tangan Digital untuk Dokumen
def sign_document(private_key, file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
        md5_hash = hashlib.md5(content).digest()

    signature = private_key.sign(
        md5_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.MD5()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.MD5()
    )
    return base64.b64encode(signature).decode('utf-8')

# 3. Verifikasi Tanda Tangan Digital untuk Dokumen
def verify_document(public_key, file_path, signature):
    with open(file_path, 'rb') as file:
        content = file.read()
        md5_hash = hashlib.md5(content).digest()

    try:
        public_key.verify(
            base64.b64decode(signature),
            md5_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.MD5()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.MD5()
        )
        return True
    except Exception as e:
        print("Verifikasi gagal:", e)
        return False

# 4. Tanda Tangan Pesan
def sign_message(private_key, message):
    message_bytes = message.encode('utf-8')
    md5_hash = hashlib.md5(message_bytes).digest()

    signature = private_key.sign(
        md5_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.MD5()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.MD5()
    )
    return base64.b64encode(signature).decode('utf-8')

# 5. Verifikasi Tanda Tangan Pesan
def verify_message(public_key, message, signature):
    message_bytes = message.encode('utf-8')
    md5_hash = hashlib.md5(message_bytes).digest()

    try:
        public_key.verify(
            base64.b64decode(signature),
            md5_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.MD5()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.MD5()
        )
        return True
    except Exception as e:
        print("Verifikasi pesan gagal:", e)
        return False

# Generate keys
private_key, public_key = generate_keys()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify(status="Gagal", message="Tidak ada file yang diunggah")

    file = request.files['file']

    if file.filename == '':
        return jsonify(status="Gagal", message="Nama file kosong")

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Tanda tangan dokumen
        signature = sign_document(private_key, file_path)

        # Simpan informasi dokumen ke memori
        documents[filename] = {'signature': signature}

        return jsonify(status="Berhasil", message="Dokumen berhasil diunggah", signature=signature)
    else:
        return jsonify(status="Gagal", message="File tidak diizinkan")

@app.route('/sign_message', methods=['POST'])
def sign_message_route():
    data = request.get_json()
    message = data.get('message')

    if not message:
        return jsonify(status="Gagal", message="Pesan tidak boleh kosong")

    signature = sign_message(private_key, message)
    return jsonify(status="Berhasil", signature=signature)

@app.route('/verify_message', methods=['POST'])
def verify_message_route():
    data = request.get_json()
    message = data.get('message')
    signature = data.get('signature')

    if not message or not signature:
        return jsonify(status="Gagal", message="Pesan dan tanda tangan tidak boleh kosong")

    is_valid = verify_message(public_key, message, signature)
    if is_valid:
        return jsonify(status="Berhasil", message="Tanda tangan valid")
    else:
        return jsonify(status="Gagal", message="Tanda tangan tidak valid")

@app.route('/verify_document', methods=['POST'])
def verify_document_route():
    data = request.get_json()
    filename = data.get('filename')  # Menggunakan nama file
    signature = data.get('signature')

    if not filename or not signature:
        return jsonify(status="Gagal", message="Nama file dan tanda tangan tidak boleh kosong")

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)  # Menggunakan path yang benar

    # Pastikan file ada
    if not os.path.exists(file_path):
        return jsonify(status="Gagal", message="File tidak ditemukan")

    is_valid = verify_document(public_key, file_path, signature)
    if is_valid:
        return jsonify(status="Berhasil", message="Tanda tangan dokumen valid")
    else:
        return jsonify(status="Gagal", message="Tanda tangan dokumen tidak valid")

@app.route('/documents', methods=['GET'])
def get_documents():
    return jsonify(documents=[{'filename': filename, 'signature': doc['signature']} for filename, doc in documents.items()])

if __name__ == '__main__':
    app.run(debug=True)
