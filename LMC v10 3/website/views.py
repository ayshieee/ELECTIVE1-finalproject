from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from .models import Student
from . import db
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils
import hashlib
import base64
import os


views = Blueprint('views', __name__)

# Path to the private key file
PRIVATE_KEY_FILE = "private_key.pem"

# Load or generate the private key
if os.path.exists(PRIVATE_KEY_FILE):
    # Load the private key from the file
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
        public_key = private_key.public_key()


# private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# public_key = private_key.public_key()

# Serialize keys for storage (optional)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Encryption and Decryption Functions
# RSA
def encrypt_data(plaintext):
    try:
        encrypted_bytes = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_text = base64.b64encode(encrypted_bytes).decode()
        print()
        print(f"[Encryption] Plaintext: {plaintext}, Encrypted: {encrypted_text}")  # Debugging
        return encrypted_text
    except Exception as e:
        print(f"[Encryption Error] {e}")  # Debugging
        return None


# Decrypt RSA
def decrypt_data(ciphertext):
    try:
        encrypted_bytes = base64.b64decode(ciphertext.encode())
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_text = decrypted_bytes.decode()
        print(f"[Decryption] Ciphertext: {ciphertext}, Decrypted: {decrypted_text}")  # Debugging
        return decrypted_text
    except Exception as e:
        print(f"[Decryption Error] {e}")  # Debugging
        return None

# Hashing function (SHA-256)
def hash_data(data):
    hashed_value = hashlib.sha256(data.encode()).hexdigest()
    print(f"[Hashing] Data: {data}, Hashed: {hashed_value}")  # Debugging
    return hashed_value

# Sign data using private key

def sign_data(data):
    # RSA enrypt
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_text = base64.b64encode(signature).decode()
    print(f"[Signing] Data: {data}, Signature: {signature_text}")  # Debugging
    return signature_text

# Verify signature using public key
def verify_signature(data, signature):
    try:
        public_key.verify(
            base64.b64decode(signature.encode()),
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"[Signature Verification] Success for data: {data}")  # Debugging
        return True
    except Exception as e:
        print(f"[Signature Verification Error] {e}")  # Debugging
        return False

# Add new routes for encryption/decryption
@views.route('/encrypt-students', methods=['POST'])
@login_required
def encrypt_students():
    students = Student.query.all()
    fields = [
        'student_id', 'name', 'middle_name', 'last_name', 'suffix',
        'birthday', 'age', 'sex', 'house_number', 'street', 'city',
        'state', 'zip_code', 'country', 'contact_number', 'lrn',
        'course_year_level', 'college', 'plm_email', 'registration_status'
    ]
    for student in students:
        for field in fields:
            value = getattr(student, field)
            if value is not None:
                # Check if the data is already encrypted
                try:
                    # Attempt to decrypt the value
                    decrypted_value = decrypt_data(value)
                    if decrypted_value is not None:
                        print(f"[Encryption Check] Field {field} is already encrypted. Skipping.")
                        continue
                except Exception as e:
                    print(f"[Encryption Check] Field {field} is not encrypted. Proceeding with encryption.")
                # Encrypt the original plaintext
                encrypted_value = encrypt_data(str(value)) # RSA
                if encrypted_value is None:
                    flash(f'Encryption failed for {field}.', 'error')
                    continue
                # Hash the original plaintext
                hashed_value = hash_data(str(value)) # SHA
                # Sign the hashed data
                signature = sign_data(hashed_value) # RSA
                # Store encrypted value and signature
                setattr(student, field, encrypted_value)
                setattr(student, f'{field}_signature', signature)
        db.session.commit()
    flash('All students encrypted and signed successfully!', category='success')
    return redirect(url_for('views.home'))

@views.route('/decrypt-students', methods=['POST'])
@login_required
def decrypt_students():
    students = Student.query.all()
    fields = [
        'student_id', 'name', 'middle_name', 'last_name', 'suffix',
        'birthday', 'age', 'sex', 'house_number', 'street', 'city',
        'state', 'zip_code', 'country', 'contact_number', 'lrn',
        'course_year_level', 'college', 'plm_email', 'registration_status'
    ]
    for student in students:
        for field in fields:
            encrypted_value = getattr(student, field)
            signature = getattr(student, f'{field}_signature')
            if encrypted_value is not None and signature is not None:
                print(f"[Decrypting Field] {field}, Encrypted Value: {encrypted_value}, Signature: {signature}")  # Debugging
                try:
                    # Decrypt the data
                    decrypted_value = decrypt_data(encrypted_value) # Decrypt using RSA - original value
                    if decrypted_value is None:
                        flash(f'Decryption failed for {field}.', 'error')
                        continue
                    # Hash the decrypted data
                    hashed_decrypted_value = hash_data(decrypted_value) # SHA 256
                    # Verify the signature
                    if verify_signature(hashed_decrypted_value, signature):
                        if field == 'age':
                            decrypted_value = int(decrypted_value)
                        setattr(student, field, decrypted_value)
                    else:
                        flash(f'Signature verification failed for {field}.', 'error')
                except Exception as e:
                    flash(f'Error decrypting {field}: {str(e)}', 'error')
        db.session.commit()
    flash('All students decrypted and verified successfully!', category='success')
    return redirect(url_for('views.home'))

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        name = request.form.get('name')
        middle_name = request.form.get('middle_name')
        last_name = request.form.get('last_name')
        suffix = request.form.get('suffix')
        birthday = request.form.get('birthday')
        sex = request.form.get('sex')
        house_number = request.form.get('house_number')
        street = request.form.get('street')
        city = request.form.get('city')
        state = request.form.get('state')
        zip_code = request.form.get('zip_code')
        country = request.form.get('country')
        contact_number = request.form.get('contact_number')
        lrn = request.form.get('lrn')
        course_year_level = request.form.get('course_year_level')
        college = request.form.get('college')
        plm_email = request.form.get('plm_email')
        registration_status = request.form.get('registration_status')
        age = request.form.get('age')  

        # Form validation
        if not student_id or not name or not last_name or not birthday or not sex or not house_number or not street or not city or not state or not zip_code or not country or not contact_number or not course_year_level or not college or not plm_email or not registration_status or not age:
            flash('Please fill out all required fields.', category='error')
        elif len(contact_number) < 10 or not contact_number.startswith(('09', '+63')):
            flash('Invalid contact number format.', category='error')
        elif Student.query.filter_by(student_id=student_id).first():
            flash('Student ID already exists!', category='error')
        elif Student.query.filter_by(plm_email=plm_email).first():
            flash('PLM Email already exists!', category='error')
        else:
            new_student = Student(
                student_id=student_id,
                name=name,
                middle_name=middle_name,
                last_name=last_name,
                suffix=suffix,
                birthday=birthday,
                age=age,  
                sex=sex,
                house_number=house_number,
                street=street,
                city=city,
                state=state,
                zip_code=zip_code,
                country=country,
                contact_number=contact_number,
                lrn=lrn,
                course_year_level=course_year_level,
                college=college,
                plm_email=plm_email,
                registration_status=registration_status
            )
            db.session.add(new_student)
            db.session.commit()
            flash('Student added successfully!', category='success')
            return redirect(url_for('views.home'))

    # Fetch all students to display
    students = Student.query.all()
    return render_template("home.html", user=current_user, students=students)

# Delete Student Route
@views.route('/delete-student', methods=['POST'])
def delete_student():
    data = request.get_json()
    student_id = data.get('student_id')
    student = Student.query.filter_by(student_id=student_id).first()

    if student:
        db.session.delete(student)
        db.session.commit()
        return jsonify({"success": True})

    return jsonify({"success": False}), 404

#Sort Route
@views.route('/sort', methods=['POST'])
def sort_students():
    sort_by = request.json.get('sort_by', 'id')  # Default sorting by 'id'
    
    # Sorting logic
    if sort_by == 'name':
        sorted_students = Student.query.order_by(Student.name).all()
    elif sort_by == 'age':
        sorted_students = Student.query.order_by(Student.age).all()
    elif sort_by == 'birthday':
        sorted_students = Student.query.order_by(Student.birthday).all()
    else:  # Default to 'id'
        sorted_students = Student.query.order_by(Student.student_id).all()
    
    # Convert students to a JSON-friendly format
    student_list = []
    for student in sorted_students:
        student_list.append({
            'student_id': student.student_id,
            'name': student.name,
            'middle_name': student.middle_name,
            'last_name': student.last_name,
            'suffix': student.suffix,
            'birthday': student.birthday,
            'age': student.age,
            'sex': student.sex,
            'address': f'{student.house_number} {student.street}, {student.city}, {student.state}, {student.zip_code}, {student.country}',
            'contact_number': student.contact_number,
            'course_year_level': student.course_year_level,
            'college': student.college,
            'plm_email': student.plm_email,
            'registration_status': student.registration_status,
        })
    return jsonify({'success': True, 'students': student_list})