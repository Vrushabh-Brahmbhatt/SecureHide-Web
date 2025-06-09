# app/routes.py
from flask import Blueprint, render_template, url_for, flash, redirect, request, abort, send_file, session
from flask_login import login_user, current_user, logout_user, login_required
from app import db, bcrypt
from app.models import User, StegoFile
from app.forms import RegistrationForm, LoginForm, HideDataForm, ExtractDataForm
from app.modules import encryption, steganography, integrity, utils, classical_ciphers
import os
import json
import secrets
import base64
from werkzeug.utils import secure_filename
from config import Config
from flask import jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from app.modules import classical_ciphers

# Blueprint definitions
main = Blueprint('main', __name__)
users = Blueprint('users', __name__)
steganography_bp = Blueprint('steganography', __name__)

# Helper functions for RSA key serialization
def serialize_private_key(private_key):
    """Convert an RSA private key object to a serializable format (PEM string)"""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(pem).decode('utf-8')

def deserialize_private_key(pem_b64):
    """Convert a serialized private key back to an RSA private key object"""
    pem = base64.b64decode(pem_b64)
    return serialization.load_pem_private_key(
        pem,
        password=None,
        backend=default_backend()
    )

# Main routes
@main.route('/')
@main.route('/home')
def home():
    return render_template('index.html', title='Home')

@main.route('/about')
def about():
    return render_template('about.html', title='About')

# User routes
@users.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been created! You can now log in.', 'success')
        return redirect(url_for('users.login'))
    
    return render_template('register.html', title='Register', form=form)

@users.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    
    return render_template('login.html', title='Login', form=form)

@users.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@users.route('/account')
@login_required
def account():
    # Get user's stego files
    stego_files = StegoFile.query.filter_by(user_id=current_user.id).all()
    return render_template('account.html', title='Account', stego_files=stego_files)

# Helper functions for steganography routes
def save_file(file, directory='uploads'):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(file.filename)
    filename = random_hex + f_ext
    file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
    file.save(file_path)
    return filename, file_path

def get_media_type(filename):
    ext = filename.rsplit('.', 1)[1].lower()
    for media_type, extensions in Config.ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return media_type
    return None

# Modified versions of encryption functions that handle RSA keys
def hybrid_encrypt_modified(message, password=None, use_rsa=False):
    """
    Hybrid encryption using AES and optionally RSA
    Returns encrypted message and keys needed for decryption
    """
    # Use AES for message encryption
    aes = encryption.AESCipher(password)
    encrypted_data = aes.encrypt(message)
    
    result = {
        'encrypted_data': encrypted_data,
        'method': 'password' if password else 'key'
    }
    
    # If RSA is requested, encrypt the AES key with RSA
    if use_rsa:
        rsa_cipher = encryption.RSACipher()
        result['method'] = 'rsa'
        result['encrypted_key'] = rsa_cipher.encrypt_aes_key(aes.key)
        
        # Serialize the private key to a format that can be stored in JSON
        result['private_key_pem'] = serialize_private_key(rsa_cipher.private_key)
    
    return result

def hybrid_decrypt_modified(encrypted_package, password=None):
    """
    Decrypt a message that was encrypted with hybrid_encrypt
    """
    method = encrypted_package['method']
    encrypted_data = encrypted_package['encrypted_data']
    
    if method == 'password':
        # Password-based decryption
        aes = encryption.AESCipher()
        plaintext = aes.decrypt(encrypted_data, password)
    elif method == 'key':
        # Direct key decryption
        aes = encryption.AESCipher()
        aes.key = encrypted_package['key']
        plaintext = aes.decrypt(encrypted_data)
    elif method == 'rsa':
        # RSA-based key decryption
        if 'private_key_pem' not in encrypted_package:
            raise ValueError("Missing private key for RSA decryption")
        
        # Deserialize the private key
        private_key = deserialize_private_key(encrypted_package['private_key_pem'])
        
        rsa_cipher = encryption.RSACipher()
        rsa_cipher.private_key = private_key
        aes_key = rsa_cipher.decrypt_aes_key(encrypted_package['encrypted_key'])
        
        aes = encryption.AESCipher()
        aes.key = aes_key
        plaintext = aes.decrypt(encrypted_data)
    else:
        raise ValueError(f"Unknown encryption method: {method}")
    
    return plaintext

# Steganography routes
# Steganography routes
@steganography_bp.route('/hide', methods=['GET', 'POST'])
@login_required
def hide():
    form = HideDataForm()
    if form.validate_on_submit():
        try:
            # Save the uploaded media file
            media_file = form.media_file.data
            filename, file_path = save_file(media_file)
            
            # Get media type
            media_type = get_media_type(media_file.filename)
            if not media_type:
                flash('Unsupported media type.', 'danger')
                return redirect(url_for('steganography.hide'))
            
            # Handle format conversions for steganography
            original_file_path = file_path
            converted_file_path = None
            
            # JPG/JPEG conversion for images
            if media_type == 'image' and any(ext in file_path.lower() for ext in ['.jpg', '.jpeg']):
                try:
                    from PIL import Image
                    # Convert JPG to PNG for steganography
                    img = Image.open(file_path)
                    png_path = os.path.splitext(file_path)[0] + '.png'
                    img.save(png_path, 'PNG')
                    
                    # Update file path and notify user
                    converted_file_path = png_path
                    flash('JPEG file was automatically converted to PNG for better steganography compatibility.', 'info')
                except ImportError:
                    flash('PIL/Pillow library is required for JPG conversion. Using original format (may not work).', 'warning')
                except Exception as e:
                    flash(f'Error converting JPG to PNG: {str(e)}. Using original format (may not work).', 'warning')
            
            # MP3 conversion for audio
            if media_type == 'audio' and any(ext in file_path.lower() for ext in ['.mp3']):
                try:
                    # Check if pydub or ffmpeg is available
                    mp3_converted = False
                    
                    # Try pydub first
                    try:
                        import pydub
                        from pydub import AudioSegment
                        
                        wav_path = os.path.splitext(file_path)[0] + '.wav'
                        sound = AudioSegment.from_mp3(file_path)
                        sound.export(wav_path, format="wav")
                        
                        if os.path.exists(wav_path):
                            converted_file_path = wav_path
                            mp3_converted = True
                            flash('MP3 file was automatically converted to WAV for steganography compatibility.', 'info')
                    except Exception as pydub_error:
                        print(f"Pydub conversion failed: {str(pydub_error)}")
                    
                    # If pydub failed, try ffmpeg directly
                    if not mp3_converted:
                        try:
                            import subprocess
                            
                            wav_path = os.path.splitext(file_path)[0] + '.wav'
                            cmd = ['ffmpeg', '-i', file_path, '-y', wav_path]
                            subprocess.run(cmd, check=True, capture_output=True)
                            
                            if os.path.exists(wav_path):
                                converted_file_path = wav_path
                                mp3_converted = True
                                flash('MP3 file was automatically converted to WAV using FFmpeg for steganography compatibility.', 'info')
                        except Exception as ffmpeg_error:
                            print(f"FFmpeg conversion failed: {str(ffmpeg_error)}")
                    
                    # If all conversion methods failed
                    if not mp3_converted:
                        flash('MP3 conversion failed. Please install pydub and FFmpeg, or use WAV files directly.', 'warning')
                except Exception as e:
                    flash(f'Error handling MP3 conversion: {str(e)}. Steganography may fail.', 'warning')
            
            # Use the converted file if available
            if converted_file_path and os.path.exists(converted_file_path):
                file_path = converted_file_path
            
            # Prepare message
            message = form.message.data
            message_to_hide = message
            
            # Add integrity check if requested
            if form.integrity_check.data:
                metadata = {
                    'timestamp': utils.import_datetime().datetime.now().isoformat(),
                    'media_type': media_type,
                    'user': current_user.username
                }
                secure_package = integrity.secure_message(message, metadata)
                message_to_hide = integrity.serialize_security_info(secure_package)
            
            # Encrypt if requested
            is_encrypted = False
            if form.encryption.data:
                encryption_type = form.encryption_type.data

                # Handle classical ciphers
                if encryption_type in ['caesar', 'playfair', 'vigenere', 'hill']:
                    try:
                        cipher = classical_ciphers.get_cipher(encryption_type)
                        classical_key = form.classical_key.data

                        # Encrypt the message
                        encrypted_message = cipher.encrypt(message_to_hide, classical_key)

                        # Create a simple package format for classical ciphers
                        encrypted_package = {
                            'method': encryption_type,
                            'encrypted_data': encrypted_message,
                            'key_type': 'classical'
                        }

                        message_to_hide = json.dumps(encrypted_package)
                        is_encrypted = True

                        flash(f'{encryption_type.capitalize()} cipher encryption applied. Note: Classical ciphers provide limited security.', 'info')
                    except Exception as e:
                        flash(f'Classical cipher encryption error: {str(e)}', 'danger')
                        return redirect(url_for('steganography.hide'))

                # Only handle AES and AES+RSA encryption if not classical
                elif encryption_type in ['aes', 'aes_rsa']:
                    password = form.password.data
                    use_rsa = (encryption_type == 'aes_rsa')

                    try:
                        # Use our modified function that handles RSA keys properly
                        encrypted_package = encryption.hybrid_encrypt(message_to_hide, password, use_rsa)
                        message_to_hide = json.dumps(encrypted_package)
                        is_encrypted = True

                        if use_rsa:
                            flash('RSA encryption used. The private key is safely stored within the message.', 'info')
                    except Exception as e:
                        flash(f'Encryption error: {str(e)}', 'danger')
                        return redirect(url_for('steganography.hide'))

            # Different handling based on media type
            if media_type == 'video':
                # Using the image-based approach for videos
                # Generate output filename based on original file
                base_output_filename = f"stego_{os.path.splitext(os.path.basename(file_path))[0]}"
                frame_output_path = os.path.join(Config.UPLOAD_FOLDER, f"{base_output_filename}_frame.png")
                
                # Use VideoSteganography.hide_lsb for image-based approach
                stego_path, additional_info_path = steganography.VideoSteganography.hide_lsb(
                    file_path, message_to_hide, frame_output_path
                )
                
                # Update media type for the database
                stored_media_type = 'video_frame'
                
                # Inform the user about the image-based approach
                flash('Video processed using frame extraction for better reliability. A frame image was created.', 'info')
            else:
                # For images and audio, use the standard approach
                # Determine the correct output extension
                base_output_filename = f"stego_{os.path.splitext(os.path.basename(file_path))[0]}"
                output_extension = '.png' if media_type == 'image' else '.wav' if media_type == 'audio' else os.path.splitext(file_path)[1]
                output_filename = base_output_filename + output_extension
                output_path = os.path.join(Config.UPLOAD_FOLDER, output_filename)
                
                # Use the standard hide_data function
                stego_path, additional_info_path = steganography.hide_data(
                    file_path, message_to_hide, media_type, output_path
                )
                
                # Keep the original media type
                stored_media_type = media_type
            
            # Save main stego file info to database
            stego_file = StegoFile(
                filename=os.path.basename(stego_path),
                original_filename=media_file.filename,
                file_path=stego_path,
                media_type=stored_media_type,  # Use the appropriate media type
                has_message=True,
                is_encrypted=is_encrypted,
                has_integrity_check=form.integrity_check.data,
                additional_info=additional_info_path,  # This stores the path to the info file
                user_id=current_user.id
            )
            db.session.add(stego_file)
            db.session.commit()
            
            # If this is a video or video_frame and we have an info file, save it as a separate record
            if (media_type == 'video' or stored_media_type == 'video_frame') and additional_info_path and os.path.exists(additional_info_path):
                # Create a new record for the info file
                info_file = StegoFile(
                    filename=os.path.basename(additional_info_path),
                    original_filename=f"{media_file.filename}.info",
                    file_path=additional_info_path,
                    media_type='metadata',  # New type for metadata files
                    has_message=False,
                    is_encrypted=False,
                    has_integrity_check=False,
                    additional_info=f"Frame info for {os.path.basename(stego_path)}",
                    user_id=current_user.id
                )
                db.session.add(info_file)
                db.session.commit()
                
                # Display a success message about the info file
                flash('Frame info file was saved for video extraction.', 'info')
            
            # Clean up temporary files if created
            if converted_file_path and os.path.exists(converted_file_path) and converted_file_path != stego_path:
                try:
                    os.remove(converted_file_path)
                except:
                    pass  # Ignore errors in cleanup
            
            flash('Data successfully hidden in the media file!', 'success')
            return redirect(url_for('users.account'))
            
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('steganography.hide'))
    
    return render_template('hide.html', title='Hide Data', form=form)

@steganography_bp.route('/extract_with_info/<int:file_id>')
@login_required
def extract_with_info(file_id):
    # Get the video file
    video_file = StegoFile.query.get_or_404(file_id)
    
    # Check if this is a video file or video frame
    if video_file.media_type != 'video' and video_file.media_type != 'video_frame':
        flash('This feature is only available for video files.', 'warning')
        return redirect(url_for('users.account'))
    
    # Check if the current user owns the file
    if video_file.user_id != current_user.id:
        abort(403)
    
    # Find the corresponding info file
    info_file = StegoFile.query.filter_by(
        user_id=current_user.id,
        media_type='metadata',
        filename=video_file.filename + '.info'
    ).first()
    
    if not info_file:
        flash('Could not find the corresponding frame info file.', 'danger')
        return redirect(url_for('steganography.extract'))
    
    # Store the file IDs in session for the extraction form to use
    session['selected_video_id'] = video_file.id
    session['selected_info_id'] = info_file.id
    
    # Redirect to the extraction page
    flash('Video and frame info file selected for extraction.', 'success')
    return redirect(url_for('steganography.extract'))

@steganography_bp.route('/extract', methods=['GET', 'POST'])
@login_required
def extract():
    form = ExtractDataForm()
    
    # Handle GET parameters from the video extraction modal
    video_id = request.args.get('video_id')
    info_id = request.args.get('info_id')
    is_encrypted = request.args.get('is_encrypted') == 'on'
    password = request.args.get('password')
    
    # If video_id and info_id were supplied in the URL, process them
    if video_id and info_id and request.method == 'GET':
        try:
            # Get the files from database
            video_file = StegoFile.query.get_or_404(video_id)
            info_file = StegoFile.query.get_or_404(info_id)
            
            # Verify ownership
            if video_file.user_id != current_user.id or info_file.user_id != current_user.id:
                abort(403)
                
            # Create temporary files from the stored files
            video_temp_filename, video_temp_path = save_file_from_path(video_file.file_path, 
                                                                      os.path.basename(video_file.file_path))
            info_temp_filename, info_temp_path = save_file_from_path(info_file.file_path, 
                                                                    os.path.basename(info_file.file_path))
            
            # Extract the data - different handling for video_frame
            media_type = video_file.media_type
            if media_type == 'video_frame':
                # Use VideoSteganography.extract_lsb for video frames
                extracted_data = steganography.VideoSteganography.extract_lsb(
                    video_temp_path, info_temp_path
                )
            else:
                # Use the standard extract_data function
                extracted_data = steganography.extract_data(
                    video_temp_path, media_type, info_temp_path
                )
            
            # Check if data is encrypted
            is_encrypted = False
            try:
                data_json = json.loads(extracted_data)
                if 'method' in data_json and any(key in data_json for key in ['encrypted_data', 'key_type', 'encrypted_key', 'iv', 'tag', 'ciphertext']):
                    is_encrypted = True
            except:
                pass
            
            # Decrypt if necessary
            if is_encrypted and form.is_encrypted.data:
                try:
                    encrypted_package = json.loads(extracted_data)
                    encryption_method = encrypted_package.get('method', '')

                    # Handle classical ciphers
                    if encryption_method in ['caesar', 'playfair', 'vigenere', 'hill']:
                        try:
                            cipher = classical_ciphers.get_cipher(encryption_method)
                            classical_key = form.classical_key.data

                            # Get the encrypted data from the package
                            encrypted_text = encrypted_package.get('encrypted_data', '')

                            # Decrypt the data
                            decrypted_data = cipher.decrypt(encrypted_text, classical_key)
                            extracted_data = decrypted_data
                        except Exception as e:
                            flash(f'Classical cipher decryption failed: {str(e)}', 'danger')
                            return redirect(url_for('steganography.extract'))

                    # Handle AES/RSA encryption methods
                    elif encryption_method in ['password', 'key', 'rsa', 'aes', 'aes_rsa']:
                        # Use our modified decrypt function
                        password = form.password.data
                        decrypted_data = hybrid_decrypt_modified(encrypted_package, password)
                        extracted_data = decrypted_data
                    else:
                        raise ValueError(f"Unknown encryption method: {encryption_method}")

                except Exception as e:
                    flash(f'Decryption failed: {str(e)}', 'danger')
                    return redirect(url_for('steganography.extract'))
    
            # Check for integrity info
            has_integrity = False
            is_valid = False
            message = extracted_data
            metadata = {}
            
            try:
                security_info = integrity.deserialize_security_info(extracted_data)
                if 'hash' in security_info:
                    has_integrity = True
                    is_valid, message, metadata = integrity.verify_message(security_info)
            except:
                pass
            
            # Store the extracted data in session for display
            session['extracted_message'] = message
            session['has_integrity'] = has_integrity
            session['is_valid'] = is_valid
            session['metadata'] = metadata if metadata else {}
            
            # Clean up temporary files
            try:
                os.remove(video_temp_path)
                os.remove(info_temp_path)
            except:
                pass  # Ignore cleanup errors
            
            return render_template('extract_result.html', 
                                  title='Extraction Result',
                                  message=message, 
                                  has_integrity=has_integrity,
                                  is_valid=is_valid, 
                                  metadata=metadata)
        
        except Exception as e:
            flash(f'Error during direct extraction: {str(e)}', 'danger')
            return redirect(url_for('steganography.extract'))
    
    # Original form submission handling
    if form.validate_on_submit():
        try:
            # Save the uploaded stego file
            stego_file = form.stego_file.data
            filename, file_path = save_file(stego_file)
            
            # Get media type
            media_type = get_media_type(stego_file.filename)
            if not media_type:
                flash('Unsupported media type.', 'danger')
                return redirect(url_for('steganography.extract'))
            
            # Check if it's a video frame (PNG from video)
            is_video_frame = False
            if media_type == 'image' and '_frame.png' in filename.lower():
                # This might be a video frame
                info_path = file_path + '.info'
                if os.path.exists(info_path):
                    is_video_frame = True
                    media_type = 'video_frame'
                    additional_info = info_path
                    flash('Detected video frame image with info file.', 'info')
            
            # Handle additional info for video and video frames
            additional_info = None
            if not is_video_frame:
                if media_type == 'video' or media_type == 'video_frame':
                    if not form.frame_info.data:
                        # Check if the info file exists alongside the stego file
                        info_path = file_path + '.info'
                        if os.path.exists(info_path):
                            additional_info = info_path
                            flash('Found frame info file automatically.', 'info')
                        else:
                            flash('Frame info file is required for video extraction.', 'warning')
                            return redirect(url_for('steganography.extract'))
                    else:
                        frame_info_file = form.frame_info.data
                        _, frame_info_path = save_file(frame_info_file)
                        additional_info = frame_info_path
            
            # Extract the data - special handling for video_frame
            if media_type == 'video_frame':
                # Use VideoSteganography.extract_lsb for video frames
                extracted_data = steganography.VideoSteganography.extract_lsb(
                    file_path, additional_info
                )
            else:
                # Use standard extraction for other media types
                extracted_data = steganography.extract_data(
                    file_path, media_type, additional_info
                )
            
            # Check if data is encrypted
            is_encrypted = False
            try:
                data_json = json.loads(extracted_data)
                if 'method' in data_json and any(key in data_json for key in ['encrypted_data', 'encrypted_key', 'iv', 'tag', 'ciphertext']):
                    is_encrypted = True
            except:
                pass
            
            # Decrypt if necessary
            if is_encrypted and form.is_encrypted.data:
                try:
                    encrypted_package = json.loads(extracted_data)
                    encryption_method = encrypted_package.get('method', '')
                    
                    # Use our modified decrypt function
                    password = form.password.data
                    decrypted_data = hybrid_decrypt_modified(encrypted_package, password)
                    extracted_data = decrypted_data
                except Exception as e:
                    flash(f'Decryption failed: {str(e)}', 'danger')
                    return redirect(url_for('steganography.extract'))
            
            # Check for integrity info
            has_integrity = False
            is_valid = False
            message = extracted_data
            metadata = {}
            
            try:
                security_info = integrity.deserialize_security_info(extracted_data)
                if 'hash' in security_info:
                    has_integrity = True
                    is_valid, message, metadata = integrity.verify_message(security_info)
            except:
                pass
            
            # Store the extracted data in session for display
            session['extracted_message'] = message
            session['has_integrity'] = has_integrity
            session['is_valid'] = is_valid
            session['metadata'] = metadata if metadata else {}
            
            return render_template('extract_result.html', 
                                  title='Extraction Result',
                                  message=message, 
                                  has_integrity=has_integrity,
                                  is_valid=is_valid, 
                                  metadata=metadata)
            
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('steganography.extract'))
    
    return render_template('extract.html', title='Extract Data', form=form)

# Helper function to save a file from an existing path
def save_file_from_path(source_path, original_filename):
    """Save a copy of a file from a source path to the upload folder"""
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(original_filename)
    filename = random_hex + f_ext
    destination_path = os.path.join(Config.UPLOAD_FOLDER, filename)
    
    # Copy the file
    import shutil
    shutil.copy2(source_path, destination_path)
    
    return filename, destination_path

@steganography_bp.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    stego_file = StegoFile.query.get_or_404(file_id)
    
    # Check if the current user owns the file
    if stego_file.user_id != current_user.id:
        abort(403)
    
    return send_file(stego_file.file_path, as_attachment=True, 
                   download_name=stego_file.original_filename or stego_file.filename)

# Visualization and benchmark routes can remain unchanged
# They can still use the classical_ciphers for educational purposes
# even though they're not available in the main interface

@steganography_bp.route('/visualize', methods=['GET', 'POST'])
def visualize():
    """Route for cipher visualization"""
    # This can remain unchanged since it's for visualization only
    # ...existing code...
    plaintext = "HELLO WORLD"
    sample_results = {
        'caesar': {
            'description': 'Caesar cipher shifts each letter in the plaintext by a fixed number of positions in the alphabet.',
            'key': '3',
            'encrypted': '',
            'steps': [
                'Convert each letter to its numeric position (A=0, B=1, ...)',
                'Add the shift value (key) to each position',
                'Take modulo 26 of the result to wrap around the alphabet',
                'Convert back to letters'
            ],
            'visualization': []
        },
        'playfair': {
            'description': 'Playfair cipher uses a 5x5 grid of letters based on a keyword, and encrypts pairs of letters.',
            'key': 'SECURITY',
            'encrypted': '',
            'steps': [
                'Create a 5x5 matrix from the keyword (excluding J, which is replaced with I)',
                'Split plaintext into pairs of letters',
                'For each pair, find their positions in the matrix',
                'Apply the Playfair rules: Same row → take letters to the right, Same column → take letters below, Different row and column → take corners of the rectangle',
                'Combine the resulting letter pairs'
            ],
            'visualization': {
                'matrix': [],
                'pairs': []
            }
        },
        'vigenere': {
            'description': 'Vigenère cipher uses a keyword to determine the shift for each letter, creating a polyalphabetic substitution.',
            'key': 'KEY',
            'encrypted': '',
            'steps': [
                'Repeat the keyword to match the length of the plaintext',
                'Convert each letter of the keyword to its numeric value (A=0, B=1, ...)',
                'Add the keyword value to each plaintext letter value',
                'Take modulo 26 of the result',
                'Convert back to letters'
            ],
            'visualization': []
        },
        'hill': {
            'description': 'Hill cipher uses a matrix of numbers as the key and performs matrix multiplication for encryption.',
            'key': 'HILL',
            'encrypted': '',
            'steps': [
                'Convert the key to a matrix of numbers',
                'Convert plaintext to vectors of numbers',
                'Multiply each vector by the key matrix',
                'Take modulo 26 of each result',
                'Convert back to letters'
            ],
            'visualization': {
                'key_matrix': [],
                'blocks': []
            }
        }
    }

    # Generate visualization data for each cipher
    try:
        # Caesar visualization
        caesar = classical_ciphers.get_cipher('caesar')
        caesar_encrypted = caesar.encrypt(plaintext, sample_results['caesar']['key'])
        sample_results['caesar']['encrypted'] = caesar_encrypted
        
        # Generate step-by-step visualization for Caesar
        caesar_viz = []
        shift = int(sample_results['caesar']['key'])
        for char in plaintext:
            if char.isalpha():
                original_pos = ord(char.upper()) - ord('A')
                shifted_pos = (original_pos + shift) % 26
                shifted_char = chr(shifted_pos + ord('A'))
                caesar_viz.append({
                    'char': char.upper(),
                    'original_pos': original_pos,
                    'shift': shift,
                    'shifted_pos': shifted_pos,
                    'result': shifted_char
                })
            else:
                caesar_viz.append({
                    'char': char,
                    'original_pos': 'N/A',
                    'shift': shift,
                    'shifted_pos': 'N/A',
                    'result': char
                })
        sample_results['caesar']['visualization'] = caesar_viz

        # Playfair visualization
        playfair = classical_ciphers.get_cipher('playfair')
        playfair._create_matrix(sample_results['playfair']['key'])
        matrix = playfair.matrix
        sample_results['playfair']['visualization']['matrix'] = matrix
        
        # Prepare text for Playfair visualization
        prepared_text = playfair._prepare_text(plaintext)
        pairs = []
        for i in range(0, len(prepared_text), 2):
            if i+1 < len(prepared_text):
                char1, char2 = prepared_text[i], prepared_text[i+1]
                row1, col1 = playfair._find_position(char1)
                row2, col2 = playfair._find_position(char2)
                
                # Determine rule and result
                if row1 == row2:  # Same row
                    rule = "Same row → take letters to the right"
                    enc1 = matrix[row1][(col1 + 1) % 5]
                    enc2 = matrix[row2][(col2 + 1) % 5]
                elif col1 == col2:  # Same column
                    rule = "Same column → take letters below"
                    enc1 = matrix[(row1 + 1) % 5][col1]
                    enc2 = matrix[(row2 + 1) % 5][col2]
                else:  # Rectangle
                    rule = "Different row and column → take corners of the rectangle"
                    enc1 = matrix[row1][col2]
                    enc2 = matrix[row2][col1]
                
                pairs.append({
                    'input': f"{char1}{char2}",
                    'positions': f"({row1},{col1}) ({row2},{col2})",
                    'rule': rule,
                    'output': f"{enc1}{enc2}"
                })
        
        sample_results['playfair']['visualization']['pairs'] = pairs
        sample_results['playfair']['encrypted'] = playfair.encrypt(plaintext, sample_results['playfair']['key'])

        # Vigenere visualization
        vigenere = classical_ciphers.get_cipher('vigenere')
        vigenere_encrypted = vigenere.encrypt(plaintext, sample_results['vigenere']['key'])
        sample_results['vigenere']['encrypted'] = vigenere_encrypted
        
        # Generate step-by-step visualization for Vigenere
        vigenere_viz = []
        key = sample_results['vigenere']['key'].upper()
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                key_char = key[key_index % len(key)]
                key_value = ord(key_char) - ord('A')
                char_value = ord(char.upper()) - ord('A')
                encrypted_value = (char_value + key_value) % 26
                encrypted_char = chr(encrypted_value + ord('A'))
                
                vigenere_viz.append({
                    'char': char.upper(),
                    'key_char': key_char,
                    'char_value': char_value,
                    'key_value': key_value,
                    'sum': char_value + key_value,
                    'modulo': encrypted_value,
                    'result': encrypted_char
                })
                
                key_index += 1
            else:
                vigenere_viz.append({
                    'char': char,
                    'key_char': '',
                    'char_value': 'N/A',
                    'key_value': 'N/A',
                    'sum': 'N/A',
                    'modulo': 'N/A',
                    'result': char
                })
        
        sample_results['vigenere']['visualization'] = vigenere_viz

        # Hill visualization
        hill = classical_ciphers.get_cipher('hill')
        key_matrix = hill._key_to_matrix(sample_results['hill']['key'])
        sample_results['hill']['visualization']['key_matrix'] = key_matrix
        
        # Prepare text and generate block-by-block visualization
        prepared_text = hill._prepare_text(plaintext)
        text_vectors = hill._text_to_vectors(prepared_text)
        blocks = []
        
        for i, vector in enumerate(text_vectors):
            # Input block (2 characters)
            if i*2 < len(prepared_text):
                input_block = prepared_text[i*2:i*2+hill.block_size]
            else:
                input_block = ""
            
            # Calculate multiplication
            output_vector = [0] * hill.block_size
            for j in range(hill.block_size):
                for k in range(hill.block_size):
                    output_vector[j] += key_matrix[j][k] * vector[k]
                output_vector[j] %= 26
            
            # Output block
            output_chars = [chr(v + ord('A')) for v in output_vector]
            output_block = ''.join(output_chars)
            
            blocks.append({
                'input_block': input_block,
                'input_vector': vector,
                'output_vector': output_vector,
                'output_block': output_block,
                'calculation': [
                    f"{key_matrix[j][0]} × {vector[0]} + {key_matrix[j][1]} × {vector[1]} = {output_vector[j]}"
                    for j in range(hill.block_size)
                ]
            })
        
        sample_results['hill']['visualization']['blocks'] = blocks
        sample_results['hill']['encrypted'] = hill.encrypt(plaintext, sample_results['hill']['key'])

    except Exception as e:
        flash(f"Error generating visualization: {str(e)}", "danger")
    
    return render_template('visualize.html', 
                          title='Cipher Visualization',
                          plaintext=plaintext,
                          results=sample_results)

@steganography_bp.route('/benchmark', methods=['GET', 'POST'])
def benchmark():
    """Route for security benchmarking"""
    # This can remain unchanged since it's for benchmarking only
    sample_text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    
    # Define different encryption methods with their properties
    encryption_methods = {
        'caesar': {
            'name': 'Caesar Cipher',
            'type': 'Classical',
            'key_space': '26 keys',
            'key_space_numeric': 26,
            'complexity': 'Very Low',
            'resistance': {
                'brute_force': 'Very Low',
                'frequency_analysis': 'Very Low',
                'known_plaintext': 'Very Low',
                'chosen_plaintext': 'Very Low'
            },
            'time_to_crack': 'Seconds',
            'use_cases': 'Educational only, not secure',
            'year_invented': '~50 BCE',
            'breakthrough_year': 'Ancient times',
            'key_used': '3',
            'encrypted': '',
            'performance': {
                'encryption_time': 0,
                'decryption_time': 0
            }
        },
        'playfair': {
            'name': 'Playfair Cipher',
            'type': 'Classical',
            'key_space': '~10^20 keys',
            'key_space_numeric': 10**20,
            'complexity': 'Low',
            'resistance': {
                'brute_force': 'Low',
                'frequency_analysis': 'Medium',
                'known_plaintext': 'Low',
                'chosen_plaintext': 'Low'
            },
            'time_to_crack': 'Minutes to hours',
            'use_cases': 'Historical military communications',
            'year_invented': '1854',
            'breakthrough_year': '~1900s',
            'key_used': 'SECURITY',
            'encrypted': '',
            'performance': {
                'encryption_time': 0,
                'decryption_time': 0
            }
        },
        'vigenere': {
            'name': 'Vigenère Cipher',
            'type': 'Classical',
            'key_space': 'Depends on key length',
            'key_space_numeric': 26**5,  # Assuming 5-letter key
            'complexity': 'Medium',
            'resistance': {
                'brute_force': 'Medium',
                'frequency_analysis': 'Medium',
                'known_plaintext': 'Low',
                'chosen_plaintext': 'Low'
            },
            'time_to_crack': 'Hours to days',
            'use_cases': 'Historical diplomatic communications',
            'year_invented': '1553',
            'breakthrough_year': '1863 (Kasiski examination)',
            'key_used': 'KEY',
            'encrypted': '',
            'performance': {
                'encryption_time': 0,
                'decryption_time': 0
            }
        },
        'hill': {
            'name': 'Hill Cipher',
            'type': 'Classical',
            'key_space': '~10^6 invertible matrices (2x2)',
            'key_space_numeric': 10**6,
            'complexity': 'Medium-High',
            'resistance': {
                'brute_force': 'Medium',
                'frequency_analysis': 'High',
                'known_plaintext': 'Medium',
                'chosen_plaintext': 'Low'
            },
            'time_to_crack': 'Days',
            'use_cases': 'Academic demonstrations',
            'year_invented': '1929',
            'breakthrough_year': '1931',
            'key_used': 'HILL',
            'encrypted': '',
            'performance': {
                'encryption_time': 0,
                'decryption_time': 0
            }
        },
        'aes': {
            'name': 'AES-256',
            'type': 'Modern',
            'key_space': '2^256 keys',
            'key_space_numeric': 2**256,
            'complexity': 'Very High',
            'resistance': {
                'brute_force': 'Very High',
                'frequency_analysis': 'Very High',
                'known_plaintext': 'Very High',
                'chosen_plaintext': 'High'
            },
            'time_to_crack': 'Billions of years',
            'use_cases': 'Banking, government, sensitive data protection',
            'year_invented': '1998',
            'breakthrough_year': 'Not yet broken',
            'key_used': 'Strong password',
            'encrypted': '[Complex encrypted data]',
            'performance': {
                'encryption_time': 0,
                'decryption_time': 0
            }
        },
        'aes_rsa': {
            'name': 'AES+RSA Hybrid',
            'type': 'Modern',
            'key_space': '2^256 + 2^2048 keys',
            'key_space_numeric': 2**256 + 2**2048,
            'complexity': 'Extremely High',
            'resistance': {
                'brute_force': 'Very High',
                'frequency_analysis': 'Very High',
                'known_plaintext': 'Very High',
                'chosen_plaintext': 'Very High'
            },
            'time_to_crack': 'Billions of years',
            'use_cases': 'Secure communications, data protection, digital signatures',
            'year_invented': 'RSA: 1977, AES: 1998',
            'breakthrough_year': 'Not yet broken',
            'key_used': 'Complex key pair',
            'encrypted': '[Complex encrypted data]',
            'performance': {
                'encryption_time': 0,
                'decryption_time': 0
            }
        }
    }
    
    # Run performance benchmarks for classical ciphers
    import time
    
    for cipher_name in ['caesar', 'playfair', 'vigenere', 'hill']:
        try:
            cipher = classical_ciphers.get_cipher(cipher_name)
            key = encryption_methods[cipher_name]['key_used']
            
            # Benchmark encryption time
            start_time = time.time()
            encrypted = cipher.encrypt(sample_text, key)
            encryption_time = time.time() - start_time
            
            # Benchmark decryption time
            start_time = time.time()
            decrypted = cipher.decrypt(encrypted, key)
            decryption_time = time.time() - start_time
            
            # Store results
            encryption_methods[cipher_name]['encrypted'] = encrypted
            encryption_methods[cipher_name]['performance']['encryption_time'] = round(encryption_time * 1000, 2)  # in ms
            encryption_methods[cipher_name]['performance']['encryption_time'] = round(encryption_time * 1000, 2)  # in ms
            encryption_methods[cipher_name]['performance']['decryption_time'] = round(decryption_time * 1000, 2)  # in ms
            
        except Exception as e:
            flash(f"Error benchmarking {cipher_name}: {str(e)}", "warning")
    
    # Basic AES benchmark (just an estimate, since we need a password)
    try:
        # AES encryption
        start_time = time.time()
        aes = encryption.AESCipher("password123")
        aes_encrypted = aes.encrypt(sample_text)
        encryption_time = time.time() - start_time
        
        # AES decryption
        start_time = time.time()
        decrypted = aes.decrypt(aes_encrypted)
        decryption_time = time.time() - start_time
        
        encryption_methods['aes']['performance']['encryption_time'] = round(encryption_time * 1000, 2)  # in ms
        encryption_methods['aes']['performance']['decryption_time'] = round(decryption_time * 1000, 2)  # in ms
        
        # AES+RSA is more complex, just estimate it's about 20% slower than AES
        encryption_methods['aes_rsa']['performance']['encryption_time'] = round(encryption_time * 1.2 * 1000, 2)  # in ms
        encryption_methods['aes_rsa']['performance']['decryption_time'] = round(decryption_time * 1.2 * 1000, 2)  # in ms
        
    except Exception as e:
        flash(f"Error benchmarking AES: {str(e)}", "warning")
    
    # Calculate security scores (out of 100)
    max_key_space = encryption_methods['aes_rsa']['key_space_numeric']
    
    for method_name, method in encryption_methods.items():
        # Base score on key space (log scale)
        key_space_factor = 0
        if method['key_space_numeric'] > 0:
            key_space_factor = min(50, 50 * (logbase(method['key_space_numeric'], 10) / logbase(max_key_space, 10)))
        
        # Resistance factor
        resistance_values = {'Very Low': 0, 'Low': 5, 'Medium': 10, 'High': 15, 'Very High': 20}
        resistance_score = sum(resistance_values.get(v, 0) for v in method['resistance'].values()) / len(method['resistance'])
        
        # Algorithm complexity
        complexity_values = {'Very Low': 0, 'Low': 5, 'Medium': 10, 'High': 15, 'Very High': 20, 'Extremely High': 25}
        complexity_score = complexity_values.get(method['complexity'], 0)
        
        # Calculate total score
        method['security_score'] = min(100, round(key_space_factor + resistance_score + complexity_score))
    
    return render_template('benchmark.html', 
                          title='Security Benchmark',
                          sample_text=sample_text,
                          methods=encryption_methods)

# Helper function for log with arbitrary base
def logbase(x, base):
    import math
    return math.log(x) / math.log(base) if x > 0 and base > 0 else 0

@main.route('/debug/routes')
def list_routes():
    from flask import current_app
    
    routes = []
    for rule in current_app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'path': str(rule)
        })
    
    return {'routes': routes}

@steganography_bp.route('/files/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    # Find the file in the database
    file = StegoFile.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    
    try:
        # Get the file path
        file_path = file.file_path
        
        # Delete the file from filesystem if it exists
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete the record from the database
        db.session.delete(file)
        db.session.commit()
        
        flash('File deleted successfully!', 'success')
        return redirect(url_for('users.account'))
    
    except Exception as e:
        # If an error occurs, rollback the session
        db.session.rollback()
        flash(f'Error deleting file: {str(e)}', 'danger')
        return redirect(url_for('users.account'))