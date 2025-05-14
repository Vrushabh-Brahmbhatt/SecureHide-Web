"""
Utility functions for SecureHide
"""

import os
import json
import base64
import datetime


def ensure_directory_exists(directory_path):
    """Ensure that a directory exists, creating it if necessary"""
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
    return directory_path


def generate_output_path(input_path, suffix="_secured", output_dir=None):
    """Generate an output file path based on an input path"""
    # Get the directory and filename
    input_dir, filename = os.path.split(input_path)
    name, ext = os.path.splitext(filename)
    
    # Determine the output directory
    if output_dir is None:
        output_dir = input_dir
    
    # Ensure the output directory exists
    ensure_directory_exists(output_dir)
    
    # Generate the output path
    output_filename = f"{name}{suffix}{ext}"
    output_path = os.path.join(output_dir, output_filename)
    
    return output_path


def log_operation(operation, details=None, log_file="securehide_log.json"):
    """Log an operation to a file"""
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "operation": operation,
        "details": details or {}
    }
    
    # Create the log directory if it doesn't exist
    log_dir = os.path.join(os.path.expanduser("~"), ".securehide")
    ensure_directory_exists(log_dir)
    
    log_path = os.path.join(log_dir, log_file)
    
    # Read existing log if it exists
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                log_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            log_data = {"entries": []}
    else:
        log_data = {"entries": []}
    
    # Add the new entry
    log_data["entries"].append(log_entry)
    
    # Write the log
    with open(log_path, 'w') as f:
        json.dump(log_data, f, indent=2)


def get_media_type(file_path):
    """Determine the media type of a file based on its extension"""
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
        return 'image'
    elif ext in ['.wav', '.mp3']:
        return 'audio'
    elif ext in ['.mp4', '.avi', '.mov']:
        return 'video'
    else:
        return None


def encode_data(data):
    """Encode data to a string format suitable for embedding"""
    if isinstance(data, dict) or isinstance(data, list):
        data = json.dumps(data)
    
    if not isinstance(data, str):
        data = str(data)
    
    return data


def decode_data(data_str):
    """Decode data from string format"""
    try:
        # Try to parse as JSON
        return json.loads(data_str)
    except json.JSONDecodeError:
        # Return as is if it's not JSON
        return data_str


def is_valid_file(file_path, allowed_extensions=None):
    """
    Check if a file exists and has an allowed extension
    
    Args:
        file_path: Path to the file
        allowed_extensions: List of allowed extensions (default: None = all extensions)
    
    Returns:
        bool: True if valid, False otherwise
    """
    if not os.path.isfile(file_path):
        return False
    
    if allowed_extensions is not None:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in allowed_extensions:
            return False
    
    return True


def format_file_size(size_bytes):
    """Format file size in bytes to a human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def calculate_max_data_capacity(file_path):
    """
    Calculate the maximum data capacity for a media file
    
    Args:
        file_path: Path to the media file
    
    Returns:
        int: Maximum data capacity in bytes
    """
    from . import steganography
    
    media_type = get_media_type(file_path)
    
    if media_type == 'image':
        from PIL import Image
        img = Image.open(file_path)
        width, height = img.size
        return (width * height * 3) // 8  # RGB image, 1 bit per channel
    
    elif media_type == 'audio':
        import wave
        with wave.open(file_path, 'rb') as wav:
            n_frames = wav.getnframes()
            return n_frames // 8  # 1 bit per sample
    
    elif media_type == 'video':
        import cv2
        cap = cv2.VideoCapture(file_path)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        cap.release()
        
        return (width * height * 3 * total_frames) // 8  # RGB video, 1 bit per channel
    
    return 0  # Unknown file type

def import_datetime():
    import datetime
    return datetime