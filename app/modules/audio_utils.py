"""
Utility functions for audio format conversion in SecureHide
"""

import os
import subprocess
import tempfile

def convert_mp3_to_wav(mp3_path, wav_path=None):
    """
    Convert an MP3 file to WAV format
    
    Args:
        mp3_path: Path to the MP3 file
        wav_path: Output path for the WAV file (optional)
        
    Returns:
        Path to the converted WAV file
    """
    if not os.path.exists(mp3_path):
        raise ValueError(f"MP3 file not found: {mp3_path}")
    
    # Generate WAV path if not provided
    if not wav_path:
        wav_path = os.path.splitext(mp3_path)[0] + '_converted.wav'
    
    # Method 1: Try using pydub
    try:
        import importlib
        if importlib.util.find_spec("pydub") is not None:
            from pydub import AudioSegment
            sound = AudioSegment.from_mp3(mp3_path)
            sound.export(wav_path, format="wav")
            if os.path.exists(wav_path):
                print(f"Successfully converted MP3 to WAV using pydub: {wav_path}")
                return wav_path
    except Exception as e:
        print(f"Pydub conversion failed: {str(e)}")
    
    # Method 2: Try using ffmpeg directly
    try:
        # Check if ffmpeg is available
        try:
            subprocess.run(['ffmpeg', '-version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            raise ValueError("FFmpeg is not installed or not in PATH. Please install FFmpeg.")
        
        # Convert using ffmpeg
        cmd = ['ffmpeg', '-i', mp3_path, '-y', wav_path]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            raise ValueError(f"FFmpeg conversion failed: {result.stderr.decode('utf-8', errors='ignore')}")
        
        if os.path.exists(wav_path):
            print(f"Successfully converted MP3 to WAV using ffmpeg: {wav_path}")
            return wav_path
        else:
            raise ValueError("FFmpeg conversion did not produce a WAV file")
    except Exception as e:
        print(f"FFmpeg conversion failed: {str(e)}")
        
    # If all conversion methods failed
    raise ValueError(
        "Failed to convert MP3 to WAV. Please ensure you have pydub and FFmpeg installed. "
        "You can install pydub with 'pip install pydub' and download FFmpeg from https://ffmpeg.org/download.html"
    )

def is_valid_wav(wav_path):
    """
    Check if a file is a valid WAV file
    
    Args:
        wav_path: Path to the WAV file
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        if not os.path.exists(wav_path):
            return False
        
        # Try to open with wave module
        import wave
        with wave.open(wav_path, 'rb') as wav:
            # Get basic properties to verify it's a valid WAV
            channels = wav.getnchannels()
            sample_width = wav.getsampwidth()
            framerate = wav.getframerate()
            n_frames = wav.getnframes()
            
            # A valid WAV file should have reasonable values for these properties
            if channels <= 0 or sample_width <= 0 or framerate <= 0 or n_frames <= 0:
                return False
        
        return True
    except Exception:
        return False

def get_audio_format(file_path):
    """
    Determine the audio format of a file
    
    Args:
        file_path: Path to the audio file
        
    Returns:
        str: Audio format ('wav', 'mp3', or 'unknown')
    """
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext == '.wav':
        if is_valid_wav(file_path):
            return 'wav'
        else:
            return 'unknown'
    elif ext == '.mp3':
        # Basic check for MP3 - we can't easily validate without libraries
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            return 'mp3'
    
    return 'unknown'