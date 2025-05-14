"""
Steganography module for SecureHide
Provides functionality to hide data in various media formats (images, audio, video)
"""

import os
import json
import base64
import struct
import random
import wave
import numpy as np
from PIL import Image
import cv2


class ImageSteganography:
    """Methods for hiding and extracting data from images using LSB steganography"""
    
    @staticmethod
    def hide_lsb(image_path, data, output_path=None):
        """
        Hide data in the least significant bits of an image
        
        Args:
            image_path: Path to the cover image
            data: String data to hide
            output_path: Path to save the modified image
        
        Returns:
            Path to the stego image
        """
        try:
            # Convert string data to bytes
            data_bytes = data.encode('utf-8')
            
            # Open the image
            img = Image.open(image_path)
            
            # Check if image is JPG/JPEG and warn about it
            if image_path.lower().endswith(('.jpg', '.jpeg')):
                print("Warning: JPG/JPEG format is not ideal for steganography due to lossy compression.")
                print("The hidden data may be lost when saving. Consider using PNG format instead.")
            
            # Convert to RGB mode if not already
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get the pixel data
            pixels = list(img.getdata())
            width, height = img.size
            
            # Calculate maximum data capacity
            max_bytes = (width * height * 3) // 8
            if len(data_bytes) > max_bytes:
                raise ValueError(f"Data too large ({len(data_bytes)} bytes). Maximum: {max_bytes} bytes")
            
            # Use a simple marker pattern instead of length
            marker = b'\x00\x00\x00\x00'  # 4 null bytes to mark end of data
            all_data = data_bytes + marker
            
            # Create a bit stream
            bits = []
            for byte in all_data:
                # Add each bit, LSB first (easier to work with)
                for i in range(8):
                    bits.append((byte >> i) & 1)
            
            # Create new pixels with embedded data
            new_pixels = []
            pixel_idx = 0
            bit_idx = 0
            
            # Process each pixel
            while pixel_idx < len(pixels) and bit_idx < len(bits):
                r, g, b = pixels[pixel_idx]
                
                # Modify the least significant bit of each RGB component
                if bit_idx < len(bits):
                    r = (r & ~1) | bits[bit_idx]
                    bit_idx += 1
                
                if bit_idx < len(bits):
                    g = (g & ~1) | bits[bit_idx]
                    bit_idx += 1
                
                if bit_idx < len(bits):
                    b = (b & ~1) | bits[bit_idx]
                    bit_idx += 1
                
                new_pixels.append((r, g, b))
                pixel_idx += 1
            
            # Add remaining pixels unchanged
            while pixel_idx < len(pixels):
                new_pixels.append(pixels[pixel_idx])
                pixel_idx += 1
            
            # Create a new image with modified pixels
            new_img = Image.new(img.mode, img.size)
            new_img.putdata(new_pixels)
            
            # Save the modified image - ensuring we use the appropriate format
            if output_path is None:
                filename, ext = os.path.splitext(image_path)
                output_path = f"{filename}_stego.png"  # Always use PNG for output
            
            # Force PNG format for saving
            if not output_path.lower().endswith('.png'):
                output_path = os.path.splitext(output_path)[0] + '.png'
                
            new_img.save(output_path, 'PNG')
            return output_path
            
        except Exception as e:
            raise ValueError(f"Error hiding data: {str(e)}")
    
    @staticmethod
    def extract_lsb(image_path):
        """
        Extract data hidden in the least significant bits of an image
        
        Args:
            image_path: Path to the stego image
        
        Returns:
            Extracted data as a string
        """
        try:
            # Check if image exists
            if not os.path.exists(image_path):
                raise ValueError(f"Image file not found: {image_path}")
                
            # Try to detect format issues
            if image_path.lower().endswith(('.jpg', '.jpeg')):
                print("Warning: Attempting to extract from JPG/JPEG format. This may fail due to lossy compression.")
            
            # Open the image
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get pixel data
            pixels = list(img.getdata())
            
            # Extract the least significant bit from each RGB channel
            extracted_bits = []
            for r, g, b in pixels:
                extracted_bits.append(r & 1)
                extracted_bits.append(g & 1)
                extracted_bits.append(b & 1)
            
            # Convert bits to bytes (8 bits per byte, LSB first to match hiding)
            bytes_data = bytearray()
            for i in range(0, len(extracted_bits), 8):
                if i + 8 <= len(extracted_bits):
                    byte = 0
                    for j in range(8):
                        # Set the bit at the appropriate position (LSB first)
                        byte |= (extracted_bits[i + j] << j)
                    bytes_data.append(byte)
            
            # Look for marker pattern (4 null bytes) to find end of data
            marker_position = bytes_data.find(b'\x00\x00\x00\x00')
            
            if marker_position == -1:
                # If marker not found, try to find at least one null byte
                null_pos = bytes_data.find(b'\x00')
                
                if null_pos == -1 or null_pos == 0:
                    # No marker found or it's at the beginning
                    # Likely no data hidden or the image format caused loss of data
                    raise ValueError("No data found in the image. If this is a JPG/JPEG file, try using PNG format instead.")
                
                # Use the first null byte as our marker
                data_bytes = bytes_data[:null_pos]
            else:
                data_bytes = bytes_data[:marker_position]
            
            # Try to decode as UTF-8
            try:
                extracted_string = data_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # If we can't decode as UTF-8, it might be corrupted data
                # Try to salvage what we can
                for i in range(len(data_bytes), 0, -1):
                    try:
                        extracted_string = data_bytes[:i].decode('utf-8')
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    raise ValueError("Extracted data is not valid UTF-8 text. The image format may have corrupted the hidden data.")
            
            if not extracted_string:
                raise ValueError("No data found in the image")
                
            return extracted_string
            
        except UnicodeDecodeError:
            # Try to decode as much as possible
            for i in range(len(bytes_data)):
                try:
                    return bytes_data[:i].decode('utf-8')
                except UnicodeDecodeError:
                    continue
            raise ValueError("Extracted data is not valid UTF-8 text")
        except Exception as e:
            raise ValueError(f"Error extracting data: {str(e)}")

class AudioSteganography:
    """Methods for hiding and extracting data from audio files"""
    
    @staticmethod
    def hide_lsb(audio_path, data, output_path=None):
        """
        Hide data in the least significant bits of an audio file
        
        Args:
            audio_path: Path to the cover audio file (WAV or MP3)
            data: String data to hide
            output_path: Path to save the modified audio (if None, generates one)
        
        Returns:
            Path to the stego audio
        """
        temp_wav_file = None
        try:
            # Check file extension
            ext = os.path.splitext(audio_path)[1].lower()
            
            # For MP3 files, convert to WAV first
            if ext == '.mp3':
                try:
                    import pydub
                    from pydub import AudioSegment
                    temp_wav_file = os.path.splitext(audio_path)[0] + '_temp.wav'
                    
                    # Convert MP3 to WAV using pydub
                    print(f"Converting MP3 to WAV: {audio_path} -> {temp_wav_file}")
                    sound = AudioSegment.from_mp3(audio_path)
                    sound.export(temp_wav_file, format="wav")
                    
                    if not os.path.exists(temp_wav_file):
                        raise ValueError(f"Failed to create WAV file at {temp_wav_file}")
                    
                    print(f"Converted MP3 to WAV: {temp_wav_file}")
                    
                    # Use the converted file for the rest of the processing
                    audio_path = temp_wav_file
                except ImportError:
                    raise ValueError("The pydub library is required for MP3 conversion. Install with 'pip install pydub'")
                except Exception as e:
                    raise ValueError(f"Error converting MP3 to WAV: {str(e)}")
            
            # Verify the file is a valid WAV file before proceeding
            if not os.path.exists(audio_path):
                raise ValueError(f"Audio file not found: {audio_path}")
            
            try:
                # Try opening with wave to verify it's a valid WAV file
                with wave.open(audio_path, 'rb') as wav_test:
                    pass
            except Exception as wave_error:
                raise ValueError(f"Invalid WAV file: {str(wave_error)}")
            
            # Open the audio file (now it should be WAV)
            with wave.open(audio_path, 'rb') as wav:
                # Get audio parameters
                n_channels = wav.getnchannels()
                sample_width = wav.getsampwidth()
                framerate = wav.getframerate()
                n_frames = wav.getnframes()
                
                # Read frames
                frames = wav.readframes(n_frames)
            
            # Convert data to binary
            binary_data = ''.join(format(ord(char), '08b') for char in data)
            binary_data += '0' * 8  # Add a null terminator
            
            # Check if data can fit in the audio file
            max_bytes = len(frames) // 8
            if len(binary_data) > max_bytes:
                raise ValueError(f"Data too large. Maximum size: {max_bytes} bytes")
            
            # Create a byte array from frames
            frame_array = bytearray(frames)
            
            # Embed data
            data_index = 0
            for i in range(0, len(binary_data)):
                if data_index >= len(binary_data):
                    break
                    
                # Get the byte
                byte = frame_array[i]
                
                # Replace the LSB with the data bit
                new_byte = (byte & ~1) | int(binary_data[data_index])
                frame_array[i] = new_byte
                data_index += 1
            
            # Create output path if not provided
            if output_path is None:
                filename, _ = os.path.splitext(audio_path)
                output_path = f"{filename}_stego.wav"
            elif not output_path.lower().endswith('.wav'):
                # Force WAV extension for output
                output_path = os.path.splitext(output_path)[0] + '.wav'
            
            # Write modified audio to file
            with wave.open(output_path, 'wb') as wav:
                wav.setnchannels(n_channels)
                wav.setsampwidth(sample_width)
                wav.setframerate(framerate)
                wav.writeframes(frame_array)
            
            # Clean up temporary file if created
            if temp_wav_file and os.path.exists(temp_wav_file):
                try:
                    os.remove(temp_wav_file)
                except:
                    pass  # Ignore errors in cleanup
            
            return output_path
            
        except Exception as e:
            # Clean up temporary file if exception occurred
            if temp_wav_file and os.path.exists(temp_wav_file):
                try:
                    os.remove(temp_wav_file)
                except:
                    pass  # Ignore errors in cleanup
            
            raise ValueError(f"Error hiding data in audio: {str(e)}")
    
    @staticmethod
    def extract_lsb(audio_path):
        """
        Extract data hidden in the least significant bits of an audio file
        
        Args:
            audio_path: Path to the stego audio file (WAV)
        
        Returns:
            Extracted data as a string
        """
        try:
            # Verify the file is a valid WAV file before proceeding
            if not os.path.exists(audio_path):
                raise ValueError(f"Audio file not found: {audio_path}")
            
            # Check file extension
            ext = os.path.splitext(audio_path)[1].lower()
            if ext != '.wav':
                raise ValueError(f"Only WAV files are supported for extraction. Found: {ext}")
            
            # Try opening with wave to verify it's a valid WAV file
            try:
                with wave.open(audio_path, 'rb') as wav_test:
                    pass
            except Exception as wave_error:
                raise ValueError(f"Invalid WAV file: {str(wave_error)}")
            
            # Open the audio file
            with wave.open(audio_path, 'rb') as wav:
                # Get audio parameters
                n_frames = wav.getnframes()
                
                # Read frames
                frames = wav.readframes(n_frames)
            
            # Create a byte array from frames
            frame_array = bytearray(frames)
            
            # Extract the LSBs
            extracted_bits = ""
            for i in range(len(frame_array)):
                extracted_bits += str(frame_array[i] & 1)
            
            # Convert bits to characters
            extracted_data = ""
            for i in range(0, len(extracted_bits), 8):
                if i + 8 > len(extracted_bits):
                    break
                    
                byte = extracted_bits[i:i+8]
                if byte == '00000000':  # Null terminator
                    break
                    
                extracted_data += chr(int(byte, 2))
            
            if not extracted_data:
                raise ValueError("No data found in the audio file")
            
            return extracted_data
            
        except Exception as e:
            raise ValueError(f"Error extracting data from audio: {str(e)}")

class VideoSteganography:
    """
    Methods for hiding and extracting data from video files using an image-based approach.
    This class extracts a frame from the video, applies steganography to the frame,
    and saves the frame separately. More reliable than direct video steganography.
    """
    
    @staticmethod
    def hide_lsb(video_path, data, output_path=None, frames_to_use=None):
        """
        Hide data in a frame extracted from the video
        
        Args:
            video_path: Path to the cover video
            data: String data to hide
            output_path: Path to save the modified frame (if None, generates one)
            frames_to_use: Not used in this implementation (for API compatibility)
        
        Returns:
            Path to the stego frame image and the frame info file
        """
        # Open the video
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise ValueError(f"Could not open video file: {video_path}")
            
        # Get video properties
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        # Read the first frame
        ret, frame = cap.read()
        if not ret:
            cap.release()
            raise ValueError(f"Could not read frame from video: {video_path}")
        
        # Release the video capture
        cap.release()
        
        # Convert data to binary
        binary_data = ''.join(format(ord(char), '08b') for char in data)
        
        # Make sure data fits in the frame
        max_bits = width * height  # Theoretical maximum using 1 bit per pixel
        if len(binary_data) > max_bits:
            raise ValueError(f"Data too large for frame. Maximum bits: {max_bits}, Required: {len(binary_data)}")
        
        # Embed data in the frame (blue channel)
        blue_channel = frame[:, :, 0].copy()
        
        # Embed each bit in sequential pixels
        for i, bit in enumerate(binary_data):
            # Calculate position - row-major order
            y = (i // width) % height
            x = i % width
            
            # Embed the bit
            blue_channel[y, x] = (blue_channel[y, x] & ~1) | int(bit)
        
        # Update the frame with modified blue channel
        frame[:, :, 0] = blue_channel
        
        # Generate output path if not provided
        if output_path is None:
            directory, filename = os.path.split(video_path)
            name, _ = os.path.splitext(filename)
            output_path = os.path.join(directory, f"{name}_stego_frame.png")
        
        # Ensure output path has correct extension
        output_path = os.path.splitext(output_path)[0] + ".png"
        
        # Save the stego frame
        cv2.imwrite(output_path, frame)
        
        # Create frame info
        frame_info = {
            'data_length': len(data),
            'binary_length': len(binary_data),
            'width': width,
            'height': height,
            'original_video': os.path.basename(video_path)
        }
        
        # Save frame info
        frame_info_path = output_path + '.info'
        with open(frame_info_path, 'w') as f:
            json.dump(frame_info, f)
        
        return output_path, frame_info_path
    
    @staticmethod
    def extract_lsb(stego_frame_path, frame_info_path):
        """
        Extract data hidden in a stego frame
        
        Args:
            stego_frame_path: Path to the stego frame image
            frame_info_path: Path to the frame info file
        
        Returns:
            Extracted data as a string
        """
        # Load the stego frame
        stego_frame = cv2.imread(stego_frame_path)
        if stego_frame is None:
            raise ValueError(f"Could not read stego frame: {stego_frame_path}")
        
        # Load the frame info
        try:
            with open(frame_info_path, 'r') as f:
                frame_info = json.load(f)
                
            binary_length = frame_info.get('binary_length')
            data_length = frame_info.get('data_length')
            width = frame_info.get('width')
            height = frame_info.get('height')
            
            if not all([binary_length, width, height]):
                raise ValueError("Missing required frame info")
        except Exception as e:
            raise ValueError(f"Error loading frame info: {str(e)}")
        
        # Get blue channel
        blue_channel = stego_frame[:, :, 0]
        
        # Extract bits
        extracted_bits = ""
        for i in range(binary_length):
            # Calculate position - row-major order
            y = (i // width) % height
            x = i % width
            
            # Extract LSB
            bit = blue_channel[y, x] & 1
            extracted_bits += str(bit)
        
        # Convert binary data to characters
        extracted_data = ""
        for i in range(0, len(extracted_bits), 8):
            if i + 8 <= len(extracted_bits):
                byte = extracted_bits[i:i+8]
                byte_val = int(byte, 2)
                extracted_data += chr(byte_val)
        
        # Validate result
        if not extracted_data and data_length > 0:
            raise ValueError("No data could be extracted from the image")
        
        return extracted_data
    
def calculate_max_data_capacity(media_path, media_type):
    """
    Calculate the maximum data capacity for a media file
    
    Args:
        media_path: Path to the media file
        media_type: Type of media ('image', 'audio', 'video')
    
    Returns:
        int: Maximum data capacity in bytes
    """
    if media_type == 'image':
        from PIL import Image
        img = Image.open(media_path)
        width, height = img.size
        return (width * height * 3) // 8  # RGB image, 1 bit per channel
    
    elif media_type == 'audio':
        import wave
        with wave.open(media_path, 'rb') as wav:
            n_frames = wav.getnframes()
            n_channels = wav.getnchannels()
            sample_width = wav.getsampwidth()
            return (n_frames * n_channels * sample_width) // 8  # 1 bit per sample
    
    elif media_type == 'video':
        import cv2
        cap = cv2.VideoCapture(media_path)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        cap.release()
        
        # Consider using only a subset of frames for practical purposes
        usable_frames = min(total_frames, 30)  # Use first 30 frames by default
        return (width * height * 3 * usable_frames) // 8  # RGB video, 1 bit per channel
    
    return 0  # Unknown file type

def hide_data(media_path, data, media_type=None, output_path=None):
    """
    Hide data in a media file with improved error handling
    
    Args:
        media_path: Path to the cover media file
        data: String data to hide
        media_type: Type of media ('image', 'audio', 'video'). If None, autodetect.
        output_path: Path to save the stego file
    
    Returns:
        Path to the stego file and any additional info
    """
    # Validate inputs
    if not os.path.exists(media_path):
        raise ValueError(f"Media file not found: {media_path}")
    
    if not data:
        raise ValueError("No data provided to hide")
    
    # Autodetect media type if not specified
    if media_type is None:
        ext = os.path.splitext(media_path)[1].lower()
        if ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
            media_type = 'image'
        elif ext in ['.wav', '.mp3']:
            media_type = 'audio'
        elif ext in ['.mp4', '.avi', '.mov']:
            media_type = 'video'
        else:
            raise ValueError(f"Unsupported file type: {ext}")
    
    # Generate output path if not provided
    if output_path is None:
        directory, filename = os.path.split(media_path)
        name, ext = os.path.splitext(filename)
        output_path = os.path.join(directory, f"{name}_stego{ext}")
    
    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Check if data will fit in the media
    max_capacity = calculate_max_data_capacity(media_path, media_type)
    data_size = len(data.encode('utf-8'))
    
    if data_size > max_capacity:
        raise ValueError(
            f"Data too large ({data_size} bytes) for media capacity ({max_capacity} bytes)"
        )
    
    # Hide data according to media type
    try:
        if media_type == 'image':
            ImageSteganography.hide_lsb(media_path, data, output_path)
            return output_path, None
        elif media_type == 'audio':
            AudioSteganography.hide_lsb(media_path, data, output_path)
            return output_path, None
        elif media_type == 'video':
            output_path, frame_info_path = VideoSteganography.hide_lsb(media_path, data, output_path)
            return output_path, frame_info_path
        else:
            raise ValueError(f"Unsupported media type: {media_type}")
    except Exception as e:
        raise ValueError(f"Error hiding data: {str(e)}")

def extract_data(media_path, media_type=None, additional_info=None):
    """
    Extract data from a stego file with improved error handling
    
    Args:
        media_path: Path to the stego file
        media_type: Type of media ('image', 'audio', 'video'). If None, autodetect.
        additional_info: Additional information needed for extraction (e.g., frame info for video)
    
    Returns:
        Extracted data as a string
    """
    # Validate inputs
    if not os.path.exists(media_path):
        raise ValueError(f"Stego file not found: {media_path}")
    
    # Autodetect media type if not specified
    if media_type is None:
        ext = os.path.splitext(media_path)[1].lower()
        if ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
            media_type = 'image'
        elif ext in ['.wav', '.mp3']:
            media_type = 'audio'
        elif ext in ['.mp4', '.avi', '.mov']:
            media_type = 'video'
        else:
            raise ValueError(f"Unsupported file type: {ext}")
    
    # Extract data according to media type
    try:
        extracted_data = None
        
        if media_type == 'image':
            extracted_data = ImageSteganography.extract_lsb(media_path)
        elif media_type == 'audio':
            extracted_data = AudioSteganography.extract_lsb(media_path)
        elif media_type == 'video':
            if additional_info is None:
                # Try to find the frame info file
                frame_info_path = media_path + '.info'
                if not os.path.exists(frame_info_path):
                    raise ValueError("Frame info file is required for video extraction")
            else:
                frame_info_path = additional_info
                
            extracted_data = VideoSteganography.extract_lsb(media_path, frame_info_path)
        else:
            raise ValueError(f"Unsupported media type: {media_type}")
        
        if not extracted_data:
            raise ValueError("No data could be extracted from the file")
        
        return extracted_data
    except Exception as e:
        raise ValueError(f"Error extracting data: {str(e)}")