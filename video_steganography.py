import cv2
import numpy as np
import subprocess
import os
import argparse
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from tqdm import tqdm

def display_banner():
    """Display Cerberus Stegano banner with Hulk-themed ASCII art."""
    banner = r"""
      _.-^^---....,,--       
  _--                  --_  
 <                        >)
 |                         | 
  \._                   _./  
     ```--. . , ; .--'''       
           | |   |             
        .-=||  | |=-.   
        `-=#$%&%$#=-'   
           | ;  :|     
  _____.,-#%&$@%#&#~,._____
  CERBERUS SMASH!
  
  Cerberus Stegano
  Video Steganography Tool
  Programmer: Sudeepa Wanigarathna
  Inject and Extract: Text, Images, Files
  Secure with AES Encryption
  Powered by OpenCV & FFmpeg
    """
    print(banner)

def text_to_binary(text):
    """Convert text to binary string."""
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary):
    """Convert binary string to text."""
    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:
            text += chr(int(byte, 2))
    return text

def file_to_binary(file_path, extension):
    """Convert file to binary string with metadata."""
    with open(file_path, 'rb') as f:
        file_data = f.read()
    metadata = f"{len(file_data):032b}{extension[:8]:<8}".encode()
    return ''.join(format(byte, '08b') for byte in metadata + file_data)

def binary_to_file(binary, output_path):
    """Convert binary string to file."""
    file_size = int(binary[:32], 2)
    extension = binary_to_text(binary[32:96]).strip()
    file_data = binary[96:96 + file_size * 8]
    data_bytes = bytes(int(file_data[i:i+8], 2) for i in range(0, len(file_data), 8))
    output_file = f"{output_path}.{extension}" if extension else output_path
    with open(output_file, 'wb') as f:
        f.write(data_bytes)
    return output_file

def encrypt_data(data, password):
    """Encrypt data with AES."""
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

def decrypt_data(ciphertext, password):
    """Decrypt data with AES."""
    key = hashlib.sha256(password.encode()).digest()
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def encode_with_hamming(binary_message):
    """Apply Hamming code (4 data bits, 3 parity bits) for error correction."""
    def calculate_parity(bits, positions):
        return str(sum(int(bits[pos-1]) for pos in positions) % 2)
    
    encoded = ''
    for i in range(0, len(binary_message), 4):
        chunk = binary_message[i:i+4].ljust(4, '0')
        d1, d2, d3, d4 = chunk
        p1 = calculate_parity(chunk, [1, 3, 4])
        p2 = calculate_parity(chunk, [2, 3, 4])
        p3 = calculate_parity(chunk, [1, 2, 4])
        encoded += p1 + p2 + d1 + p3 + d2 + d3 + d4
    return encoded

def decode_with_hamming(encoded_message):
    """Decode Hamming code and correct single-bit errors."""
    def calculate_syndrome(bits):
        s1 = (int(bits[0]) + int(bits[2]) + int(bits[4]) + int(bits[6])) % 2
        s2 = (int(bits[1]) + int(bits[4]) + int(bits[5]) + int(bits[6])) % 2
        s3 = (int(bits[3]) + int(bits[5]) + int(bits[6])) % 2
        return s3 * 4 + s2 * 2 + s1
    
    decoded = ''
    for i in range(0, len(encoded_message), 7):
        chunk = encoded_message[i:i+7]
        if len(chunk) != 7:
            continue
        syndrome = calculate_syndrome(chunk)
        if syndrome != 0 and syndrome <= 7:
            corrected = list(chunk)
            corrected[syndrome-1] = '1' if corrected[syndrome-1] == '0' else '0'
            chunk = ''.join(corrected)
        decoded += chunk[2] + chunk[4] + chunk[5] + chunk[6]
    return decoded

def hide_message_in_frame(frame, binary_message, bit_index):
    """Hide binary message in frame using LSB steganography."""
    if frame is None or len(frame.shape) != 3:
        print(f"Debug: Invalid frame at bit_index={bit_index}, shape={frame.shape if frame is not None else None}")
        return frame, bit_index, True
    
    height, width, channels = frame.shape
    max_bits = height * width * channels
    
    if bit_index >= len(binary_message) or bit_index >= max_bits:
        print(f"Debug: Hiding stopped at bit_index={bit_index}, max_bits={max_bits}")
        return frame, bit_index, True
    
    pixel_index = bit_index // channels
    channel = bit_index % channels
    row = pixel_index // width
    col = pixel_index % width
    
    if row >= height or col >= width or channel >= channels:
        print(f"Debug: Invalid pixel at bit_index={bit_index}, row={row}, col={col}, channel={channel}, height={height}, width={width}")
        return frame, bit_index, True
    
    pixel_value = frame[row, col, channel]
    new_value = (pixel_value & 0xFE) | int(binary_message[bit_index])
    frame[row, col, channel] = new_value
    if bit_index % 1000 == 0:
        print(f"Debug: Hid bit {bit_index}/{len(binary_message)} at row={row}, col={col}, channel={channel}")
    bit_index += 1
    return frame, bit_index, False

def extract_message_from_frame(frame, bit_index, message_length):
    """Extract binary message from frame using LSB with detailed debugging."""
    if frame is None or len(frame.shape) != 3:
        print(f"Debug: Invalid frame at bit_index={bit_index}, shape={frame.shape if frame is not None else None}")
        return '', bit_index, True
    
    height, width, channels = frame.shape
    max_bits = height * width * channels
    
    if bit_index >= message_length or bit_index >= max_bits:
        print(f"Debug: Extraction stopped at bit_index={bit_index}, max_bits={max_bits}")
        return '', bit_index, True
    
    pixel_index = bit_index // channels
    channel = bit_index % channels
    row = pixel_index // width
    col = pixel_index % width
    
    if row >= height or col >= width or channel >= channels:
        print(f"Debug: Invalid pixel access at bit_index={bit_index}, row={row}, col={col}, channel={channel}, height={height}, width={width}")
        return '', bit_index, True
    
    bit = frame[row, col, channel] & 1
    if bit_index % 8 == 0:
        print(f"Debug: Extracted bit {bit_index}/{message_length} at row={row}, col={col}, channel={channel}, value={bit}")
    bit_index += 1
    return str(bit), bit_index, False

def estimate_capacity(video_path):
    """Estimate video capacity in bytes."""
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return 0
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    cap.release()
    return (width * height * 3 * frame_count) // 8

def hide_data(video_path, output_path, data_type, data_input, password, no_hamming=False):
    """Hide data (text, image, or file) in video with debugging."""
    if data_type == "text":
        binary_data = text_to_binary(f"TEXT{len(data_input):032b}{data_input}")
        print(f"Debug: Text data binary length: {len(binary_data)} bits")
    elif data_type in ["image", "file"]:
        extension = os.path.splitext(data_input)[1][1:] if data_type == "file" else data_input.split('.')[-1]
        binary_data = file_to_binary(data_input, extension)
        binary_data = text_to_binary("FILE") + binary_data
        print(f"Debug: File data binary length: {len(binary_data)} bits")
    else:
        print("Error: Invalid data type.")
        return False
    
    if not no_hamming:
        binary_data = encode_with_hamming(binary_data)
        print(f"Debug: Hamming encoded binary length: {len(binary_data)} bits")
    
    if password:
        binary_data = ''.join(format(byte, '08b') for byte in encrypt_data(
            bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8)), 
            password
        ))
        print(f"Debug: Encrypted binary length: {len(binary_data)} bits")
    
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print("Error: Could not open video.")
        return False
    
    fps = cap.get(cv2.CAP_PROP_FPS)
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    print(f"Debug: Video stats - width={width}, height={height}, frames={frame_count}, fps={fps}")
    
    max_capacity = (width * height * 3 * frame_count) // 8
    if len(binary_data) > max_capacity * 8:
        print(f"Error: Data too large. Video capacity: {max_capacity} bytes.")
        cap.release()
        return False
    
    temp_output = "temp_output.mp4"
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(temp_output, fourcc, fps, (width, height))
    
    bit_index = 0
    done = False
    progress = tqdm(total=frame_count, desc=f"Hiding {data_type}")
    
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            print("Debug: End of video reached during hiding")
            break
        if frame is None or len(frame.shape) != 3:
            print(f"Debug: Invalid frame at bit_index={bit_index}, shape={frame.shape if frame is not None else None}")
            progress.update(1)
            continue
        if not done:
            while bit_index < len(binary_data):
                frame, bit_index, done = hide_message_in_frame(frame, binary_data, bit_index)
                if done:
                    break
            out.write(frame)
        else:
            out.write(frame)
        progress.update(1)
    
    progress.close()
    cap.release()
    out.release()
    
    try:
        subprocess.run([
            'ffmpeg', '-i', temp_output, '-c:v', 'copy', '-c:a', 'aac',
            '-map_metadata', '0', '-y', output_path
        ], check=True, capture_output=True)
        os.remove(temp_output)
        print(f"Stego-video saved as {output_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error in FFmpeg processing: {e.stderr.decode()}")
        os.remove(temp_output)
        return False

def extract_data(video_path, output_dir, password, no_hamming=False):
    """Extract data (text, image, or file) from video with terminal output."""
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print("Error: Could not open video.")
        return None
    
    binary_metadata = ''
    bit_index = 0
    done = False
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    print(f"Total frames: {frame_count}, width={width}, height={height}")
    progress = tqdm(total=frame_count, desc="Extracting data")
    
    while len(binary_metadata) < 32 and cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            print("Debug: End of video reached while extracting metadata")
            break
        if frame is None or len(frame.shape) != 3:
            print(f"Debug: Invalid frame at bit_index={bit_index}, shape={frame.shape if frame is not None else None}")
            progress.update(1)
            continue
        while len(binary_metadata) < 32:
            bit, bit_index, done = extract_message_from_frame(frame, bit_index, 32)
            if done:
                break
            binary_metadata += bit
        progress.update(1)
    
    if len(binary_metadata) < 32:
        print(f"Debug: Extracted metadata bits: {len(binary_metadata)}/32, Metadata: {binary_metadata}")
        print("Error: Could not extract data type.")
        cap.release()
        progress.close()
        return None
    
    data_type = binary_to_text(binary_metadata)
    print(f"Debug: Data type: {data_type}")
    
    if data_type not in ["TEXT", "FILE"]:
        print(f"Error: Invalid data type '{data_type}'. Expected 'TEXT' or 'FILE'.")
        print("Debug: Attempting text extraction as fallback")
        data_type = "TEXT"
    
    binary_data = ''
    if data_type == "TEXT":
        while len(binary_data) < 32 and cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                print("Debug: End of video reached while extracting text length")
                break
            if frame is None or len(frame.shape) != 3:
                print(f"Debug: Invalid frame at bit_index={bit_index}, shape={frame.shape if frame is not None else None}")
                progress.update(1)
                continue
            while len(binary_data) < 32:
                bit, bit_index, done = extract_message_from_frame(frame, bit_index, 32)
                if done:
                    break
                binary_data += bit
            progress.update(1)
        
        if len(binary_data) < 32:
            print(f"Debug: Extracted text length bits: {len(binary_data)}/32, Data: {binary_data}")
            print("Error: Could not extract text length.")
            cap.release()
            progress.close()
            return None
        
        try:
            text_length = int(binary_data, 2) * 8
            print(f"Debug: Text length: {text_length} bits")
        except ValueError:
            print(f"Debug: Invalid text length binary: {binary_data}")
            print("Error: Could not parse text length.")
            cap.release()
            progress.close()
            return None
        
        binary_data = ''
        while len(binary_data) < text_length and cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                print("Debug: End of video reached while extracting text data")
                break
            if frame is None or len(frame.shape) != 3:
                print(f"Debug: Invalid frame at bit_index={bit_index}, shape={frame.shape if frame is not None else None}")
                progress.update(1)
                continue
            while len(binary_data) < text_length:
                bit, bit_index, done = extract_message_from_frame(frame, bit_index, text_length)
                if done:
                    break
                binary_data += bit
            progress.update(1)
    else:
        while len(binary_data) < 96 and cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                print("Debug: End of video reached while extracting file metadata")
                break
            if frame is None or len(frame.shape) != 3:
                print(f"Debug: Invalid frame at bit_index={bit_index}, shape={frame.shape if frame is not None else None}")
                progress.update(1)
                continue
            while len(binary_data) < 96:
                bit, bit_index, done = extract_message_from_frame(frame, bit_index, 96)
                if done:
                    break
                binary_data += bit
            progress.update(1)
        
        if len(binary_data) < 96:
            print(f"Debug: Extracted file metadata bits: {len(binary_data)}/96, Data: {binary_data}")
            print("Error: Could not extract file metadata.")
            cap.release()
            progress.close()
            return None
        
        try:
            file_size = int(binary_data[:32], 2) * 8
            print(f"Debug: File size: {file_size} bits")
        except ValueError:
            print(f"Debug: Invalid file size binary: {binary_data[:32]}")
            print("Error: Could not parse file size.")
            cap.release()
            progress.close()
            return None
        
        while len(binary_data) < 96 + file_size and cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                print("Debug: End of video reached while extracting file data")
                break
            if frame is None or len(frame.shape) != 3:
                print(f"Debug: Invalid frame at bit_index={bit_index}, shape={frame.shape if frame is not None else None}")
                progress.update(1)
                continue
            while len(binary_data) < 96 + file_size:
                bit, bit_index, done = extract_message_from_frame(frame, bit_index, 96 + file_size)
                if done:
                    break
                binary_data += bit
            progress.update(1)
    
    progress.close()
    cap.release()
    
    expected_length = text_length if data_type == "TEXT" else 96 + file_size
    if len(binary_data) < expected_length:
        print(f"Debug: Extracted data bits: {len(binary_data)}/{expected_length}, Data: {binary_data[:100]}...")
        print("Error: Could not extract complete data.")
        return None
    
    print(f"Debug: Extracted binary data length: {len(binary_data)} bits")
    if not no_hamming:
        binary_data = decode_with_hamming(binary_data)
        print(f"Debug: Hamming decoded data length: {len(binary_data)} bits")
    
    if password:
        try:
            data_bytes = bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))
            print(f"Debug: Pre-decryption bytes length: {len(data_bytes)}")
            binary_data = ''.join(format(byte, '08b') for byte in decrypt_data(data_bytes, password))
            print(f"Debug: Post-decryption binary data length: {len(binary_data)} bits")
        except Exception as e:
            print(f"Debug: Decryption failed with password: {password}")
            print(f"Error in decryption: {e}")
            return None
    
    os.makedirs(output_dir, exist_ok=True)
    if data_type == "TEXT":
        try:
            message = binary_to_text(binary_data)
            print(f"Extracted secret message: {message}")
            output_file = os.path.join(output_dir, "extracted_text.txt")
            with open(output_file, 'w') as f:
                f.write(message)
            print(f"Saved text to: {output_file}")
            return output_file
        except Exception as e:
            print(f"Debug: Failed to convert binary to text: {binary_data[:100]}...")
            print(f"Error in text conversion: {e}")
            return None
    else:
        try:
            extracted_file = binary_to_file(binary_data, os.path.join(output_dir, "extracted_file"))
            print(f"Extracted {data_type.lower()}: {extracted_file}")
            return extracted_file
        except Exception as e:
            print(f"Debug: Failed to convert binary to file: {binary_data[:100]}...")
            print(f"Error in file conversion: {e}")
            return None

def main():
    display_banner()
    parser = argparse.ArgumentParser(description="Video Steganography Tool")
    parser.add_argument("mode", choices=["hide", "extract"], help="Mode: hide or extract")
    parser.add_argument("--input", required=True, help="Input video file (.mp4)")
    parser.add_argument("--output", help="Output video file (.mp4) for hiding")
    parser.add_argument("--data-type", choices=["text", "image", "file"], help="Data type to hide (text, image, or file)")
    parser.add_argument("--data-input", help="Text message or file path to hide")
    parser.add_argument("--output-dir", help="Directory for extracted data", default="extracted")
    parser.add_argument("--capacity", action="store_true", help="Estimate video capacity")
    parser.add_argument("--no-hamming", action="store_true", help="Disable Hamming encoding/decoding")
    
    args = parser.parse_args()
    
    if args.capacity:
        capacity = estimate_capacity(args.input)
        print(f"Video capacity: {capacity} bytes")
        return
    
    if args.mode == "hide":
        if not args.output or not args.data_type or not args.data_input:
            print("Error: Output video, data type, and data input required for hiding mode.")
            return
        if args.data_type in ["image", "file"] and not os.path.exists(args.data_input):
            print("Error: Input file does not exist.")
            return
        password = getpass("Enter encryption password (leave empty for none): ")
        hide_data(args.input, args.output, args.data_type, args.data_input, password, args.no_hamming)
    else:
        password = getpass("Enter decryption password (leave empty if none): ")
        extract_data(args.input, args.output_dir, password, args.no_hamming)

if __name__ == "__main__":
    main()
