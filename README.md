Cerberus Stegano
CERBERUS SMASH!A video steganography tool for hiding and extracting text, images, or files in MP4 videos using Least Significant Bit (LSB) steganography. Features AES encryption, Hamming error correction, and support for any video resolution. Extracted text messages are displayed in the terminal, and files are saved to the extracted folder.
Features

Hide Data: Embed text, images, or files in MP4 videos.
Extract Data: Retrieve hidden data, with text printed to terminal and files saved.
Resolution Support: Works with any video resolution (e.g., 640x480, 1920x1080).
Security: Optional AES encryption with password protection.
Error Correction: Hamming codes for single-bit error correction (optional).
User-Friendly: CLI with progress bars and "CERBERUS SMASH!" banner.

![1](https://github.com/user-attachments/assets/66ddc737-8cbc-4b50-a142-7bc7e2fa3ee6)

![2](https://github.com/user-attachments/assets/430067c0-bf2e-4b7e-85df-3672847aff4f)



Prerequisites

OS: Linux (tested on Kali Linux)
Tools:
Python 3.8+
FFmpeg
OpenCV (python3-opencv)


Python Packages:
PyCryptodome
tqdm



Installation

Clone the Repository:
git clone https://github.com/<your-username>/cerberus_stegano.git
cd cerberus_stegano


Set Up Virtual Environment:
python3 -m venv venv
source venv/bin/activate


Install Dependencies:
sudo apt update
sudo apt install -y python3-opencv ffmpeg
pip install -r requirements.txt



Usage
Run video_steganography.py in hide or extract mode. See example_usage.sh for sample commands.
Hide Data
Hide a text message, image, or file in a video:
python video_steganography.py hide --input input.mp4 --output stego_video.mp4 --data-type text --data-input "Secret message" --no-hamming


--data-type: text, image, or file.
--no-hamming: Optional, disables Hamming encoding for simplicity.
Enter a password (or leave empty for none).

Extract Data
Extract and display the hidden data:
python video_steganography.py extract --input stego_video.mp4 --output-dir extracted --no-hamming


Text is printed to the terminal and saved to extracted/extracted_text.txt.
Images/files are saved to extracted/extracted_file.<extension>.
Enter the decryption password (or leave empty if none).

Check Video Capacity
Estimate the video’s data capacity:
python video_steganography.py --capacity --input input.mp4

Example
# Hide text
python video_steganography.py hide --input 1.mp4 --output stego_video.mp4 --data-type text --data-input "Secret message" --no-hamming

# Extract text
python video_steganography.py extract --input stego_video.mp4 --output-dir extracted --no-hamming

Output:
CERBERUS SMASH!
Total frames: 250, width=1920, height=1080
Debug: Data type: TEXT
Debug: Text length: 112 bits
Extracted secret message: Secret message
Saved text to: extracted/extracted_text.txt

Troubleshooting

Error: Extraction stopped at bit_index=32:
Cause: Corrupted stego_video.mp4 or frame indexing issue.
Fix: Re-hide with a new video using -c:v copy:ffmpeg -i 1.mp4 -c:v copy -c:a copy test_input.mp4
python video_steganography.py hide --input test_input.mp4 --output stego_video.mp4 --data-type text --data-input "Secret message" --no-hamming




Error: Invalid data type 'm¶Ûm':
Cause: LSBs altered by FFmpeg compression.
Fix: Ensure lossless encoding (-c:v copy) and verify video integrity:ffprobe stego_video.mp4




No output file:
Check debug logs for Invalid frame or Invalid pixel access.
Use a different video resolution or re-encode:ffmpeg -i 1.mp4 -vf scale=640:480 -c:a copy low_res.mp4




Fallback: Use SteganoTools for reliable DCT-based steganography:pip3 install steganotools
steganotools hide --input 1.mp4 --output stego_video.mp4 --data-type text --data "Secret message"
steganotools extract --input stego_video.mp4 --output extracted/message.txt



Project Structure
cerberus_stegano/
├── video_steganography.py  # Main script
├── README.md              # Documentation
├── .gitignore             # Git ignore rules
├── LICENSE                # MIT License
├── requirements.txt        # Python dependencies
├── example_usage.sh        # Example commands
├── tests/                 # Test videos (optional)
│   ├── test_640x480.mp4
│   ├── test_1920x1080.mp4

License
This project is licensed under the MIT License. See LICENSE for details.
Contributing
Contributions are welcome! Please submit a pull request or open an issue on GitHub.
Author

Sudeepa Wanigarathna


Notes

The tool uses LSB steganography, which may be affected by video compression. For production use, consider SteganoTools (DCT-based, Reed-Solomon error correction).
Tested on Kali Linux with Python 3.8+, OpenCV 4.5.5, FFmpeg 4.4.

