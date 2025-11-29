# 😈 CERBERUS STEGANO 🎥

## Video Steganography with LSB, AES Encryption, and Hamming Correction

**Cerberus Stegano** is a robust, command-line video steganography tool designed to **hide and extract text, images, or files** within **MP4 videos** using the **Least Significant Bit (LSB)** technique.

It provides critical security and integrity features, including optional **AES-256 encryption** for confidentiality and **Hamming error correction** for data resilience.

> **Key Takeaway:** Hide sensitive data securely within any standard MP4 video, regardless of its resolution, with built-in encryption and error correction.

---

## ✨ Features

| Feature | Description |
| :--- | :--- |
| **Data Hiding** | Embed text, image, or any file type into an MP4 container. |
| **Cross-Resolution** | Works seamlessly with **any video resolution** (e.g., 640x480, 1920x1080). |
| **Security (Optional)** | Use **AES-256 encryption** with a password to secure hidden data. |
| **Integrity (Optional)**| Apply **Hamming Codes** for **single-bit error correction** during extraction. |
| **Output** | Extracted text is printed to the terminal; files/images are saved to an output directory. |
| **Usability** | User-friendly Command-Line Interface (CLI) with **progress bars** for large files. |

---

## 🛠️ Prerequisites

Cerberus Stegano is primarily tested on **Linux (Kali Linux)** environments.

### System Dependencies

You must have the following system tools installed:

* **Python 3.8+**
* **FFmpeg:** For video stream manipulation.
* **OpenCV (`python3-opencv`):** For frame-by-frame image processing.

### Python Packages

These packages are listed in `requirements.txt`:

* `PyCryptodome` (for AES encryption)
* `tqdm` (for progress bars)

---

## 🚀 Installation

Follow these steps to get the project running locally.

### 1. Clone the Repository

```bash
git clone [https://github.com/](https://github.com/)<your-username>/cerberus_stegano.git
cd cerberus_stegano
````

### 2\. Install System Tools

Make sure **FFmpeg** and **OpenCV** are available on your system.

```bash
sudo apt update
sudo apt install -y python3-opencv ffmpeg
```

### 3\. Set Up and Install Python Dependencies

It's highly recommended to use a virtual environment.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

-----

## 💻 Usage

The main script is `video_steganography.py`. Run it in either `hide`, `extract`, or `capacity` mode.

### 1\. Hide Data

Embed a message, image, or file into your input video. **Use lossless encoding (`-c:v copy`)** on your video to minimize compression artifacts that can destroy the hidden LSB data.

```bash
# General Syntax
python video_steganography.py hide \
  --input <input_video.mp4> \
  --output <stego_video.mp4> \
  --data-type <text|image|file> \
  --data-input <"message" or path/to/file> \
  [--no-hamming] # Optional: omit for Hamming correction

# Example: Hiding a Text Message without Error Correction
python video_steganography.py hide \
  --input input.mp4 \
  --output stego_video.mp4 \
  --data-type text \
  --data-input "Secret message" \
  --no-hamming
# PROMPT: Enter a password (or leave empty for none).
```

### 2\. Extract Data

Retrieve the hidden data from the steganographic video.

```bash
# General Syntax
python video_steganography.py extract \
  --input <stego_video.mp4> \
  --output-dir extracted \
  [--no-hamming] # Must match the setting used during hiding

# Example: Extracting the Text Message
python video_steganography.py extract \
  --input stego_video.mp4 \
  --output-dir extracted \
  --no-hamming
# PROMPT: Enter the decryption password (or leave empty if none).
```

  * **Text Output:** Printed to the terminal and saved to `extracted/extracted_text.txt`.
  * **File Output:** Saved to `extracted/extracted_file.<extension>`.

### 3\. Check Video Capacity

Estimate the maximum data size that can be hidden in a video.

```bash
python video_steganography.py --capacity --input input.mp4
```

-----

## ⚙️ Troubleshooting LSB Corruption

LSB steganography is highly sensitive to video compression. If extraction fails, the LSBs were likely altered by FFmpeg.

| Error/Symptom | Probable Cause | Recommended Fix |
| :--- | :--- | :--- |
| **Invalid data type** or **Extraction stopped** | FFmpeg altered LSBs during hiding due to lossy encoding. | **Re-encode input video losslessly** before hiding: `ffmpeg -i 1.mp4 -c:v copy -c:a copy test_input.mp4` |
| **No output file** | Invalid frame or pixel access due to uncommon video stream parameters. | **Re-encode to a standard resolution** (e.g., 640:480): `ffmpeg -i 1.mp4 -vf scale=640:480 -c:a copy low_res.mp4` |
| **General Failure** | High data integrity requirement. | **Fallback:** Consider using a **DCT-based tool** like `SteganoTools` (see notes). |

-----

## 📂 Project Structure

```
cerberus_stegano/
├── video_steganography.py  # ▶️ Main execution script
├── requirements.txt        # 📦 Python dependencies
├── example_usage.sh        # 📜 Sample usage commands
├── README.md               # 📄 This documentation
└── LICENSE                 # ⚖️ MIT License
```

-----

## 🤝 Contributing

We welcome contributions\! Please feel free to **open an issue** or submit a **Pull Request** on GitHub.

## ⚖️ License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

## 👤 Author

  * **Sudeepa Wanigarathna**

-----

## 💡 Notes on LSB Steganography

**Caution:** This tool uses LSB steganography, which is susceptible to destruction by **lossy video compression**. For commercial or production use requiring higher reliability, consider **Discrete Cosine Transform (DCT)-based steganography** (like [SteganoTools](https://www.google.com/search?q=https://pypi.org/project/steganotools/)), which is generally more robust against re-encoding.

*Tested on Kali Linux, Python 3.8+, OpenCV 4.5.5, FFmpeg 4.4.*
