## Ransomware Sample for Testing

A hybrid ransomware sample that uses AES-256 in CBC mode and RSA-2048 to encrypt the AES key. Automatically decrypts files after a predefined amount of time (100 seconds). Currently undetected by antivirus programs as of 2023. Creates a random initialization vector for each file. Connects to a command and control server currently set to local host in order to decrypt the AES symmetric key (using an RSA private key) after the predefined waiting time. Places ransom notes. By default, it only encrypts .pdf, .docx, and .txt files. It will, by default, only target a folder on the Desktop called "testFolder". Tested on Windows, Linux, and MacOS.

## Usage

After compiling the files, open two cmd/terminal windows. First run CommandAndControl and then once thats running, run the Ransomware file.

javac *.java

java CommandAndControl

java Ransomware

## Disclaimer

This program is purely for academic/educational use. Someone who can transform this program into a real/practical malicious payload likely had the know-how to do it from scratch anyways.
