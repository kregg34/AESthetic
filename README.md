## Ransomware Sample for Testing

A hybrid ransomware sample that uses AES-256 in CBC mode and RSA-2048 to encrypt the AES key. Automatically decrypts files after a predefined amount of time (10 seconds). Currently undetected by antivirus programs as of early 2021. Creates a random initialization vector for each file. Connects to a command and control server currently set to local host in order to decrypt the AES symmetric key after the predefined waiting time. Places ransom notes. By default, it only encrypt .pdf, .docx, and .txt files. It will, by default, only target a folder on the Desktop called "testFolder". Tested on Windows, Linux, and MacOS.

## Useage

After compiling the files, open two cmd/terminal windows. First run CommandAndControl and then once thats running, run the Ransomware file.
