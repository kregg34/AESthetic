## Ransomware Sample for Testing

A hybrid ransomware sample that uses AES-256 in CBC mode and RSA-2048 to encrypt the AES key. Automatically decrypts files after a predefined amount of time (10 seconds). Currently undetected by antivirus programs as of early 2021. Creates a random initialization vector for each file. Connects to a command and control server currently set to local host in order to decrypt the AES symmetric key after the predefined waiting time.
