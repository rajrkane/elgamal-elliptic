# elgamal-elliptic
An command-line implementation of the Elgamal public-key cryptosystem using elliptic curves. Uses 2048-bit primes that are congruent to 3 modulo 4. 
Divides the plaintext into blocks of 128 characters. Converts each block to an integer by interpreting the ASCII encodings of the 
characters in the block as the base-256 digits of the integer.

<h2>To use</h2>

To generate your public and private keys, run ```python3 GenerateKeys.py```. This will save the keys in ```my_elgamal_public_key.txt``` 
and ```my_elgamal_private_key.txt```. 

To encrypt your plaintext, have your plaintext file saved as ```plaintext.txt``` in the same directory. Run ```python3 Encryption.py```, 
and the ciphertext will be saved to ```elgamal_encrypted_message.txt```. 

To decrypt some ciphertext, run ```python3 Decryption.py```. The decrypted plaintext will be saved to ```elgamal_decrypted_message.txt```.
