This Python program is a demonstration of how the Double Ratchet encryption algorithm functions, featuring a step-by-step guide and the encrypted messages in transit. 

While this program was created with close reference to the official documentation, some liberties had to be taken as the encryption algorithm is specially designed for messaging apps. For example, the salt value in this program is set to an insecure value while messaging apps have a seperate way of generating and synchronising the salt value.

This double ratchet implementation requires a few additional libraries. You may run the .bat file to install all libraries if you do not have them. 

The program uses: pyDH, cryptography, aead.
