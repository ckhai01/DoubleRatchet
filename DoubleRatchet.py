import os
import pyDH
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from aead import AEAD
from time import sleep

def init():
    #a work-around since this program is using many libraries with different formats.
    aeadkey=AEAD.generate_key()
    msgkey=AEAD(aeadkey)
    return msgkey.mac_key
    

def generate_dh():
    #generates diffie hellman key pairs and obtains the shared key.
    d1 = pyDH.DiffieHellman()
    d2 = pyDH.DiffieHellman()
    d1_pubkey = d1.gen_public_key()
    d2_pubkey = d2.gen_public_key()
    d1_sharedkey = d1.gen_shared_key(d2_pubkey)
    d2_sharedkey = d2.gen_shared_key(d1_pubkey)
    d1_sharedkey = d2_sharedkey
    return d1, d2

def encrypt(msgkey, plaintext, ad):
    ct = msgkey.encrypt(plaintext, ad)
    return ct
    
def decrypt(msgkey, ciphertext, ad):
    pt=msgkey.decrypt(ciphertext, ad)
    return pt
    

def generate_key(salt, msg):
    #info is set to a default, secret value. Ideally this should not be plain text. 
    info = b"double-ratchet example"
    hkdf = HKDF(
        #we use SHA256 as recommended by Signal
        algorithm=hashes.SHA256(),
        
        #Key length needed to be 65 so that we can split it in 2. 
        length=64,
        
        #the salt is the sender's root key if it is not the first message, 
        #otherwise it is set to another default value. 
        salt=salt,
        info=info,
    )
    #input key is the diffie hellman public key. Needs to be converted to bytes for this program.
    inputkey=bytes(str(msg), 'utf-8')
    
    #executes the KDF with the specified parameters and input key. 
    key = hkdf.derive(inputkey)
    
    #splits big key to 2. 
    rootkey=key[0:31]
    chainkey=key[32:64]
    return rootkey, chainkey


def generate_chainkey(chainkey, rootkey):
    global mackey
    salt=rootkey
    info = b"double-ratchet example"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=info,
    )    
    key = hkdf.derive(chainkey)
    newchain=key[0:31]
    encryptionkey=key[32:64]
    aeadkey=AEAD.generate_key()
    msgkey=AEAD(aeadkey)
    msgkey.encryption_key=encryptionkey
    msgkey.mac_key=mackey
    return newchain, msgkey

def send_message(iterations):
    
    for i in range(iterations):
        global mackey
        count=1
        d1,d2=generate_dh()
        
        if count==1:
            salt=b"first"
        else:
            salt=aliceroot
        
        #alice's side
        mackey=init()
        associated_data=b"Message verifier"
        aliceroot, alicechain=generate_key(salt, d1.shared_key)
        alicechain, alicemessage=generate_chainkey(alicechain, aliceroot)
        print("POV: You are Alice")
        msg=input("Enter a message for your best friend Bob: ")
        bmsg=bytes(msg, 'utf-8')
        ct=encrypt(alicemessage, bmsg, associated_data)
        print("Cipher text:", ct)
        
        #bob's side
        print("\nBob receives ciphertext", ct)
        sleep(1.5)
        associated_data=b"Message verifier"
        if count==1:
            salt=b"first"
        else:
            salt=bobroot    
        bobroot, bobchain=generate_key(salt, d1.shared_key)
        bobchain, bobmessage=generate_chainkey(bobchain, bobroot)
        try:
            pt=decrypt(bobmessage, ct, associated_data)
            print("Plain text:", pt)
            print()
        except:
            print("Message has been altered! Decryption is not possible")
        count+=1

def send_messageExplain(iterations):
    global mackey
    count=1
    for i in range(iterations):
        input("Step 1: Establish Diffie Hellman public key")
        d1,d2=generate_dh()
        print("DH Public key:", d1.shared_key)
        
        input("\nStep 2: Check if this is the first message sent")
        if count==1:
            print("This is the first message. Salt will be set to a default value.")
            salt=b"first"
        else:
            print("This is no longer the first message. Salt will be set to Alice's Rootkey.")
            salt=aliceroot
        
        
        #alice's side
        print("On Alice's side: ")
        mackey=init()
        input("\nStep 3: Establish associated data.")
        associated_data=b"Message verifier"
        input("\nStep 4: Using established salt and Diffie Hellman shared key, generate one key using a Key Derivation Function")
        aliceroot, alicechain=generate_key(salt, d1.shared_key)
        print("Whole key:", aliceroot, alicechain)
        input("\nStep 5: Split 64 bit key to two 32 bit keys: one called the root key, and the other called the chain key.")
        print("Alice's rootkey:", aliceroot)
        print("Alice's chain key:", alicechain)
        input("\nStep 6: Using chain key and root key, generate another 64 bit key using the same KDF.")
        alicechain, alicemessage=generate_chainkey(alicechain, aliceroot)
        input("\nStep 7: Split 64 bit key into two 32 bit keys: the new chain key, and the message key.")
        print("Alice's new chain key:", alicechain)
        print("Alice's message key:", alicemessage.encryption_key)
        print("Now Alice can send her message.")
        msg=input("Enter a message for Bob: ")
        bmsg=bytes(msg, 'utf-8')
        input("\nStep 8: Encrypt plaintext with generated message key using AEAD. After encryption, this message key is disposed.")
        print("Associated Data is appended in order to verify message.")
        ct=encrypt(alicemessage, bmsg, associated_data)
        print("Cipher text:", ct)
        
        #bob's side
        print("\nOn Bob's side: ")
        print("Bob receives ciphertext", ct)
        associated_data=b"Message verifier"
        input("\nStep 9: Check if this is the first message received.")
        if count==1:
            print("This is the first message received. Salt will be set to the same default value.")
            salt=b"first"
        else:
            print("This is not the first message received. Salt will be set to Bob's root key.")
            salt=bobroot    
        input("\nStep 10: Using established salt and Diffie Hellman shared key, generate one key using a Key Derivation Function")
        input("Note: Since salt and Diffie Hellman are the same, the output will be the same as Alice.")
        input("\nStep 11: Split 64 bit key to two 32 bit keys, same as the process on Alice's side.")
        bobroot, bobchain=generate_key(salt, d1.shared_key)
        print("Bob's root key:", bobroot)
        print("Bob's chainkey:", bobchain)
        input("\nStep 12: Using chain key and root key, generate another 64 bit key using the same KDF.")
        input("\nStep 13: Split 64 bit key into two 32 bit keys: the new chain key, and the message key.")
        bobchain, bobmessage=generate_chainkey(bobchain, bobroot)
        print("Bob's new chain key:", bobchain)
        print("Bob's message key:", bobmessage.encryption_key)
        input("\nStep 14: Decrypt message using message key.")
        try:
            pt=decrypt(bobmessage, ct, associated_data)
            print("Plain text:", pt)
        except:
            print("Message has been altered! Decryption is not possible")
        count+=1
        input("Message has been successfully sent and received. A new pair of diffie Hellman keys will be generated.")

def display_menu(menu):
    if menu=="main":
        print("Welcome to your friendly neighbourhood Double Ratchet Demonstration!")
        print("[1] Start encryption process")
        print("[2] Start detailed encryption process")
        print("[3] Instructions")
        print("[0] Exit")
    elif menu=="instruction":
        print("\nThis simple implementation of the Double Ratchet encryption system demonstrates")
        print("the key generation, encryption, and decryption process.")
        print("The message entered is the one that will be sent from Alice, and Bob will receive the ciphertext.")
        print("Due to the one-time nature of the keys, decryption of a user-provided ciphertext is not available.")
        print("\nSelecting option 2 will allow the program to display additional information,")
        print("like what keys are used and how they are derived.")
        print("")

while True:
    display_menu("main")
    try:
        choice=int(input("Enter choice: "))
    except:
        print("Not a number.")
        continue
    if choice==1:
        count=int(input("Number of messages encrypted: "))
        send_message(count)
        continue
        
    if choice==2:
        print("Warning: Due to the lengthy nature of the explanation, we do not recommend sending more than 3 messages.")
        count=int(input("Number of messages encrypted: "))
        send_messageExplain(count)
        continue
    elif choice==3:
        display_menu("instruction")
    elif choice==0:
        print("Exiting...")
        break
    else:
        print("Incorrect input.")
        continue
    
    