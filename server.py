'''


	Author = Berke Kocadere
	Date = 25.06.2022 
	Version = 1.0
	
	This program is a simple Pretty Good Privacy (PGP) Secure Protocol simulation for Receiver Side. MD5, RSA, ZIP, AES and BASE64 Encoding are used. Work flow of the program is shown below. 
	
	Receiver side 
	1. Receiver receives data from Sender. 
	2. Data is BASE64 decoded.  
	3. Decoded data is splitted to encrypted one-time message key and encrypted zipped data.
	4. Encrypted one-time message key is decrypted with RSA using Receiver Private Key. 
	5. Encrypted zipped data is decrypted with AES using one-time message key. 
	6. Zipped data is unzipped and splitted to encrypted MD5 Hashed value and Original message plain text.  
	7. Encrypted MD5 Hashed Value is decrypted with RSA using Receiver Private Key. 
	8. Original message Plain text is hashed with same MD5 algorithm and compared with MD5 Hashed Value. If it's the same, PGP Protocol was succesful. 
	
	
'''

# Imports 
import socket
import sys 
import base64 
import traceback
import hashlib 
import zlib
from ast import literal_eval
from Crypto.PublicKey import RSA 
from Crypto.Random import get_random_bytes 
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import MD5  



'''
	Function : RSA Key Generator
	
	Description :
		This function creates RSA private and public key for Client and 
		store them in file system as PEM format.
	
	Return : key 
	
'''
def RSA_keyGen(): 
	# RSA Private and Public Key Generation for Client
	key = RSA.generate(2048)

	private_key = key.export_key()
	file_out = open("server_private.pem", "wb")
	file_out.write(private_key)
	file_out.close()

	public_key = key.publickey().export_key()
	file_out = open("server_public.pem","wb")
	file_out.write(public_key)
	file_out.close()
	
	return key 



'''
	Function : TCP Server Connection 
	
	Description : 
		This function creates a TCP Server.  
	
	 Return : server  

'''
def serverConnection(): 
	# Client connection 
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	host = "127.0.0.1"
	port = 15000 

	server.bind((host, port))
	server.listen(1)
	
	return server
	

	
'''
	Function : Print Data 
	
	Description : 
		This function is used for printing length, type and content of a variable.
	
	Return : None 

'''
def printData(data, dataString): 
	print("\n\n")
	print("\n{} len : {}\n".format(dataString,len(data)))
	print("\n{} type : {}\n".format(dataString,type(data)))
	print("\n{} : \n".format(dataString))
	print(data)



# RSA Private and Public Key Generation for Server
key = RSA_keyGen() 
# Server Connection
server = serverConnection()

# Wait for a client connection 
while True: 
	print("Waiting for a connection...")
	try: 
		connection, client_address = server.accept() # Connection accepted 
		while True: 
			print("Client connected : " , str(client_address))
			
			# Receive data from client in 'dataFromClient'
			dataFromClient = connection.recv(3096).decode() 
			dataFromClient_str = "dataFromClient"
			printData(dataFromClient, dataFromClient_str)
			
			# RSA Encryption Setup 
			cipher_RSA = PKCS1_OAEP.new(key) 
			
			# Encode data in 'data_bytes'
			data_bytes = dataFromClient.encode("ascii") # data_bytes = base64_bytes
			data_bytes_str = "data_bytes_str"
			printData(data_bytes, data_bytes_str)
			
			# Decode data with Base 64 Decoding in 'concat_data_v2_bytes' 
			concat_data_v2_bytes = base64.b64decode(data_bytes)
			concat_data_v2_bytes_str = "concat_data_v2_bytes" 
			printData(concat_data_v2_bytes, concat_data_v2_bytes_str) 
			
			# Decode concatenated data in 'concat_data_v2'
			concat_data_v2 = concat_data_v2_bytes.decode("ascii")
			concat_data_v2_str = "concat_data_v2"
			printData(concat_data_v2, concat_data_v2_str) 
			
			# Split concatenated data into list in 'concat_data_v2_list'
			concat_data_v2_list = concat_data_v2.split("!!!")
			concat_data_v2_list_str = "concat_data_v2_list"
			printData(concat_data_v2_list, concat_data_v2_list_str)
			
			# Get Encrypted zipped data in 'ciphertext_string' 
			ciphertext_string = concat_data_v2_list[0]
			ciphertext_string_str = "ciphertext_string"
			printData(ciphertext_string, ciphertext_string_str)
			
			ciphertext = literal_eval(ciphertext_string)
			ciphertext_str = "ciphertext"
			printData(ciphertext, ciphertext_str)
			
			# Get Encrypted session key in 'enc_session_key_string'
			enc_session_key_string = concat_data_v2_list[1]
			enc_session_key_string_str = "enc_session_key_string"
			printData(enc_session_key_string, enc_session_key_string_str)
			

			enc_session_key = literal_eval(enc_session_key_string)
			enc_session_key_str = "enc_session_key"
			printData(enc_session_key, enc_session_key_str)
			
			# Get nonce value in 'nonce_string'
			nonce_string = concat_data_v2_list[2]
			nonce_string_str = "nonce_string"
			printData(nonce_string, nonce_string_str)			
			
			nonce = literal_eval(nonce_string)
			nonce_str = "nonce"
			printData(nonce, nonce_str)
			
			# Encrypted session key is decrypted with RSA using Server's Private Key in 'session_key' 
			session_key = cipher_RSA.decrypt(enc_session_key)
			session_key_str = "session_key"
			printData(session_key, session_key_str)
			
			# AES Encryption Setup 
			cipher_AES = AES.new(session_key, AES.MODE_EAX, nonce)
			
			# Decrypt Encrypted zipped data with RSA using session key in 'zip_data'
			zip_data = cipher_AES.decrypt(ciphertext)
			zip_data_str = "zip_data"
			printData(zip_data, zip_data_str)

			# Decompress zipped data in 'concat_data_bytes'
			concat_data_bytes = zlib.decompress(zip_data) 
			concat_data_bytes_str = "concat_data_bytes"
			printData(concat_data_bytes, concat_data_bytes_str)

			# Decode concatenated data in 'concat_data'
			concat_data = concat_data_bytes.decode("ascii") 
			concat_data_str = "concat_data"
			printData(concat_data, concat_data_str)  
			
			# Split concatenated data into list in 'concat_data_list'
			concat_data_list = concat_data.split("!!!")
			concat_data_list_str = "concat_data_list"
			printData(concat_data_list, concat_data_list_str)
			
			# Plain text message in 'plain_text'
			plain_text = concat_data_list[1] 
			plain_text_str = "plain_text" 
			printData(plain_text, plain_text_str)
			
			# Hashed message 'data_RSA_text'
			data_RSA_text = concat_data_list[0]
			data_RSA_text_str = "data_RSA_text"
			printData(data_RSA_text, data_RSA_text_str)
			
			data_RSA = literal_eval(data_RSA_text)
			data_RSA_str = "data_RSA"
			printData(data_RSA, data_RSA_str)
			
			# Decrpyt Encrypted hashed value with RSA using Server's Public Key 
			data_md5_bytes = cipher_RSA.decrypt(data_RSA)
			data_md5_bytes_str = "data_md5_bytes"
			printData(data_md5_bytes, data_md5_bytes_str)
			
			# Encode plaintext for later use in 'plain_text_bytes'
			plain_text_bytes = plain_text.encode("ascii")
			plain_text_bytes_str = "plain_text_bytes" 
			printData(plain_text_bytes, plain_text_bytes)
			
			# Hash message with MD5
			plaintext_md5 = hashlib.md5(plain_text_bytes) 
			plaintext_md5_bytes = plaintext_md5.digest()
			plaintext_md5_bytes_str = "plaintext_md5_bytes"
			printData(plaintext_md5_bytes, plaintext_md5_bytes_str)
			
			# Compare received hashed value and received plain text hashed with same algorithm  
			if data_md5_bytes == plaintext_md5_bytes:
			
				 ### PGP On Receiver Side is Done #### 
				 print(" PGP OPERATION SUCCESFUL ! ")
				 print(" Client has sent the message : \n")
				 print(plain_text)
			
			elif dataFromClient == "Exit": 
				break 
			else: 
				### PGP OPERATION FAILED  ###
				print(" PGP OPERATION FAILED ! ") 
				continue 
	except: 
		traceback.print_exc() 


