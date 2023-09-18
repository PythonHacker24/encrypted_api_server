from encrypter import encrypt, decrypt
from flask import Flask, request, jsonify  
import json 
import random
import string

app = Flask(__name__)

length = 20
temporary_database = []     # dictionaries would be stored inside these dictionary
letters = string.ascii_letters
password = ''.join(random.choice(letters) for _ in range(length))

def encrypter(data_object):
    private_key = data_object['private_key']

    encryption_data = {}
    salt, encrypted_key = encrypt(private_key, password) 
    encryption_data["salt"] = salt
    encryption_data["encrypted_key"] = encrypted_key

    storage_object = {}
    storage_object[data_object['client_tag']] = encryption_data

    temporary_database.append(storage_object)

@app.route('/api', methods=['POST'])
def database_update():
    try:
        data = request.get_json()
        encrypter(data)
        print(temporary_database)
        return jsonify({'recieve_status': 'success'})
    except Exception as e:
        print("Exception: \n" + str(e))
        return jsonify({'recieve_status': 'failed'})

@app.route('/fetch', methods=['POST'])
def fetch_data():
    try:
        data = request.get_json()
        client_tag = data['client_tag']
        for i in range(len(temporary_database)):
            if client_tag == temporary_database[i].keys()[0]:
                decrypted_key = decrypt(temporary_database[i][client_tag][encrypted_key], temporary_database[i][client_tag][salt], password)

        return jsonify("{" + str(decrypted_key) + "}")

    except Exception as e:
        print("Exception: " + str(e))
        return jsonify("{Failed!}")
    
