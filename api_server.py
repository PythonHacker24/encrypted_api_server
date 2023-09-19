#! /usr/share/python3

from encrypter import encrypt, decrypt
from flask import Flask, request, jsonify  
import json 
import random
import string
import time 
import requests

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

def user_auth(did):

    url = 'http://127.0.0.1:5000/verify'
    data = {'did': did}
    headers = {'Content-Type': 'application/json'}

    data_json = json.dumps(data)
    payload = requests.post(url, data=data_json, headers=headers)

    if payload.status_code == 200:
        print("Verification request sent successfully")
        response = json.loads(payload.text)
        if response['signal'] == 'verified':
            return 'verified'
        if response['signal'] == 'unverified':
            return 'unverified'

    else:
        print("Verification request failed")
        print(payload.text)
        return 'failed'

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
        did = data['did']
        
        auth_status = user_auth(did)
        if auth_status == 'verified':

            for i in range(len(temporary_database)):
                data_dict = temporary_database[i]
                dict_keys = list(data_dict.keys())
                current_client_tag = dict_keys[0]
    
                if client_tag == current_client_tag:
                    salt = data_dict[client_tag]['salt']
                    encrypted_key = data_dict[client_tag]['encrypted_key']
                    decrypted_key = decrypt(encrypted_key, salt, password)
    
                    return jsonify({"decrypted_key": decrypted_key})
            
            return jsonify({"status": "not found!"})

        if auth_status == 'unverified':
            return jsonify({'status': 'unauthorised'})

    except Exception as e:
        print(str(e))
        return jsonify({'status': 'failed to retrieve data'})
    

