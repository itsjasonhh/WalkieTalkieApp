#!/usr/bin/env python3
"""
    Script to start a client connection to server. (Talker)
"""
import socket
import json
import datetime
import copy
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from encryptlib.json_message import JsonMessage
from encryptlib.print_helper import PrintHelper

BUFFER_SIZE = 4096
KEY_BIT_SIZE = 4000

g = int("""9677178152764243356585979556264224589944191744979699073371576738861236
        5663820546922607619786124954900448084138704336019707101781113070799068
        5744514558595068941725067952556006237862391064159647193542530329259333
        4424851756939418426847120076462424229265080004033026690789716709345894
        8676163784692008959171172634206184380581278989999081666391528267108503
        9813609522242829719587993249808317734238106660385861768230295679126590
        8390972444782203928717828427457583267560097495187522617809715033399571
        0124142927808606451916188467080375525692807503004072582957175996256741
        6958199028585508053574180142683126826804771118716296486230523760774389
        7157494791542352379311268259974895147341335235499016003307513390038990
        1582196141853936279863966997543171337135092681583084518153432642302837
        0436056697857918994988629688023563560002153140124962200937852164145182
        1610847931627295268929335901602846813690082539801509776517015975714046
        5455848263618069464889478247144935435822126939965077545376582476552939
        5288811662441509565199205733657279155210616750060391443188845224391244
        5982465119470715706942563826139640100216780957119233780885476576542097
        8318327126238727841787217270826207296485682133095572761510633060271315""".replace(" ", "").replace("\n", ""))

p = int("""2773513095749167337576358874942831569385761553923082020361322269992944
        8489006798120232791463013505228500900024049333039459029366992215417394
        0703109337560451078293297821188778260938274928421790028940882569457077
        8270715497001472804773372159699487464437256876108641279314813575799288
        0353560828726390302647822163531592190925834713707675874151479095828997
        9709275760692869280803757520668776451222054720062078905947201506921948
        2248258148634825249349597280042484353178956233483223727571140311838306
        9497997993896536595853659564600179648675284862073335665278820295284039
        2441154268228992660874384047813295938635270043470524847835602162062324
        6182957756186469188241103927864116660349640671385022766484753851141361
        3324705366794734356249759513986782234719409680441184269264165474240174
        7019497972779105025866714266206768504640255640079527841905839126323963
        3600041551667467165519541808705130094613958692430907777974227738480151
        9284479867895217795687886082284763600753200413473134257852188910038101
        0022934537091672256327978299054218233790927484338926431601990283936699
        4034965244475466733634646851920984543901636177633543005383561910647171
        8158178526713140623881625988429186051133467385983636059069118372099145
        33050012879383""".replace(" ", "").replace("\n", ""))

class Client(object):
    def __init__(self, server, port):
        """
        Default constructor for the client implementation
        """
        self.server = server
        self.port = port
        self.clientsocket = None
        self.request = None
        self.pprint = PrintHelper()

        # TODO: needs to be dynamic this is representative of reveiver public key
        key = RSA.generate(KEY_BIT_SIZE)
        public_key = key.publickey()
        self.recv_key = key
        self.recv_public_key = public_key
        #TODO: need access to the public and private keys

    def init(self):
        """
        Function to initialize client socket
        """
        # Create an INET, STREAMing socket
        self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to server
        self.clientsocket.connect((self.server, self.port))

    def create_sess_key(self):
        """
        Function to create sess key
        """
        # 1. create a 256 bit session key
        key = str(int.from_bytes(get_random_bytes(KEY_BIT_SIZE), byteorder='little'))
        nonce = str(int(datetime.datetime.now().timestamp() * 1000))

        sess_key = {
            key: key,
            nonce: nonce
        }

        self.json_request.dhke_data["payload"]["sess_key"] = sess_key

    def encrypt_sess_key(self):
        """
        Function used to encrypt the sess_key object by the receivers public key
        """
        sess_key = copy.copy(self.json_request.dhke_data["payload"]["sess_key"])
        sess_key = json.dumps(sess_key)

        raw_bytes = bytes(sess_key, 'UTF-8')
        sess_key_int = int.from_bytes(raw_bytes, byteorder='little')

        sess_key_encrypted = pow(sess_key_int, self.recv_public_key.e, self.recv_public_key.n)

        sess_key_encrypted_str = str(sess_key_encrypted)

        self.json_request.dhke_data["sess_key"] = sess_key_encrypted_str

    def hash_sess_key(self):
        """
        Function used to hash the sess key, needed to encryp the payload
        """
        m = hashlib.sha3_512()
        m.update(bytes(self.json_request.dhke_data["sess_key"], 'UTF-8'))

        byte_value = m.digest()
        hash_sess_str = str(int.from_bytes(byte_value, byteorder='little'))

        self.json_request.dhke_data["payload"]["agreement_data"]["hash_sess_key"] = hash_sess_str

    def generate_diffie_pub_key(self):
        """
        Function used to generate the our public diffie hellman key based on g and p values
        """
        diffie_pub_key = pow(g, self.recv_key.d, p)
        diffie_pub_key_str = str(diffie_pub_key)

        self.json_request.dhke_data["payload"]["agreement_data"]["diffie_pub_k"] = diffie_pub_key_str

    def sign_agreement_data(self):
        """
        Function used to sign the payload messgae before encryption
        """
        # get raw data_agreement info
        data_raw = json.dumps(self.json_request.dhke_data["payload"]["agreement_data"])

        m = hashlib.sha3_512()
        m.update(bytes(data_raw, 'UTF-8'))

        hash_bytes = m.digest()
        hash_int = int.from_bytes(hash_bytes, byteorder='little')

        signature = str(pow(hash_int, self.recv_key.d, self.recv_public_key.n))
        self.json_request.dhke_data["payload"]["signature"] = signature

    def encrypt_agreement_data():
        """
        Function used to encrypt the agreement data using conter mode.
        """
        #TODO: need to encrypt data useing counter mode
        pass

    def build_request(self):
        """
        Function used to build the initial request
        """
        self.json_request = JsonMessage()

        self.json_request.set_json_payload()
        self.create_sess_key()
        self.encrypt_sess_key()

        self.hash_sess_key()
        self.generate_diffie_pub_key()

        self.sign_agreement_data()

        self.encrypt_agreement_data()

        # Determine length of JSON payload
        length = len(self.json_request.__str__())
        length_str = '{:08d}'.format(length)

        # form entire request
        self.request = '{0}{1}{2}'.format('1', length_str, self.json_request.__str__())
        self.pprint.sent('\nRequest <<<\n----------\n{0}\n----------'.format(self.request))

    def is_valid_response(self, response):
        """
        Function used to validate response
        """
        resp_type = response[0]
        resp_length = response[1:9]

        if resp_type != '2':
            return False

        try:
            length  = int(resp_length)
        except ValueError:
            # sent us data that is NOT just digits 0-9
            return False

        payload = response[9: length + 9]

        try:
            self.json_response = json.loads(payload)
        except json.JSONDecodeError:
            # invalid JSON object
            return False

        self.pprint.received('\nResponse >>>\n----------\n{0}\n----------'.format(response))
        return True


    def run(self):
        """
        Function used to run client connection to server
        """
        self.build_request()
        self.clientsocket.sendall(bytes(self.request, 'UTF-8'))

        while True:
            in_data = self.clientsocket.recv(BUFFER_SIZE)
            msg = in_data.decode()

            if self.is_valid_response(msg):
                print('Valid Response')
                # 1. get key info
                # 2. If valid response we need to send audio
            else:
                # else close connection
                self.clientsocket.close()

            break

