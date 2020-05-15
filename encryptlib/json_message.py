"""
    Object to handle json message Request and Response
"""
import json
import datetime

WHO_SENT = "ShelterInPlaceHackers"

class JsonMessage(object):
    def __init__(self):
        """
        Default constructor for JsonMessage class object
        """
        self.dhke_data = {
            "payload": {
                "TOD": 0,
                "agreement_data": {
                    "who_sent": WHO_SENT,
                    "sender_public_key": 0,
                    "diffie_pub_k": 0,
                    "generator": 0,
                    "modulus": 0,
                },
                "signature": 0
            },
            "sess_key": {
                "key": None,
                "nonce": None
            }
       }

    def set_json_payload(self):
        """
        Function used to handle creating the json message
        response or request
        """
        # Currently not passing parameters, but might need to change
        self.set_agreement_data()
        self.set_signature()
        self.set_sess_key()

        epoch = datetime.datetime.now().timestamp() * 1000
        epoch = int(epoch)
        self.dhke_data["payload"]["TOD"] = epoch

    def set_agreement_data(self):
        """
        Function used to handle setting agreement data parameters
        """
        self.dhke_data["payload"]["agreement_data"]["sender_public_key"] = 696969
        self.dhke_data["payload"]["agreement_data"]["diffie_pub_k"] = 696969
        self.dhke_data["payload"]["agreement_data"]["generator"] = 696969
        self.dhke_data["payload"]["agreement_data"]["modulus"] = 696969

    def set_signature(self):
        """
        Function used to handle setting signature
        """
        self.dhke_data["payload"]["signature"] = 696969

    def set_sess_key(self):
        """
        Function used to set sess key parameters
        """
        self.dhke_data["sess_key"]["key"] = 696969
        self.dhke_data["sess_key"]["key"] = 696969

    def __str__(self):
        """
        Function to return json object as string
        """
        return json.dumps(self.dhke_data)