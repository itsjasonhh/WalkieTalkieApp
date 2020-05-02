# encrypt-server
Sever used to send and receive requests for encrypting audio

## Requirements
Software requirements, python version 3 or greater.
```
python >= 3
```

# Run Software
## Run Server (Listener)
In order to run the listener run the following command where 8080 is the PORT
we are listening on
```
python __main__.py 8080 --listener
```

## Run Client (Talker)
In order to run the talker run the following command where 8080 is the PORT
that the listener is listening on, and the port we want to connect to. Meaning
the port we want to send data to the listener on
```
python __main__.py 8080 --talker
```

## Software Help
Run the following command to get a help menu output of valid parameters
```
python __main__.py -h

usage: __main__.py [-h] [-t] [-l] PORT

Server Accepting and Sending Encrypt/Decrypt Request

positional arguments:
  PORT            Port for server to listen on

optional arguments:
  -h, --help      show this help message and exit
  -t, --talker    Flag used to specify the server is will send request to
                  encrpyt data
  -l, --listener  Flag used to specify the server is will send request to
                  encrpyt data
```

## Setup Virtual Environment
Setting up a virtual enviorment is a good idea in case we need to install
packages that are specific for the application
```
cd encrypt-server
virtualenv --system-site-packages -p python3 ./venv
source ./venv/bin/activiate
```

To exit out of virtual enviornment run the following command:
```
deactivate
```
