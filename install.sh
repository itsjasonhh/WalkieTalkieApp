#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
    echo "This script must be ran as root"
    exit 1
fi

handle_help() {
    echo -e "Usage: install.sh [MODE]\n"
    echo -e "install.sh - Installation script for CSE 234 Project Encryption/Decryption.\n"
    echo -e "Positional Arguments:"
    echo -e "[MODE] {develop, deploy}\tsets the installation mode of the application.\n"
    echo -e "Optional Arguments:"
    echo -e "-h, --help\t\tDisplays this help menu."
    echo -e "-v, --version\t\tDisplays the version."

    return $1
}

handle_version() {
    echo -e "version 0.1"

    return 0
}

handle_deploy() {
    pip3 install . --upgrade

    return 0
}

handle_develop() {
    python3 setup.py develop

    return 0
}

handle_error() {
    echo -e "Unhandle argument received...\n"
    handle_help 1
}

install_requirements() {
    pip3 install -r ./requirements.txt

    return 0
}

if [ -z "$@" ]
then
    handle_help 1
fi;

while [ "$1" != "" ];
do
    case $1 in
        -h | --help)
            handle_help
            exit 0
            shift
            ;;
        develop)
           install_requirements
           handle_develop
           exit 0
           ;;
        deploy)
           install_requirements
            handle_deploy
            exit 0
            ;;
        *)
            handle_error
            exit 1
            ;;
    esac
    shift
done
