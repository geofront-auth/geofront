#!/bin/bash
if [[ $VIRTUAL_ENV = "" ]]; then
    echo You seem not using virtualenv.  Try pyvenv command.
    exit 1
fi
if [[ ! $(which pip | grep $VIRTUAL_ENV) ]]; then
    pushd /tmp
    if [[ $(which wget) ]]; then
        wget https://raw.github.com/pypa/pip/master/contrib/get-pip.py
    else
        if [[ $(which curl) ]]; then
            curl -O https://raw.github.com/pypa/pip/master/contrib/get-pip.py
        else
            echo "You need wget or curl at least."
            exit 1
        fi
    fi
    python get-pip.py
    popd
fi
pip install -f https://github.com/spoqa/sftpserver/releases -e .[tests] flake8
py.test --cov geofront tests
flake8
