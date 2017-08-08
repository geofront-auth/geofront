# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
    config.vm.box = "ubuntu/trusty64"
    config.vm.network "private_network", ip: "192.168.33.10"
    config.vm.synced_folder ".", "/home/vagrant/geofront"

    config.vm.provision "shell", inline: <<-SHELL
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip libffi-dev libssl-dev

        # Install redis
        cd /home/vagrant
        echo "Downloading http://download.redis.io/redis-stable.tar.gz..."
        wget -q http://download.redis.io/redis-stable.tar.gz
        tar xvzf redis-stable.tar.gz
        cd redis-stable
        make
        make install
        cd utils
        echo -n | ./install_server.sh

        # Re-do some symlinks
        rm -f /usr/bin/python /usr/bin/pip
        ln -s /usr/bin/python3 /usr/bin/python
        ln -s /usr/bin/pip3 /usr/bin/pip

        # Install redis pip module
        pip install redis

        # Upgrade setuptools
        pip install setuptools --upgrade

        # Install geofront in dev mode
        cd /home/vagrant/geofront
        python setup.py develop
    SHELL
end