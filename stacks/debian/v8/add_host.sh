#!/bin/sh

# start with a fresh terminal
clear

echo "---------------------------"
echo "    Make new nginx host    "
echo "---------------------------"
echo
echo "Please choose some of the options below"
echo "to configure individual components."
echo "(case sensitive)"
echo

echo "Configure new nginx host? [Y/n]"
read NEW_HOSTNAME ; echo

if [ "$NEW_HOSTNAME" == "y" ] ; then
	echo "Please input your new nginx host name: "
	read HOSTNAME_URI ; echo
fi

echo "Review your choices above and type 'y' to continue..."
read CONT_INSTALL ; echo

if [ "$CONT_INSTALL" == "y" ] ; then
	echo "Continuing setup..."
	echo
else
	echo "Exiting setup."
	exit 0
fi

#--------------------#
# Start System Stuff #
#--------------------#

# build initinal host folders under /www
mkdir -p /www/$HOSTNAME_URI/{etc,ssl,logs,public,data,tmp}

# /www/*/etc/nginx.conf     Site nginx conf file
# /www/*/ssl/*              Site specific SSL files (private key, cert, etc)
# /www/*/logs/              Site specific webserver logs
# /www/*/public/*           Site web root folder
# /www/*/data/*             Site specific misc data folder
# /www/*/tmp/*              Site Specific TMP folder

# Install EveSpark Nginx Conf File
cat > /www/${HOSTNAME_URI}/etc/nginx.conf <<"ZOA"
server {
    listen                          80;
    server_name                     www.${HOSTNAME_URI} ${HOSTNAME_URI};
    rewrite                         ^ https://${HOSTNAME_URI}\$request_uri? permanent;
}

server {

    listen                          443;
    server_name                     ${HOSTNAME_URI};

    # SSL Switch
    ssl on;

    # SSL Certs
    ssl_certificate                 /www/${HOSTNAME_URI}/ssl/${HOSTNAME_URI}.pem;
    ssl_certificate_key             /www/${HOSTNAME_URI}/ssl/${HOSTNAME_URI}.key;

    # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits
    ssl_dhparam /www/${HOSTNAME_URI}/ssl/dhparam.pem;

    # Include Generic SSL Setup
    include /etc/openresty/global/ssl.conf;

    # Security Headers
    #add_header X-Permitted-Cross-Domain-Policies "master-only";
    #add_header Content-Security-Policy "default-src 'self'; script-src 'self' cdnjs.cloudflare.com ajax.googleapis.com; style-src 'self' cdnjs.cloudflare.com ajax.googleapis.com; img-src *";
    #add_header X-Content-Security-Policy "default-src 'self'; script-src 'self' cdnjs.cloudflare.com ajax.googleapis.com; style-src 'self' cdnjs.cloudflare.com ajax.googleapis.com; img-src *";

    # Public Key HTTP Pinning Header
    #add_header Public-Key-Pins 'pin-sha256="FSyRHRit2OOSWTDXfS7/F0ExhcWB743N0xvMrQIftek="; pin-sha256="ol+4bItasNLG0z/5RWBJrdWJcXf/RIT1NQfZMeRox5w="; max-age=15768000;';

    root   /www/${HOSTNAME_URI}/public;
    index index.php;

    # Include remote logging directives
    include /etc/openresty/global/logging_remote.conf;

    access_log         /www/${HOSTNAME_URI}/logs/access.log main;
    error_log         /www/${HOSTNAME_URI}/logs/error.log;

    underscores_in_headers on;

    autoindex                       off;
    charset                         utf8;

    # setup some helper location blocks
    include /etc/openresty/global/locations.conf;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    # This site serves PHP files
    include /etc/openresty/global/php.conf;
}
ZOA

# setup an index.php file with phpinfo()
echo "<?php phpinfo();" > /www/${HOSTNAME_URI}/public/index.php

# setup basic ssl stuff
cd /www/${HOSTNAME_URI}/ssl
openssl req -sha256 -out ${HOSTNAME_URI}.csr -new -newkey rsa:4096 -nodes -keyout ${HOSTNAME_URI}.key

# fix permissions for nginx + php-fpm
chown -R openresty /www/${HOSTNAME_URI}
# service openresty restart

echo "*********************"
echo "  Generating DHPARAM File, this will take a while  "
echo "*********************"
openssl dhparam -out dhparam.pem 4096

cd /www/${HOSTNAME_URI}

echo "*********************"
echo "  Install Complete!  "
echo "*********************"

# exit clean
exit 0