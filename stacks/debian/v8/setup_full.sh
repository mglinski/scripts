#!/usr/bin/env bash

#######################
# Full Stack Setup
# Debian 8 (Jesse), using systemd
# Openresty(1.7), PHP (5.6), PostgreSql(9.4), Redis(2.4), ElasticSearch(1.5), Memcached(1.4), Oracle Java 8(u45)
#
# Sites go in /www like this:
# /www/*/etc/nginx.conf     Site nginx conf file
# /www/*/ssl/*              Site specific SSL files (private key, cert, etc)
# /www/*/logs/              Site specific webserver logs
# /www/*/public/*           Site web root folder
# /www/*/data/*             Site specific misc data folder
# /www/*/tmp/*              Site Specific TMP folder
#######################

echo "---------------------------"
echo " Setup server from minimal "
echo "---------------------------"
echo
echo "Please choose some of the options below"
echo "to configure individual components."
echo "(case sensitive)"
echo

echo "Would you like to run this with everything turned on? (don't be stupid though...) [y/n]"
read RUN_DEFAULTS ; echo
if [ "$RUN_DEFAULTS" == "y" ]
then
    TIMEZONE=y
    AUTO_UPDATES=y
else

    echo "Configure timezone? [y/n]"
    read TIMEZONE ; echo

    if [ "$TIMEZONE" == "y" ]; then
        cp /usr/share/zoneinfo/UTC /etc/localtime
        echo "Timezone is now set to UTC"
    fi

    echo "Configure automatic updates? [y/n]"
    read AUTO_UPDATES ; echo

    echo "Perform a Yum update after setting up this machine? [y/n]"
    read POST_UPDATE ; echo
fi

echo "Would you like to change root password? [y/n]"
read CHANGE_ROOT ; echo

if [ "$CHANGE_ROOT" == "y" ]; then
    echo "Please enter the password to change it to"
    read -s ROOT_PASS ; echo
    echo -e "$ROOT_PASS" | ( passwd --stdin root )
    ROOT_PASS=
fi

echo "Configure hostname? [y/n]"
read NEW_HOSTNAME ; echo

if [ "$NEW_HOSTNAME" == "y" ] ; then
	echo "Please input your new hostname: "
	read HOSTNAME_URI ; echo

	# backup original hosts file
	cp /etc/hosts /etc/hosts.back

	ORIG_HOSTNAME=`cat config.txt`
	sed -i '' -e  "s/$ORIG_HOSTNAME/HOSTNAME_URI/" /etc/hosts
	cat ${HOSTNAME_URI} > /etc/hostname
fi

echo "Review your choices above and type 'y' to continue..."
read CONT_INSTALL ; echo

if [ "$CONT_INSTALL" == "y" ] ; then
	echo "Continuing install..."
	echo
else
	echo "Exiting installer."
	exit 0
fi

# install new apt repo sources
echo "deb http://packages.dotdeb.org jessie all 
deb-src http://packages.dotdeb.org jessie all" > /etc/apt/sources.list.d/dotdeb.list
echo "deb http://packages.elasticsearch.org/elasticsearch/1.5/debian stable main" > /etc/apt/sources.list.d/elasticsearch.list
echo "deb http://apt.postgresql.org/pub/repos/apt/ jessie-pgdg main" > /etc/apt/sources.list.d/pgdg.list

# install pgp keys
wget --quiet -O - http://www.dotdeb.org/dotdeb.gpg | apt-key add -
wget --quiet -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | apt-key add -
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -

# system services
SYSTEM_SERVICES=()

# system update
apt-get update
apt-get upgrade -y

# install needed base packages
apt-get install -y build-essential git curl libreadline6-dev ncurses-dev libpcre++-dev libssl-dev libgeoip-dev libxml2-dev libxslt-dev libgd2-xpm-dev libperl-dev zlib1g-dev libpcre3 libpcre3-dev

# Get latest openresty version number
curl -XGET https://github.com/openresty/ngx_openresty/tags | grep tag-name > /tmp/openresty_tag
sed -e 's/<[^>]*>//g' /tmp/openresty_tag > /tmp/openresty_ver
OPENRESTY_VER=`sed -e 's/      v//g' /tmp/openresty_ver | head -n 1` && rm -f /tmp/openresty_*
google_pagespeed

#install composer globally
curl -sS https://getcomposer.org/installer | php
chmod +x composer.phar
copy composer.phar /usr/bin/composer

# Install OpenResty init.d Script
echo '[Unit]
Description=OpenResty - high performance web server
Documentation=http://openresty.org/
After=network.target remote-fs.target nss-lookup.target
 
[Service]
Type=forking
PIDFile=/var/run/openresty.pid
ExecStartPre=/usr/sbin/openresty -t -c /etc/openresty/nginx/nginx.conf
ExecStart=/usr/sbin/openresty -c /etc/openresty/nginx/nginx.conf
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true
 
[Install]
WantedBy=multi-user.target
' > /lib/systemd/system/openresty.service

# Install OpenResty logrotate script
echo '/var/log/openresty/*.log {
        daily
        missingok
        rotate 52
        compress
        delaycompress
        notifempty
        create 640 openresty adm
        sharedscripts
        postrotate
                [ -f /var/run/openresty.pid ] && kill -USR1 `cat /var/run/openresty.pid`
        endscript
}
' > /etc/logrotate.d/openresty

# install other services
apt-get install -y redis-server postgresql-9.4 postgresql-client-9.4 postgresql-contrib-9.4 mysql-client memcached nodejs

# Add new system services to processing list
SYSTEM_SERVICES+=('postgresql')
SYSTEM_SERVICES+=('redis-server')
SYSTEM_SERVICES+=('memcached')

# Install OpenResty Group
if ! getent group openresty >/dev/null; then
   addgroup --system openresty >/dev/null
fi

# creating openresty user if he isn't already there
if ! getent passwd openresty >/dev/null; then
    adduser \
        --system \
        --disabled-login \
        --ingroup openresty \
        --no-create-home \
        --home /nonexistent \
        --gecos "openresty user" \
        --shell /bin/false \
        openresty  >/dev/null
fi

# download and cd into openresty src code
cd /root
wget http://openresty.org/download/ngx_openresty-1.7.10.1.tar.gz
tar xf ngx_openresty-1.7.10.1.tar.gz
cd ngx_openresty-1.7.10.1

# install google pagespeed
curl -L -o /tmp/ngx_pagespeed_config "https://raw.githubusercontent.com/pagespeed/ngx_pagespeed/master/config"
cat /tmp/ngx_pagespeed_config | grep "dl.google.com" > /tmp/nps_ver && sed -i 's/gz\"/gz/g' /tmp/nps_ver
PSOL="`cat /tmp/nps_ver | awk '{printf $5}'`" && rm -f /tmp/{ngx_pagespeed_config,nps_ver}

# Google Page Speed
git clone https://github.com/pagespeed/ngx_pagespeed.git
cd ngx_pagespeed && curl -LO "$PSOL" && mod_pagespeed_dir="`pwd`/psol/include"
tar xzvf *.tar.gz && cd ..

# awesome openresty vars
OPENRESTY_CACHE_PREFIX=/var/cache/openresty
OPENRESTY_LOG_PREFIX=/var/log/openresty

# Make cache folders
mkdir -p $OPENRESTY_CACHE_PREFIX/{client_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp} $OPENRESTY_LOG_PREFIX
chown -R openresty:openresty $OPENRESTY_CACHE_PREFIX $OPENRESTY_LOG_PREFIX

# Configure OpenResty
./configure \
    --with-ipv6 \
    --prefix=/etc/openresty/ \
    --sbin-path=/usr/sbin/openresty \
    --conf-path=/etc/openresty/openresty.conf \
    --error-log-path=$OPENRESTY_LOG_PREFIX/error.log \
    --http-log-path=$OPENRESTY_LOG_PREFIX/access.log \
    --pid-path=/var/run/openresty.pid \
    --lock-path=/var/run/openresty.lock \
    --http-client-body-temp-path=$OPENRESTY_CACHE_PREFIX/client_temp \
    --http-proxy-temp-path=$OPENRESTY_CACHE_PREFIX/proxy_temp \
    --http-fastcgi-temp-path=$OPENRESTY_CACHE_PREFIX/fastcgi_temp \
    --http-uwsgi-temp-path=$OPENRESTY_CACHE_PREFIX/uwsgi_temp \
    --http-scgi-temp-path=$OPENRESTY_CACHE_PREFIX/scgi_temp \
    --user=openresty \
    --group=openresty \
    --add-module=ngx_pagespeed \
    --with-file-aio \
    --with-ipv6 \
    --with-luajit \
    --with-http_realip_module \
    --with-http_addition_module \
    --with-http_xslt_module \
    --with-http_image_filter_module \
    --with-http_geoip_module \
    --with-http_sub_module \
    --with-http_flv_module \
    --with-http_iconv_module \
    --with-http_gzip_static_module \
    --with-http_random_index_module \
    --with-http_secure_link_module \
    --with-http_degradation_module \
    --with-http_stub_status_module \
    --with-http_perl_module \
    --with-pcre --with-pcre-jit --with-md5-asm --with-sha1-asm 

# Install OpenResty
make && make install

# add to system services
SYSTEM_SERVICES+=('openresty')

# back dat ass up
cd 

# Install PHP
apt-get install -y php5 php5-fpm php5-memcached php5-redis php5-imagick php5-geoip php5-curl php5-dev php5-mcrypt php5-mysqlnd php5-pgsql php5-sqlite php5-gmp

# set systemd thing
SYSTEM_SERVICES+=('php5-fpm')

# Install PHP OpCache Settings
cat > /etc/php5/mods-available/opcache.ini <<"ZOA"
; configuration for php ZendOpcache module
; priority=05
zend_extension=opcache.so
opcache.enable=1
opcache.save_comments=0
opcache.enable_file_override=1
opcache.memory_consumption=512
opcache.interned_strings_buffer=64
opcache.max_accelerated_files=16000
opcache.revalidate_freq=0
opcache.validate_timestamps=0
opcache.fast_shutdown=1
opcache.enable_cli=0
ZOA

# Install PHP.ini Settings
cat >> /etc/php5/fpm/php.ini <<"ZOB"

max_execution_time = 3000
max_input_time = 6000
expose_php = Off
short_open_tag = Off
zlib.output_compression = Off
implicit_flush = Off
memory_limit = 512M
error_reporting = E_ALL
display_errors = Off
log_errors = On
error_log = php_errors.log
post_max_size = 2G
cgi.force_redirect = 1
cgi.fix_pathinfo = 0
upload_max_filesize = 2G
max_file_uploads = 10
date.timezone = UTC
#error_log = __php-fpm.log
ZOB

# Change listen mode in php-fpm socket
sed -i 's/^;listen.mode = */listen.mode = 0666/' /etc/php5/fpm/pool.d/www.conf

# Set Openresty fastcgi_params file
cat > /etc/openresty/fastcgi_params <<"ZOC"

fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;
fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  PATH_INFO          $fastcgi_script_name;
#fastcgi_param   PATH_TRANSLATED $document_root$fastcgi_path_info;

fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI       $document_uri;
fastcgi_param  DOCUMENT_ROOT      $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  HTTPS              $https if_not_empty;

fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;

fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  REMOTE_PORT        $remote_port;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;

fastcgi_connect_timeout 300;
fastcgi_send_timeout 300;
fastcgi_read_timeout 300;
fastcgi_buffer_size 32k;
fastcgi_buffers 8 16k;
fastcgi_busy_buffers_size 256k;
fastcgi_temp_file_write_size 256k;
fastcgi_intercept_errors on;

# PHP only, required if PHP was built with --enable-force-cgi-redirect
#fastcgi_param  REDIRECT_STATUS    200;
ZOC

# Set Openresty fastcgi_eve file
cat > /etc/openresty/fastcgi_eve <<"ZOD"

fastcgi_param   HTTP_EVE_TRUSTED            $http_eve_trusted;
fastcgi_param   HTTP_EVE_SERVERIP           $http_eve_serverip;
fastcgi_param   HTTP_EVE_CHARNAME           $http_eve_charname;
fastcgi_param   HTTP_EVE_CHARID             $http_eve_charid;
fastcgi_param   HTTP_EVE_CORPNAME           $http_eve_corpname;
fastcgi_param   HTTP_EVE_CORPID             $http_eve_corpid;
fastcgi_param   HTTP_EVE_ALLIANCENAME       $http_eve_alliancename;
fastcgi_param   HTTP_EVE_ALLIANCEID         $http_eve_allianceid;
fastcgi_param   HTTP_EVE_REGIONNAME         $http_eve_regionname;
fastcgi_param   HTTP_EVE_CONSTELLATIONNAME  $http_eve_constellationname;
fastcgi_param   HTTP_EVE_SOLARSYSTEMNAME    $http_eve_solarsystemname;
fastcgi_param   HTTP_EVE_STATIONNAME        $http_eve_stationname;
fastcgi_param   HTTP_EVE_STATIONID          $http_eve_stationid;
fastcgi_param   HTTP_EVE_CORPROLE           $http_eve_corprole;
fastcgi_param   HTTP_EVE_SOLARSYSTEMID      $http_eve_solarsystemid;
fastcgi_param   HTTP_EVE_WARFACTIONID       $http_eve_warfactionid;
fastcgi_param   HTTP_EVE_SHIPID             $http_eve_shipid;
fastcgi_param   HTTP_EVE_SHIPNAME           $http_eve_shipname;
fastcgi_param   HTTP_EVE_SHIPTYPEID         $http_eve_shiptypeid;
fastcgi_param   HTTP_EVE_SHIPTYPENAME       $http_eve_shiptypename;
ZOD



# Set Openresty main config file
cat > /etc/openresty/openresty.conf <<"ZOE"

user  www-data;
worker_processes  auto;
worker_rlimit_nofile 7000000;

events {
    use epoll;
    worker_connections  10240;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    #GeoIP2 
    #geoip2 /etc/openresty/geoip2/GeoLite2-Country.mmdb {
    #     $geoip_country_code default=US country iso_code;
    #    $geoip_country_name country names en;
    #}

    #geoip2 /etc/openresty/geoip2/GeoLite2-City.mmdb {
    #    $geoip_city_name default=London city names en;
    #}

    # Mitigate Poodle Attacks
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

    server_tokens off;

    sendfile on;
    tcp_nopush  on;
    tcp_nodelay off;

    # Cache
    add_header Cache-Control "public, max-age=3153600";
    client_max_body_size 64M;
    client_body_temp_path /var/cache/openresty 1 2;

    # Main access log
    access_log   off;

    # Log directives
    log_format main '$remote_addr "$remote_user" [$time_local] '
        '"$http_host" [$status] "$request" "$body_bytes_sent" "$http_referer" '
        '"$http_user_agent" "$http_x_forwarded_for" "$request_time" "$gzip_ratio"';

    log_format json_format '{ "@time": "$time_iso8601", '
                        '"@fields": { '
                        '"host": "$remote_addr", '
                        '"user": "$remote_user", '
                        '"status": "$status", '
                        '"request": "$request", '
                        '"size": "$body_bytes_sent", '
                        '"user-agent": "$http_user_agent", '
                        '"forwarded_for": "$http_x_forwarded_for", '
                        '"request_time": "$request_time", '
                        '"bytes_sent": "$body_bytes_sent", '
                        '"referrer": "$http_referer" } }';

    log_format main_eve '$remote_addr "$remote_user" [$time_local] '
        '"$http_host" [$status] "$request" "$body_bytes_sent" "$http_referer" '
        '"$http_user_agent" "$http_x_forwarded_for" "$request_time" "$gzip_ratio"'
        '"$http_eve_charname" "$http_eve_charid" "$http_eve_corpid" "$http_eve_solarsystemid" "$http_eve_stationid" ';

    ## Timeouts
    send_timeout          5;
    keepalive_timeout     5 5;
    client_body_timeout   5;
    client_header_timeout 5;

    # OpenResty
    variables_hash_max_size 4096;
    variables_hash_bucket_size 512;
    server_names_hash_bucket_size 64;
    types_hash_max_size 8192;

    # Header
    more_set_headers "Server: dabes";

    ## General Options
    sendfile                 on;
    server_tokens           off;
    recursive_error_pages    on;
    ignore_invalid_headers   on;
    server_name_in_redirect  off;

    ## TCP options
    tcp_nodelay on;
    tcp_nopush  on;

    ## Compression
    gzip on;
    gzip_disable "msie6";

    gzip              on;
    gzip_static       on;
    gzip_buffers      16 8k;
    gzip_comp_level   9;
    gzip_http_version 1.0;
    gzip_min_length   0;
    gzip_vary         on;
    gzip_proxied      any;
    gzip_types        text/plain text/css text/xml text/javascript application/x-javascript application/xml application/xml+rss application/json;


    # PHP Upstream
    include /etc/openresty/global/php_upstream.conf;

    # default deny server
    server {
        listen *:80 default;
        server_name _;

        location / {
            deny all;
        }
    }

    include /home/*/etc/nginx.conf;
    include /www/*/etc/nginx.conf;
}
ZOE

# make folder to store awesome global config files
mkdir /etc/openresty/global/

# Set Openresty global/locations.conf file
cat > /etc/openresty/global/locations.conf <<"ZOF"
# setup some helper location blocks
location = /favicon.ico {
    log_not_found off;
    access_log off;
}

location = /robots.txt {
    allow all;
    log_not_found off;
    access_log off;
}

# Deny all attempts to access hidden files such as .htaccess, .htpasswd, .DS_Store (Mac).
# Keep logging the requests to parse later (or to pass to firewall utilities such as fail2ban)
location ~ /\. {
    deny all;
}

# Directives to send expires headers and turn off 404 error logging.
location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
    expires 24h;
    log_not_found off;
}
ZOF

# Set Openresty global/logging_remote.conf file
cat > /etc/openresty/global/logging_remote.conf <<"ZOF"
access_log syslog:server=unix:/dev/log,facility=local7,tag=nginx,severity=info main;
error_log syslog:server=unix:/dev/log,facility=local7,tag=nginx,severity=error;
ZOF

# Set Openresty global/php_upstream.conf file
cat > /etc/openresty/global/php_upstream.conf <<"ZOF"
# PHP Upstream
upstream php { 
    server unix:/var/run/php5-fpm.sock;
}
ZOF

# Set Openresty global/php.conf file
cat > /etc/openresty/global/php.conf <<"ZOF"
location ~ [^/]\.php(/|$) {
    try_files $uri =404;

    fastcgi_split_path_info ^(.+?\.php)(/.*)$;
    if (!-f $document_root$fastcgi_script_name) {
            return 404;
    }

    include fastcgi_params;
    include fastcgi_eve;

    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_pass php;
}
ZOF

# Set Openresty global/ssl.conf file
cat > /etc/openresty/global/ssl.conf <<"ZOF"
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA;

ssl_session_timeout 10m;
ssl_session_cache shared:SSL:256m;

ssl_stapling on;
ssl_stapling_verify on;

## verify chain of trust of OCSP response using Root CA and Intermediate certs
ssl_trusted_certificate /etc/cacert.pem;

resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 10s;

# Security Headers
add_header Strict-Transport-Security max-age=15768000;
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header X-Content-Type-Options "nosniff";
add_header X-Download-Options "noopen";
ZOF

# PHP-FPM Socket: /var/run/php5-fpm.sock

# Get Oracle JAVA 8 x86
wget --no-cookies \
--no-check-certificate \
--header "Cookie: oraclelicense=accept-securebackup-cookie" \
"http://download.oracle.com/otn-pub/java/jdk/8u45-b14/jdk-8u45-linux-x64.tar.gz" \
-O /tmp/jdk-8-linux-x64.tar.gz

# install oracle java
mkdir /opt/java-oracle
tar -zxf /tmp/jdk-8-linux-x64.tar.gz -C /opt/java-oracle
JHome=/opt/java-oracle/jdk1.8.0_45
update-alternatives --install /usr/bin/java java ${JHome%*/}/bin/java 20000
update-alternatives --install /usr/bin/javac javac ${JHome%*/}/bin/javac 20000

# Install ElasticSearch 1.5
apt-get install elasticsearch
SYSTEM_SERVICES+=('elasticsearch')

# install iojs
# curl https://raw.githubusercontent.com/creationix/nvm/v0.24.1/install.sh | bash
# nvm install iojs

# loop through all enabled system services and set them for startup on boot and start them now
for service_name in "${SYSTEM_SERVICES[@]}"
do
    systemctl enable ${service_name}.service
    systemctl start ${service_name}.service
done