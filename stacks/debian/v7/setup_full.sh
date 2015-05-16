#!/usr/bin/env bash

#######################
# Full Stack Setup
# Debian 7 (Wheezy), using init.d
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


echo "
deb http://packages.dotdeb.org wheezy all
deb-src http://packages.dotdeb.org wheezy all

deb http://packages.dotdeb.org wheezy-php56 all
deb-src http://packages.dotdeb.org wheezy-php56 all
" >> /etc/apt/sources.list.d/php.list

echo "deb http://packages.elasticsearch.org/elasticsearch/1.0/debian stable main" > /etc/apt/sources.list.d/elasticsearch.list

echo "deb http://apt.postgresql.org/pub/repos/apt/ wheezy-pgdg main" > /etc/apt/sources.list.d/pgdg.list

wget --quiet -O - http://www.dotdeb.org/dotdeb.gpg | apt-key add -
wget --quiet -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | apt-key add -
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -

apt-get update
apt-get upgrade

apt-get install -y git curl build-essential libreadline6-dev ncurses-dev libpcre++-dev libssl-dev libgeoip-dev libxml2-dev libxslt-dev libgd2-xpm-dev libperl-dev zlib1g-dev libpcre3 libpcre3-dev

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
echo '#!/bin/sh
### BEGIN INIT INFO
# Provides:          openresty
# Required-Start:    $network $remote_fs $local_fs
# Required-Stop:     $network $remote_fs $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Stop/start openresty
### END INIT INFO

# Author: Sergey Budnevitch <sb@nginx.com>

PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC=openresty
NAME=openresty
CONFFILE=/etc/openresty/openresty.conf
DAEMON=/usr/sbin/openresty
DAEMON_ARGS="-c $CONFFILE"
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME

[ -x $DAEMON ] || exit 0

[ -r /etc/default/$NAME ] && . /etc/default/$NAME

. /lib/init/vars.sh

. /lib/lsb/init-functions

do_start()
{
    start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON -- \
        $DAEMON_ARGS
    RETVAL="$?"
    return "$RETVAL"
}

do_stop()
{
    # Return
    #   0 if daemon has been stopped
    #   1 if daemon was already stopped
    #   2 if daemon could not be stopped
    #   other if a failure occurred
    start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE --name $NAME
    RETVAL="$?"
    rm -f $PIDFILE
    return "$RETVAL"
}

do_reload() {
    #
    start-stop-daemon --stop --signal HUP --quiet --pidfile $PIDFILE --name $NAME
    RETVAL="$?"
    return "$RETVAL"
}

do_configtest() {
    if [ "$#" -ne 0 ]; then
        case "$1" in
            -q)
                FLAG=$1
                ;;
            *)
                ;;
        esac
        shift
    fi
    $DAEMON -t $FLAG -c $CONFFILE
    RETVAL="$?"
    return $RETVAL
}

do_upgrade() {
    OLDBINPIDFILE=$PIDFILE.oldbin

    do_configtest -q || return 6
    start-stop-daemon --stop --signal USR2 --quiet --pidfile $PIDFILE --name $NAME
    RETVAL="$?"
    sleep 1
    if [ -f $OLDBINPIDFILE -a -f $PIDFILE ]; then
        start-stop-daemon --stop --signal QUIT --quiet --pidfile $OLDBINPIDFILE --name $NAME
        RETVAL="$?"
    else
        echo $"Upgrade failed!"
        RETVAL=1
        return $RETVAL
    fi
}

case "$1" in
    start)
        [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC " "$NAME"
        do_start
        case "$?" in
            0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
            2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
        esac
        ;;
    stop)
        [ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
        do_stop
        case "$?" in
            0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
            2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
        esac
        ;;
  status)
        status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
        ;;
  configtest)
        do_configtest
        ;;
  upgrade)
        do_upgrade
        ;;
  reload|force-reload)
        log_daemon_msg "Reloading $DESC" "$NAME"
        do_reload
        log_end_msg $?
        ;;
  restart|force-reload)
        log_daemon_msg "Restarting $DESC" "$NAME"
        do_configtest -q || exit $RETVAL
        do_stop
        case "$?" in
            0|1)
                do_start
                case "$?" in
                    0) log_end_msg 0 ;;
                    1) log_end_msg 1 ;; # Old process is still running
                    *) log_end_msg 1 ;; # Failed to start
                esac
                ;;
            *)
                # Failed to stop
                log_end_msg 1
                ;;
        esac
        ;;
    *)
        echo "Usage: $SCRIPTNAME {start|stop|status|restart|reload|force-reload|upgrade|configtest}" >&2
        exit 3
        ;;
esac

exit $RETVAL
' > /etc/init.d/openresty

chmod +x /etc/init.d/openresty
update-rc.d openresty defaults

mkdir /var/cache/openresty/
chown -R openresty:openresty /var/cache/openresty/

apt-get install -y redis-server postgresql-9.4 postgresql-client-9.4 postgresql-contrib-9.4 mysql-client memcached

update-rc.d postgresql defaults
update-rc.d redis-server defaults
update-rc.d memcached defaults

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

cd /root
wget http://openresty.org/download/ngx_openresty-1.7.10.1.tar.gz
tar xf ngx_openresty-1.7.10.1.tar.gz
cd ngx_openresty-1.7.10.1

# Install OpenResty Group
./configure --with-ipv6 --with-luajit --prefix=/etc/openresty/ --sbin-path=/usr/sbin/openresty --conf-path=/etc/openresty/openresty.conf --error-log-path=/var/log/openresty/error.log --http-log-path=/var/log/openresty/access.log --pid-path=/var/run/openresty.pid --lock-path=/var/run/openresty.lock --http-client-body-temp-path=/var/cache/openresty/client_temp --http-proxy-temp-path=/var/cache/openresty/proxy_temp --http-fastcgi-temp-path=/var/cache/openresty/fastcgi_temp --http-uwsgi-temp-path=/var/cache/openresty/uwsgi_temp --http-scgi-temp-path=/var/cache/openresty/scgi_temp --user=openresty --group=openresty
make && make install

cd /root

# Install PHP
apt-get install -y php5 php5-fpm php5-memcached php5-redis php5-imagick php5-geoip php5-curl php5-dev php5-mcrypt php5-mysqlnd php5-pgsql php5-sqlite

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
short_open_tag = On
zlib.output_compression = Off
implicit_flush = Off
memory_limit = 512M
error_reporting = E_ALL
display_errors = On
log_errors = On
error_log = php_errors.log
post_max_size = 2G
cgi.force_redirect = 1
cgi.fix_pathinfo=0
upload_max_filesize = 2G
max_file_uploads = 2
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

fastcgi_connect_timeout 5;
fastcgi_send_timeout 180;
fastcgi_read_timeout 180;
fastcgi_buffer_size 128k;
fastcgi_buffers 4 256k;
fastcgi_busy_buffers_size 256k;
fastcgi_temp_file_write_size 256k;
fastcgi_intercept_errors on;

# PHP only, required if PHP was built with --enable-force-cgi-redirect
#fastcgi_param  REDIRECT_STATUS    200;
ZOC

# Set Openresty fastcgi_params file
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



# Set Openresty fastcgi_params file
cat > /etc/openresty/openresty.conf <<"ZOE"

user  www-data;
worker_processes  2;

events {
    worker_connections  4096;
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
    client_max_body_size 64M;
    client_body_temp_path /var/cache/openresty 1 2;
    types_hash_max_size 8192;
    log_format main '$remote_addr "$remote_user" [$time_local] '
        '"$http_host" "$request" "$status" "$body_bytes_sent" "$http_referer" '
        '"$http_user_agent" "$http_x_forwarded_for" "$request_time" "$gzip_ratio"'
        '"$http_eve_charname" "$http_eve_charid" "$http_eve_corpid" "$http_eve_solarsystemid" "$http_eve_stationid" ';

    keepalive_timeout  3;
    client_body_timeout 1800;

    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_min_length 1024;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_comp_level 5;
    gzip_proxied any;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml application/xml+rss application/json;

    variables_hash_max_size 4096;
    variables_hash_bucket_size 512;

    # PHP Upstream
    include /etc/openresty/global/php_upstream.conf;

    # Default Server Block
    server {
        listen       80 default_server;
        server_name  localhost;

        #charset koi8-r;

        location / {
            root   html;
            index  index.html index.htm;
        }

        #location /nginx_status {
        #   stub_status on;
        #   access_log   off;
        #   allow 127.0.0.1;
        #   deny all;
        # }


        #location ~ ^/(phpstatus|phpping)$ {
        #    include fastcgi_params;
        #    access_log off;
        #
        #    fastcgi_pass php;
        #    fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
        #
        #    allow 127.0.0.1;
        #    deny all;
        #}

        error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

    }

    #include sites-enabled/*.conf;
    #include /home/*/etc/openresty/*.conf;
    include /home/*/etc/nginx.conf;
    include /www/*/etc/nginx.conf;
}
ZOE

mkdir /etc/openresty/global/

logging_remote.conf
php_upstream.conf
php.conf
ssl.conf

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

resolver 8.8.4.4 8.8.8.8 valid=300s;
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

mkdir /opt/java-oracle
tar -zxf /tmp/jdk-8-linux-x64.tar.gz -C /opt/java-oracle

JHome=/opt/java-oracle/jdk1.8.0_45
update-alternatives --install /usr/bin/java java ${JHome%*/}/bin/java 20000
update-alternatives --install /usr/bin/javac javac ${JHome%*/}/bin/javac 20000

# Start up ElasticSearch!
apt-get install elasticsearch
update-rc.d elasticsearch defaults 95 10

# install `iojs`
apt-get install curl
curl https://raw.githubusercontent.com/creationix/nvm/v0.24.1/install.sh | bash
nvm install iojs

# Startup services
service mysql start
service redis-server start
service memcached start
service openresty start
service elasticsearch start