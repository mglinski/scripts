## System Scripts

Some of my system install scripts, mainly for debian. More will prolly be added soon.

### Debian 

Includes system setup scriptes for installing this software stack in debian servers using active and popular repos wherever possible:

* (http://openresty.org/)[Openresty] (latest) [Nginx custom configuration with LUA scripting capabilities]
* (http://php.net)[PHP] (latest, 5.6) [Popular web scripting/programming language, php-fpm]
* (http://www.postgresql.org/)[PostgreSql] (9.4.*) [SQL Database Server]
* (http://redis.io)[Redis] (2.4.x) [KVS Database with helpful datatypes and functionality]
* (https://www.elastic.co/products/elasticsearch)[ElasticSearch] [FullText Supported Document Index and Warehouse]
* (http://memcached.org/)[Memcached] (1.4.x) [In Memory Data Blob cache]
* (https://www.oracle.com/java/index.html)[Oracle Java] (v8, latest update) [Jaa Programming Language, needed for ElasticSearch]

Some platform specific notes below:

#### 8 (Jessie)

* Most up to date build system
* Full support for systemd

#### 7 (Wheezy)

* Includes init script for openresty
* Needs generic changes backported from the v8 script

## License 

MIT Licensed

## Copyright

(c) 2015 Matthew Glinski
