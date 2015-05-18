## System Scripts

Some of my system install scripts, mainly for debian. More will prolly be added soon.

### Debian 

Includes system setup scriptes for installing this software stack in debian servers using active and popular repos wherever possible:

* [Openresty](http://openresty.org/) (latest) [Nginx custom configuration with LUA scripting capabilities]
* [PHP](http://php.net) (latest, 5.6) [Popular web scripting/programming language, php-fpm]
* [PostgreSql](http://www.postgresql.org/) (9.4.*) [SQL Database Server]
* [Redis](http://redis.io) (2.4.x) [KVS Database with helpful datatypes and functionality]
* [ElasticSearch](https://www.elastic.co/products/elasticsearch) [FullText Supported Document Index and Warehouse]
* [Memcached](http://memcached.org/) (1.4.x) [In Memory Data Blob cache]
* [Oracle Java](https://www.oracle.com/java/index.html) (v8, latest update) [Jaa Programming Language, needed for ElasticSearch]

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
