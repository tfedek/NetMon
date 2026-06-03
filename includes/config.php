<?php
define('DB_HOST',    'localhost');
define('DB_PORT',    '3306');
define('DB_NAME',    'netmon');
define('DB_USER',    'root');
define('DB_PASS',    '');
define('DB_CHARSET', 'utf8mb4');

define('APP_NAME',     'NetMon');
define('APP_URL',      'http://localhost/netmon_v4');
define('APP_ENV',      'development');
define('APP_TIMEZONE', 'Europe/Belgrade');

define('JWT_SECRET',      'f8969e1ef91dc14413c9c1875c046f55');
define('JWT_ALGO',        'HS256');
define('JWT_TTL',         3600);
define('CSRF_TOKEN_NAME', '_csrf');
define('SESSION_LIFETIME', 3600);
define('BCRYPT_COST',     12);

define('MAIL_HOST',      'smtp.gmail.com');
define('MAIL_PORT',      587);
define('MAIL_USER',      'fedek.maxbet@gmail.com');
define('MAIL_PASS',      'dzlpbofvofvwwvkf');
define('MAIL_FROM',      'noreply@netmon.local');
define('MAIL_FROM_NAME', 'NetMon');
define('MAIL_ENCRYPTION', 'tls');

define('GEO_API_URL', 'http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,query');

define('CHECK_TIMEOUT',  3);
define('CHECK_INTERVAL', 300000);

define('LOGIN_MAX_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_TIME', 900);

date_default_timezone_set(APP_TIMEZONE);
error_reporting(E_ALL);
ini_set('display_errors', 1);
