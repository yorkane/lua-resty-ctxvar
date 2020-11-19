# https://metacpan.org/pod/Test::Nginx::Socket
use Test::Nginx::Socket::Lua 'no_plan';

log_level('info');

our $HttpConfig = <<'_EOC_';
    lua_socket_log_errors off;
    lua_package_path 'lib/?.lua;/usr/local/share/lua/5.3/?.lua;/usr/share/lua/5.1/?.lua;;';
_EOC_

run_tests();

__DATA__

=== TEST 1: sanity
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
			local ctx = require('resty.ctxvar')
			--ctx.main()
            ctx.test()
        }
    }
--- more_headers
host: www.mock.com
content-type: text/json
connection: closed
accept-encoding: gzip, deflate
accept-language: en-US
user-agent: nginx_test
referer: http://referer.com/uri
cookie: ccs=11
--- request
GET //t////q?a=1&b=2&c=3&d=&e
--- no_error_log
[error]
--- error_code: 200
--- response_body_like
url=http://www\.mock\.com:\d+/t/q\?a=1&b=2&c=3&d=&e

=== TEST 2: Post test
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
			local ctx = require('resty.ctxvar')
            ctx.test()
        }
        log_by_lua_block {
            require('resty.ctxvar').test()
        }
    }
--- more_headers
host: www.mock.com
content-type: text/json
connection: closed
accept-encoding: gzip, deflate
accept-language: en-US
user-agent: nginx_test
--- request
POST /t/t.jpg?c=&d=1
TEST_Request_body_text
--- no_error_log
[error]
--- error_code: 200
--- response_body_like
body=TEST_Request_body_text
content_length=22
header.accept-encoding=gzip, deflate
header.user-agent=nginx_test


