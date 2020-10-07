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
--- request
GET /t/q?a=1&b=2&c=3
--- no_error_log
[error]
--- error_code: 200


