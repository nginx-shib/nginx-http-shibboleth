# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

# Choose how many times to run each request in a test block
repeat_each(1);

# Each `TEST` in __DATA__ below generates a block for each pattern match
# count. Increase the magic number accordingly if adding new tests or
# expanding checks in existing tests (this will add more blocks).
plan tests => repeat_each() * (50);

# Populate config for the dynamic module, if requested
our $main_config = '';
my $SHIB_DYNAMIC_MODULE = $ENV{'SHIB_DYNAMIC_MODULE'};
if ($SHIB_DYNAMIC_MODULE && $SHIB_DYNAMIC_MODULE eq 'true') {
    my $SHIB_MODULE_PATH = $ENV{'SHIB_MODULE_PATH'} ? $ENV{'SHIB_MODULE_PATH'} : 'modules';
    $main_config = "load_module $SHIB_MODULE_PATH/ngx_http_headers_more_filter_module.so;
                    load_module $SHIB_MODULE_PATH/ngx_http_shibboleth_module.so;";
}

our $config = <<'_EOC_';
        # 401 must be returned with WWW-Authenticate header
        location /test1 {
            shib_request /noauth;
        }

        # 401 must be returned with WWW-Authenticate header
        # X-From-Main-Request header **must** be returned.
        location /test2 {
            more_set_headers 'X-From-Main-Request: true';
            shib_request /noauth;
        }

        # 403 must be returned
        # X-Must-Not-Be-Present header **must not** be returned.
        location /test3 {
            shib_request /noauth-forbidden;
        }

        # 403 must be returned and final response have custom header.
        location /test4 {
            more_set_headers 'X-From-Request: true';
            shib_request /noauth-forbidden;
        }

        # 301 must be returned and Location header set
        location /test5 {
            add_header X-Main-Request-Add-Header Foobar;
            shib_request /noauth-redir;
        }

        # 301 must be returned and custom header set
        # This proves that a subrequest's headers can be manipulated as
        # part of the main request.
        location /test6 {
            more_set_headers 'X-From-Main-Request: true';
            shib_request /noauth-redir;
        }

        # 404 must be returned; a 200 here is incorrect
        # Check the console output from ``nginx.debug`` ensure lines
        # stating ``shib request authorizer copied header:`` are present.
        # Variable-* headers **must not** be present.
        location /test7 {
            shib_request /auth;
            shib_request_use_headers on;
        }

        # 200 for successful auth is required
        # X-From-Main-Request header **must** be returned.
        location /test8 {
            more_set_headers 'X-From-Main-Request: true';
            shib_request /auth;
            shib_request_use_headers on;
        }

        # 403 must be returned with correct Content-Encoding, Content-Length,
        # Content-Type, and no Content-Range
        location /test9 {
            shib_request /noauth-ignored-headers;
        }

        # 403 must be returned with overwritten Server and Date headers
        location /test10 {
            shib_request /noauth-builtin-headers;
        }

        # 200 for successful auth is required
        # X-From-Main-Request header **must** be returned.
        # Headers MUST NOT be copied to the backend
        location /test11 {
            more_set_headers 'X-From-Main-Request: true';
            shib_request /auth;
            shib_request_use_headers off;
        }

        ####################
        # Internal locations
        ####################

        # Mock backend authentication endpoints, simulating shibauthorizer
        # more_set_headers is used as Nginx header filters (add_header) ignore subrequests
        location /noauth {
            internal;
            more_set_headers 'WWW-Authenticate: noauth-block' 'X-From-Subrequest: true';
            return 401 'Not authenticated';
        }

        # more_set_headers is used as Nginx header filters (add_header) ignore subrequests
        location /noauth-redir {
            internal;
            more_set_headers 'X-From-Subrequest: true';
            return 301 https://sp.example.org;
        }

        # more_set_headers is used as Nginx header filters (add_header) ignore subrequests
        location /noauth-forbidden {
            more_set_headers 'X-From-Subrequest: true';
            return 403 "Not allowed";
        }

        # more_set_headers is used as Nginx header filters (add_header) ignore subrequests
        location /noauth-ignored-headers {
            more_set_headers 'Content-Encoding: wrong';
            more_set_headers 'Content-Length: 100';
            more_set_headers 'Content-Type: etc/wrong';
            more_set_headers 'Content-Range: 0-100';
            return 403 "Not allowed";
        }

        # more_set_headers is used as Nginx header filters (add_header) ignore subrequests
        location /noauth-builtin-headers {
            more_set_headers 'Server: FastCGI';
            more_set_headers 'Date: today';
            more_set_headers 'Location: https://sp.example.org';
            return 403 "Not allowed";
        }

        # more_set_headers is used as Nginx header filters (add_header) ignore subrequests
        location /auth {
            internal;
            more_set_headers "Variable-Email: david@example.org";
            more_set_headers "Variable-Commonname: davidjb";
            return 200 'Authenticated';
        }
_EOC_

worker_connections(128);
no_shuffle();
no_diff();
ok(1 eq 1, "Dummy test, no Nginx");
run_tests();

__DATA__

=== TEST 1: Testing 401 response
--- config eval: $::config
--- main_config eval: $::main_config
--- request
GET /test1
--- error_code: 401
--- response_headers
WWW-Authenticate: noauth-block
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/

=== TEST 2: Testing 401 response with main request header
--- config eval: $::config
--- main_config eval: $::main_config
--- request
GET /test2
--- error_code: 401
--- response_headers
X-From-Main-Request: true
WWW-Authenticate: noauth-block
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/

=== TEST 3: Testing 403 response with main request header
--- config eval: $::config
--- main_config eval: $::main_config
--- request
GET /test3
--- error_code: 403
--- response_headers
X-Must-Not-Be-Present:
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/

=== TEST 4: Testing 403 response with main request header
--- config eval: $::config
--- main_config eval: $::main_config
--- request
GET /test4
--- error_code: 403
--- response_headers
X-From-Request: true
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/

=== TEST 5: Testing redirection with in-built header addition
--- config eval: $::config
--- main_config eval: $::main_config
--- request
GET /test5
--- error_code: 301
--- response_headers
Location: https://sp.example.org
X-Main-Request-Add-Header: Foobar
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/

=== TEST 6: Testing redirection with subrequest header manipulation in main request
--- config eval: $::config
--- main_config eval: $::main_config
--- request
GET /test6
--- error_code: 301
--- response_headers
Location: https://sp.example.org
X-From-Main-Request: true
X-From-Subrequest: true
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/

=== TEST 7: Testing successful auth, no leaked variables
--- config eval: $::config
--- main_config eval: $::main_config
--- user_files
>>> test7
Hello, world
--- request
GET /test7
--- error_code: 200
--- response_headers
Variable-Email:
Variable-Commonname:
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/
--- grep_error_log eval
qr/shib request.*/
--- grep_error_log_out eval
qr/copied header/

=== TEST 8: Testing successful auth, no leaked variables, main request headers set
--- config eval: $::config
--- main_config eval: $::main_config
--- user_files
>>> test8
Hello, world
--- request
GET /test8
--- error_code: 200
--- response_headers
Variable-Email:
Variable-Commonname:
X-From-Main-Request: true
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/
--- grep_error_log eval
qr/shib request.*/
--- grep_error_log_out eval
qr/shib request authorizer copied header:/

=== TEST 9: Testing no auth with correct headers; subrequest header changes are ignored
--- config eval: $::config
--- main_config eval: $::main_config
--- request
GET /test9
--- error_code: 403
--- response_headers
Content-Encoding:
Content-Type: text/html
Content-Range:
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/

=== TEST 10: Testing no auth with overwritten headers; subrequest header changes are ignored
--- config eval: $::config
--- main_config eval: $::main_config
--- request
GET /test10
--- error_code: 403
--- response_headers_like
Server: FastCGI
Date: today
Location: https://sp.example.org
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/

=== TEST 11: Testing successful auth, no leaked variables, no headers set
--- config eval: $::config
--- main_config eval: $::main_config
--- user_files
>>> test11
Hello, world
--- request
GET /test11
--- error_code: 200
--- response_headers
Variable-Email:
Variable-Commonname:
X-From-Main-Request: true
--- timeout: 10
--- no_error_log eval
qr/\[(warn|error|crit|alert|emerg)\]/
--- grep_error_log eval
qr/shib request.*/
--- grep_error_log_out eval
qr/shib request authorizer not using headers/
