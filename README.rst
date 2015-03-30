Shibboleth auth request module for nginx
========================================

This module allows authorization based on the result of a subrequest to
Shibboleth.  Once a subrequest returns 2xx status - access is allowed; on 401
or 403 - access is disabled with an appropriate status.

For 40x statuses, the WWW-Authenticate header from the subrequest response
will be passed to client.  All other subrequest response statuses (such as 3xx
redirects) are passed back to the client, including status and headers.  This
mostly conforms to the FastCGI Authorizer specification, with the exception of
the processing of the sub-request and sub-response bodies due to limitations
in Nginx. As the Shibboleth FastCGI authorizer does not consider the contents
of a request body or use response bodies, this is not an issue.

The module works at access phase and therefore may be combined nicely with
other access modules (access, auth_basic) via satisfy directive.


Configuration directives
========================

.. warning::

   The ``shib_request`` directive no longer requires the ``shib_authorizer``
   flag.  This must be removed for Nginx to start. No other changes are
   required.

::

    shib_request <uri>|off

        Context: http, server, location
        Default: off

        Switches the Shibboleth auth request module on and sets uri which will be 
        asked for authorization.  The configured uri should refer to a Nginx
        location block that points to your Shibboleth FastCGI authorizer.

        The HTTP status and headers of the response resulting
        from the sub-request to the configured uri will be returned to the user,
        in accordance with the FastCGI Authorizer
        specification; see http://www.fastcgi.com/drupal/node/22#S6.3.
        The one (potentially significant) caveat is that due to the way
        Nginx operates at present with regards to subrequests (what
        an Authorizer effectively requires), the request body will *not* be
        forwarded to the authorizer, and similarly, the response body from
        the authorizer will *not* be returned to the client. 

        Configured URIs are not restricted to using a FastCGI backend
        to generate a response, however.  This may be useful during
        testing or otherwise, as you can use Nginx's built in ``return``
        and ``rewrite`` directives to produce a suitable response.
        Additionally, this module may be used with *any* FastCGI
        authorizer, although operation may be affected by the above caveat.

    shib_request_set <variable> <value>

        Context: http, server, location
        Default: none

        Set request variable to the given value after auth request completion.
        Value may contain variables from auth request, e.g. $upstream_http_*.


Installation
============

To compile nginx with this module, use the::

    --add-module <path>

option when you ``configure`` nginx.

For further information on why this is a dedicated module, see
http://forum.nginx.org/read.php?2,238523,238523#msg-238523


Configuration
=============

For full details about configuring the Nginx/Shibboleth environment,
see the documentation at
https://github.com/nginx-shib/nginx-http-shibboleth/blob/master/CONFIG.rst.

A simple example consists of the following::

    # FastCGI authorizer for Shibboleth Auth Request module
    location = /shibauthorizer {
        internal;
        include fastcgi_params;
        fastcgi_pass unix:/opt/shibboleth/shibauthorizer.sock;
    }

    # A secured location. All incoming requests query the Shibboleth FastCGI authorizer.
    # Watch out for performance issues and spoofing.
    location /secure {
        more_clear_input_headers 'Variable-*' 'Shib-*' 'Remote-User' 'REMOTE_USER' 'Auth-Type' 'AUTH_TYPE';

        # Add your attributes here. They get introduced as headers
        # by the FastCGI authorizer so we must prevent spoofing.
        more_clear_input_headers 'displayName' 'mail' 'persistent-id';

        shib_request /shibauthorizer;
        # Backend application that will receive Shibboleth variables as request
        # headers from the FastCGI authorizer
        proxy_pass http://localhost:8080;
    }


