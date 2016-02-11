Shibboleth auth request module for nginx
========================================

.. image:: https://travis-ci.org/nginx-shib/nginx-http-shibboleth.svg?branch=master
   :target: https://travis-ci.org/nginx-shib/nginx-http-shibboleth

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
------------------------

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
------------

To compile nginx with this module, use the::

    --add-module <path>

option when you ``configure`` nginx.

For further information on why this is a dedicated module, see
http://forum.nginx.org/read.php?2,238523,238523#msg-238523


Configuration
-------------

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

Note that we use the `headers-more-nginx-module <https://github.com/openresty/headers-more-nginx-module>`_
to clear potentially dangerous input headers.

Gotchas
-------

* Subrequests, such as the Shibboleth auth request, aren't processed through header filters.
  This means that built-in directives like ``add_header`` will **not** work if configured
  as part of the a ``/shibauthorizer`` block.  If you need to manipulate subrequest headers,
  use ``more_set_headers`` from the module ``headers-more``.
  
  See http://forum.nginx.org/read.php?29,257271,257272#msg-257272.

* Subrequest response bodies cannot be returned to the client as Nginx does not currently
  support NGX_HTTP_SUBREQUEST_IN_MEMORY (whereby it would be buffered in memory and could
  be returned to the client) for FastCGI.  As a result, the response body from the
  Shibboleth authorizer is simply ignored.  Typically, this is worked around by having 
  Nginx serve an suitable page instead; for instance::
  
      location /secure {
         shib_request /shibauthorizer;
         error_page 403 /shibboleth-forbidden.html;
         ...
      }
      
  would serve the given page if the Shibboleth authorizer denies the user access
  to this location.  Without ``error_page`` specified, Nginx will serve its generic
  error pages.
  
  Note that this does *not* apply to the Shibboleth responder (typically hosted at
  ``Shibboleth.sso``) as it is a FastCGI responder and Nginx is fully compatible
  with this as no subrequests are used.
  
  See http://forum.nginx.org/read.php?2,238444,238453.
