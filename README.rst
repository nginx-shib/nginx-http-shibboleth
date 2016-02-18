Shibboleth auth request module for nginx
========================================

.. image:: https://travis-ci.org/nginx-shib/nginx-http-shibboleth.svg?branch=master
   :target: https://travis-ci.org/nginx-shib/nginx-http-shibboleth

This module allows Nginx to work with Shibboleth, by way of Shibboleth's
FastCGI authorizer.  This module requires specific configuration in order to
work correctly, as well as Shibboleth's FastCGI authorizer application
available on the system.

With this module configured against a ``location`` block, incoming requests
are authorized within Nginx based upon the result of a subrequest to
Shibboleth's FastCGI authorizer.  In this process, this module will copy user
attributes from a successful authorizer response into Nginx's original request
as headers for use by any backend application.  If authorization is not
successful, the authorizer response status and headers are returned to the
client, denying access or redirecting the user's browser accordingly (such as
to a WAYF page, if so configured).  Read more about the `Behaviour`_ below and
consult `Configuration`_ for important notes on avoiding spoofing.

This module works at access phase and therefore may be combined with other
access modules (such as ``access``, ``auth_basic``) via the ``satisfy``
directive.  This module can be also compiled alongside
``ngx_http_auth_request_module``, though use of both of these modules in the
same ``location`` block is untested and not advised.

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
    # Watch out for performance issues and spoofing!
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
to clear potentially dangerous input headers and avoid the potential for
spoofing.

Gotchas
~~~~~~~

* Subrequests, such as the Shibboleth auth request, aren't processed through header filters.
  This means that built-in directives like ``add_header`` will **not** work if configured
  as part of the a ``/shibauthorizer`` block.  If you need to manipulate subrequest headers,
  use ``more_set_headers`` from the module ``headers-more``.

  See http://forum.nginx.org/read.php?29,257271,257272#msg-257272.

Behaviour
---------

This module follows the `FastCGI Authorizer spec`_ where possible, but has
some notable deviations - with good reason.  The behaviour is thus:

* An authorizer subrequest is comprised of all aspects of the original
  request, excepting the request body as Nginx does not support buffering of
  request bodies.  As the Shibboleth FastCGI authorizer does not consider the
  request body, this is not an issue.

* If an authorizer subrequest returns a ``200`` status, access is
  allowed and response headers beginning with ``Variable-\*`` are extracted,
  stripping the ``Variable-`` substring from the header name, and copied into
  the main request. For example, an authorizer response header such as
  ``Variable-CN: John Smith`` would result in ``CN: John Smith`` being added
  to the main request, and thus sent onto any backend configured.

  As per the spec, however, other authorizer response headers not prefixed
  with ``Variable-`` and the response body are ignored.

  The spec calls for ``Variable-*`` name-value pairs to be included in the
  FastCGI environment, but we make them headers so as they may be used with
  *any* backend (such as ``proxy_pass``) and not just restrict ourselves to
  FastCGI applications.  By passing the ``Variable-*`` data as headers instead,
  we end up following the behaviour of ``ShibUseHeaders On`` in ``mod_shib`` for
  Apache, which passes these user attributes as headers.

  Note that the passing of attributes as environment variables (the equivalent
  to ``ShibUseEnvironment On`` in ``mod_shib``) is not currently supported;
  pull requests are welcome to add this behaviour.

* If the authorizer subrequest returns *any* other status (including redirects
  or errors), the authorizer response's status and headers are returned to the
  client.

  This means that on ``401 Unauthorized`` or ``403 Forbidden``, access will be
  denied and headers (such as ``WWW-Authenticate``) from the authorizer will be
  passed to client.  All other authorizer responses (such as ``3xx``
  redirects) are passed back to the client, including status and headers,
  allowing redirections such as those to WAYF pages and the Shibboleth
  responder (``Shibboleth.sso``) to work correctly.

  The FastCGI Authorizer spec calls for the response body to be returned to
  the client, but as Nginx does not currently support buffering subrequest
  responses (``NGX_HTTP_SUBREQUEST_IN_MEMORY``), the authorizer response body
  is effectively ignored.  A workaround is to have Nginx serve an
  ``error_page`` of its own, like so::

      location /secure {
         shib_request /shibauthorizer;
         error_page 403 /shibboleth-forbidden.html;
         ...
      }

  This serves the given error page if the Shibboleth authorizer denies the
  user access to this location.  Without ``error_page`` specified, Nginx will
  serve its generic error pages.

  Note that this does *not* apply to the Shibboleth responder (typically hosted at
  ``Shibboleth.sso``) as it is a FastCGI responder and Nginx is fully compatible
  with this as no subrequests are used.

  For more details, see http://forum.nginx.org/read.php?2,238444,238453.

Whilst this module is geared specifically for Shibboleth's FastCGI authorizer,
it will likely work with other authorizers, bearing in mind the deviations
from the spec above.

Tests
-----

Tests are automatically run on Travis CI whenever new commits are made to the
repository or when new pull requests are opened.  If something breaks, you'll
be informed by Travis and the results will be reported on GitHub.

Tests are written using a combination of a simple Bash script in `.travis.yml`
for compilation of different versions of Nginx with our module, and also the
`Test::Nginx <https://metacpan.org/pod/Test::Nginx::Socket>`_ Perl test
scaffolding for integration testing with this module.  Consult the previous
link for information on how to extend the tests, and also refer to the
underlying `Test::Base
<https://metacpan.org/pod/Test::Base#blocks-data-section-name>`_ documentation
on aspects like the `blocks()` function.

Integration tests are run automatically with Travis CI but
also be run manually (requires Perl & CPAN to be installed)::

    cd nginx-shibboleth-auth
    cpan -fi Test::Nginx::Socket
    # nginx must be present in path and built with debugging symbols
    prove


.. _FastCGI Authorizer spec: http://www.fastcgi.com/drupal/node/6?q=node/22#S6.3
