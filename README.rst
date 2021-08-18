Shibboleth auth request module for Nginx
========================================

.. image:: https://github.com/nginx-shib/nginx-http-shibboleth/actions/workflows/build.yml/badge.svg
   :target: https://github.com/nginx-shib/nginx-http-shibboleth/actions/workflows/build.yml

This module allows Nginx to work with Shibboleth, by way of Shibboleth's
FastCGI authorizer.  This module requires specific configuration in order to
work correctly, as well as Shibboleth's FastCGI authorizer application
available on the system.  It aims to be similar to parts of Apache's
`mod_shib`_, though Shibboleth authorisation and authentication settings are
configured via `shibboleth2.xml`_ rather than in the web server configuration.

With this module configured against a ``location`` block, incoming requests
are authorized within Nginx based upon the result of a subrequest to
Shibboleth's FastCGI authorizer.  In this process, this module can be used to
copy user attributes from a successful authorizer response into Nginx's
original request as headers or environment parameters for use by any backend
application.  If authorization is not successful, the authorizer response
status and headers are returned to the client, denying access or redirecting
the user's browser accordingly (such as to a WAYF page, if so configured).

This module works at access phase and therefore may be combined with other
access modules (such as ``access``, ``auth_basic``) via the ``satisfy``
directive.  This module can be also compiled alongside
``ngx_http_auth_request_module``, though use of both of these modules in the
same ``location`` block is untested and not advised.

Read more about the `Behaviour`_ below and consult `Configuration`_ for
important notes on avoiding spoofing if using headers for attributes.

For further information on why this is a dedicated module, see
https://forum.nginx.org/read.php?2,238523,238523#msg-238523

Directives
----------

The following directives are added into your Nginx configuration files. The
contexts mentioned below show where they may be added.


shib_request <uri>|off
   | **Context:** ``http``, ``server``, ``location``
   | **Default:** ``off``

   Switches the Shibboleth auth request module on and sets URI which will be
   asked for authorization.  The configured URI should refer to a Nginx
   location block that points to your Shibboleth FastCGI authorizer.

   The HTTP status and headers of the response resulting
   from the sub-request to the configured URI will be returned to the user,
   in accordance with the `FastCGI Authorizer specification`_.
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

   .. warning::

      The ``shib_request`` directive no longer requires the ``shib_authorizer``
      flag.  This must be removed for Nginx to start. No other changes are
      required.

shib_request_set <variable> <value>
   | **Context:** ``http``, ``server``, ``location``
   | **Default:** ``none``

   Set the ``variable`` to the specified ``value`` after the auth request has
   completed. The ``value`` may contain variables from the auth request's
   response.  For instance, ``$upstream_http_*``, ``$upstream_status``, and
   any other variables mentioned in the `nginx_http_upstream_module
   <https://nginx.org/en/docs/http/ngx_http_upstream_module.html#variables>`_
   documentation.

   This directive can be used to introduce Shibboleth attributes into the
   environment of the backend application, such as `$_SERVER` for a FastCGI
   PHP application and is the recommended method of doing so.  See the
   `Configuration`_ documentation for an example.

shib_request_use_headers on|off
   | **Context:** ``http``, ``server``, ``location``
   | **Default:** ``off``

   .. note::

      Added in v2.0.0.

   Copy attributes from the Shibboleth authorizer response into the main
   request as headers, making them available to upstream servers and
   applications. Use this option only if your upstream/application does not
   support server parameters via ``shib_request_set``.

   With this setting enabled, Authorizer response headers beginning with
   ``Variable-\*`` are extracted, stripping the ``Variable-`` substring from
   the header name, and copied into the main request before it is sent to the
   backend. For example, an authorizer response header such as
   ``Variable-Commonname: John Smith`` would result in ``Commonname: John
   Smith`` being added to the main request, and thus sent to the backend.

   **Beware of spoofing** - you must ensure that your backend application is
   protected from injection of headers. Consult the `Configuration`_ example
   on how to achieve this.


Installation
------------

This module can either be compiled statically or dynamically, since the
introduction of `dynamic modules
<https://www.nginx.com/resources/wiki/extending/converting/>`_ in Nginx
1.9.11.  The practical upshot of dynamic modules is that they can be loaded,
as opposed to static modules which are permanently present and enabled.

The easiest way to obtain a packaged version of this module is to use the
`pkg-oss <https://hg.nginx.org/pkg-oss/>`_ tool from Nginx, which provides for
packaging of dynamic modules for installation alongside the official releases
of Nginx from the `main repositories <https://nginx.org/en/download.html>`_
and helps avoid the need to compile Nginx by hand.

Otherwise, to compile Nginx with this module dynamically, pass the following
option to ``./configure`` when building Nginx::

    --add-dynamic-module=<path>

You will need to explicitly load the module in your ``nginx.conf`` by
including::

    load_module /path/to/modules/ngx_http_shibboleth_module.so;

and reload or restart Nginx.

To compile Nginx with this module statically, pass the following option to
``./configure`` when building Nginx::

    --add-module=<path>

With a static build, no additional loading is required as the module is
built-in to Nginx.


Configuration
-------------

For full details about configuring the Nginx/Shibboleth environment,
see the documentation at
https://github.com/nginx-shib/nginx-http-shibboleth/blob/master/CONFIG.rst.

An example ``server`` block consists of the following:

.. code-block:: nginx

    #FastCGI authorizer for Auth Request module
    location = /shibauthorizer {
        internal;
        include fastcgi_params;
        fastcgi_pass unix:/opt/shibboleth/shibauthorizer.sock;
    }

    #FastCGI responder
    location /Shibboleth.sso {
        include fastcgi_params;
        fastcgi_pass unix:/opt/shibboleth/shibresponder.sock;
    }

    # Using the ``shib_request_set`` directive, we can introduce attributes as
    # environment variables for the backend application. In this example, we
    # set ``fastcgi_param`` but this could be any type of Nginx backend that
    # supports parameters (by using the appropriate *_param option)
    #
    # The ``shib_fastcgi_params`` is an optional set of default parameters,
    # available in the ``includes/`` directory in this repository.
    #
    # Choose this type of configuration unless your backend application
    # doesn't support server parameters or specifically requires headers.
    location /secure-environment-vars {
        shib_request /shibauthorizer;
        include shib_fastcgi_params;
        shib_request_set $shib_commonname $upstream_http_variable_commonname;
        shib_request_set $shib_email $upstream_http_variable_email;
        fastcgi_param COMMONNAME $shib_commonname;
        fastcgi_param EMAIL $shib_email;
        fastcgi_pass unix:/path/to/backend.socket;
    }

    # A secured location. All incoming requests query the Shibboleth FastCGI authorizer.
    # Watch out for performance issues and spoofing!
    #
    # Choose this type of configuration for ``proxy_pass`` applications
    # or backends that don't support server parameters.
    location /secure {
        shib_request /shibauthorizer;
        shib_request_use_headers on;

        # Attributes from Shibboleth are introduced as headers by the FastCGI
        # authorizer so we must prevent spoofing. The
        # ``shib_clear_headers`` is a set of default header directives,
        # available in the `includes/` directory in this repository.
        include shib_clear_headers;

        # Add *all* attributes that your application uses, including all
        #variations.
        more_clear_input_headers 'displayName' 'mail' 'persistent-id';

        # This backend application will receive Shibboleth variables as request
        # headers (from Shibboleth's FastCGI authorizer)
        proxy_pass http://localhost:8080;
    }

Note that we use the `headers-more-nginx-module
<https://github.com/openresty/headers-more-nginx-module>`_ to clear
potentially dangerous input headers and avoid the potential for spoofing.  The
latter example with environment variables isn't susceptible to header
spoofing, as long as the backend reads data from the environment parameters
**only**.

A `default configuration
<https://github.com/nginx-shib/nginx-http-shibboleth/blob/master/includes/shib_clear_headers>`_
is available to clear the basic headers from the Shibboleth authorizer, but
you must ensure you write your own clear directives for all attributes your
application uses.  Bear in mind that some applications will try to read a
Shibboleth attribute from the environment and then fall back to headers, so
review your application's code even if you are not using
``shib_request_use_headers``.


With use of ``shib_request_set``, a `default params
<https://github.com/nginx-shib/nginx-http-shibboleth/blob/master/includes/shib_fastcgi_params>`_
file is available which you can use as an nginx ``include`` to ensure all core
Shibboleth variables get passed from the FastCGI authorizer to the
application. Numerous default attributes are included so remove the ones that
aren't required by your application and add Federation or IDP attributes that
you need. This default params file can be re-used for upstreams that aren't
FastCGI by simply changing the ``fastcgi_param`` directives to
``uwsgi_param``, ``scgi_param`` or so forth.

Gotchas
~~~~~~~

* Subrequests, such as the Shibboleth auth request, aren't processed through header filters.
  This means that built-in directives like ``add_header`` will **not** work if configured
  as part of the a ``/shibauthorizer`` block.  If you need to manipulate subrequest headers,
  use ``more_set_headers`` from the module ``headers-more``.

  See https://forum.nginx.org/read.php?29,257271,257272#msg-257272.

Behaviour
---------

This module follows the `FastCGI Authorizer specification`_ where possible,
but has some notable deviations - with good reason.  The behaviour is thus:

* An authorizer subrequest is comprised of all aspects of the original
  request, excepting the request body as Nginx does not support buffering of
  request bodies.  As the Shibboleth FastCGI authorizer does not consider the
  request body, this is not an issue.

* If an authorizer subrequest returns a ``200`` status, access is allowed.

  If ``shib_request_use_headers`` is enabled, and response headers beginning
  with ``Variable-\*`` are extracted, stripping the ``Variable-`` substring
  from the header name, and copied into the main request.  Other authorizer
  response headers not prefixed with ``Variable-`` and the response body are
  ignored.  The FastCGI spec calls for ``Variable-*`` name-value pairs to be
  included in the FastCGI environment, but we make them headers so as they may
  be used with *any* backend (such as ``proxy_pass``) and not just restrict
  ourselves to FastCGI applications.  By passing the ``Variable-*`` data as
  headers instead, we end up following the behaviour of ``ShibUseHeaders On``
  in ``mod_shib`` for Apache, which passes these user attributes as headers.

  In order to pass attributes as environment variables (the equivalent to
  ``ShibUseEnvironment On`` in ``mod_shib``), attributes must be manually
  extracted using ``shib_request_set`` directives for each attribute.  This
  cannot (currently) be done *en masse* for all attributes as each backend may
  accept parameters in a different way (``fastcgi_param``, ``uwsgi_param``
  etc).  Pull requests are welcome to automate this behaviour.

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
  ``error_page`` of its own, like so:

  .. code-block:: nginx

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

  For more details, see https://forum.nginx.org/read.php?2,238444,238453.

Whilst this module is geared specifically for Shibboleth's FastCGI authorizer,
it will likely work with other authorizers, bearing in mind the deviations
from the spec above.

Tests
-----

Tests are automatically run on GitHub Actions (using `this configuration
<https://github.com/nginx-shib/nginx-http-shibboleth/blob/master/.github/workflows/build.yml>`_)
whenever new commits are made to the repository or when new pull requests
are opened. If something breaks, you'll be informed and the results will be
reported on GitHub.

Tests are written using a combination of a simple Bash script for compilation
of our module with different versions and configurations of Nginx and the
`Test::Nginx <https://metacpan.org/pod/Test::Nginx::Socket>`_ Perl test
scaffolding for integration testing.  Consult the previous link for
information on how to extend the tests, and also refer to the underlying
`Test::Base <https://metacpan.org/pod/Test::Base#blocks-data-section-name>`_
documentation on aspects like the `blocks()` function.

Integration tests are run automatically by CI but can also be run manually
(requires Perl & CPAN to be installed):

.. code-block:: bash

    cd nginx-http-shibboleth
    cpanm --notest --local-lib=$HOME/perl5 Test::Nginx
    # nginx must be present in PATH and built with debugging symbols
    PERL5LIB=$HOME/perl5/lib/perl5 prove

Help & Support
--------------

Support requests for Shibboleth configuration and Nginx or web server setup
should be directed to the Shibboleth community users mailing list.  See
https://www.shibboleth.net/community/lists/ for details.

Debugging
---------

Because of the complex nature of the nginx/FastCGI/Shibboleth stack, debugging
configuration issues can be difficult.  Here's some key points:

#. Confirm that ``nginx-http-shibboleth`` is successfully built and installed
   within nginx. You can check by running ``nginx -V`` and inspecting the
   output for ``--add-module=[path]/nginx-http-shibboleth`` or
   ``--add-dynamic-module=[path]/nginx-http-shibboleth``.
#. If using dynamic modules for nginx, confirm you have used the
   ``load_module`` directive to load this module.  Your use of ``shib_request``
   and other directives will fail if you have forgotten to load the module.
#. If using a version of nginx that is different to those we
   `test with <https://github.com/nginx-shib/nginx-http-shibboleth/blob/master/.github/workflows/build.yml>`_
   or if you are using other third-party modules, you should run
   the test suite above to confirm compatibility.  If any tests fail, then check
   your configuration or consider updating your nginx version.
#. Shibboleth configuration: check your ``shibboleth2.xml`` and associated
   configuration to ensure your hosts, paths and attributes are being correctly
   released.  An `example configuration <https://github.com/nginx-shib/nginx-http-shibboleth/blob/master/CONFIG.rst#configuring-shibboleths-shibboleth2xml-to-recognise-secured-paths>`_
   can help you identify key "gotchas" to configuring ``shibboleth2.xml`` to work
   with the FastCGI authorizer.
#. Application-level: within your code, always start with the simplest possible
   debugging output (such as printing the request environment) and work
   up from there.  If you want to create a basic, stand-alone app, take
   a look at the `Bottle <https://github.com/nginx-shib/nginx-http-shibboleth/wiki/bottle>`_
   configuration on the wiki.
#. Debugging module internals: if you've carefully checked all of the above, then
   you can also debug the behaviour of this module itself.  You will need to have
   compiled nginx with debugging support (via ``./auto/configure --with-debug ...``)
   and when running nginx, it is easiest if you're able run in the foreground with
   debug logging enabled.  Add the following to your ``nginx.conf``:

   .. code-block:: nginx

      daemon off;
      error_log stderr debug;

   and run nginx.  Upon starting nginx you should see lines containing `[debug]` and
   as you make requests, console logging will continue.  If this doesn't happen,
   then check your nginx configuration and compilation process.

   When you eventually make a request that hits (or should invoke) the
   ``shib_request`` location block, you will see lines like so in the output:

   .. code-block:: nginx

      [debug] 1234#0: shib request handler
      [debug] 1234#0: shib request set variables
      [debug] 1234#0: shib request authorizer handler
      [debug] 1234#0: shib request authorizer allows access
      [debug] 1234#0: shib request authorizer copied header: "AUTH_TYPE: shibboleth"
      [debug] 1234#0: shib request authorizer copied header: "REMOTE_USER: john.smith@example.com"
      ...

   If you don't see these types of lines containing `shib request ...`,
   or if you see *some* of the lines above but not where headers/variables are being
   copied, then double-check your nginx configuration.  If you're still not getting
   anywhere, then you can add your own debugging lines into the source (follow
   this module's examples) to eventually determine what is going wrong and when.
   If doing this, don't forget to recompile nginx and/or ``nginx-http-shibboleth``
   whenever you make a change.

If you believe you've found a bug in the core module code, then please
`create an issue <https://github.com/nginx-shib/nginx-http-shibboleth/issues>`_.

You can also search existing issues as it is likely someone else has
encountered a similar issue before.

Versioning
----------

This module uses `Semantic Versioning <https://semver.org/>`_ and all releases
are tagged on GitHub, which allows package downloads of individual tags.

License
-------

This project is licensed under the same license that nginx is, the
`2-clause BSD-like license <https://github.com/nginx-shib/nginx-http-shibboleth/blob/master/LICENSE>`_. 

.. _FastCGI Authorizer specification: https://web.archive.org/web/20160306081510/http://fastcgi.com/drupal/node/6?q=node/22#S6.3
.. _mod_shib: https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPApacheConfig
.. _shibboleth2.xml: https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPShibbolethXML
