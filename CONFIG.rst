Configuration
=============

.. contents::
   :local:
   :backlinks: none

Steps
-----

#. Obtain/rebuild Shibboleth SP with FastCGI support.
#. Recompile Nginx with the ``nginx-http-shibboleth`` custom module.
#. Configure Shibboleth FastCGI authorizer and reponsder applicatons to run.
#. Configure Nginx to talk to both FastCGI authorizer and responder.
#. Configure your Nginx application ``location`` block with ``shib_request
   /shibauthorizer``, where ``/shibauthorizer`` is the path to your Shibboleth
   authorizer location inside Nginx.
#. Configure Shibboleth's ``shibboleth2.xml`` so the authorizer and responder are
   aware of which paths to protect.
#. Ensure your application code accepts the relevant incoming headers for
   authN/authZ.

Background
----------

Shibboleth supports Apache and IIS by default, but not Nginx.  The closest one
gets to support is via FastCGI, which Shibboleth `does have
<https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPFastCGIConfig>`_
but the default distribution needs to be rebuilt to support it.  Nginx has
support for FastCGI responders, but not for `FastCGI authorizers
<http://www.fastcgi.com/drupal/node/22#S6.3>`_.  This current module,
``nginx-http-shibboleth``, bridges this gap using sub-requests within Nginx.

The design of Nginx is such that when handling sub-requests, it currently
cannot forward the original request body, and likewise, cannot pass a
sub-request response back to the client.  As such, this module does not fully
comply with the FastCGI authorizer specification. However, for Shibboleth,
these two factors are inconsequential as only HTTP redirections and HTTP
headers (cookies) are used for authentication to succeed and, only
HTTP headers (attributes/variables) are required to be passed onto a backend
application from the Shibboleth authorizer.


Shibboleth SP with FastCGI Support
----------------------------------

For Debian-based distributions, your ``shibboleth-sp-utils`` package has
likely already been built with FastCGI support, since default repositories
feature the required FastCGI dev packages.

For RPM-based distributions, you will either need to obtain a pre-built
package with FastCGI support or build your own.  Since the ``fcgi-devel``
libraries aren't present in RHEL or CentOS repositories, you likely require a
thirty-party repository such as EPEL (or compile from source yourself).
Recompilation of ``shibboleth-sp`` is simple, however, and an example script
can be found at https://github.com/jcu-eresearch/shibboleth-fastcgi.


Running the FastCGI authorizer and responder
--------------------------------------------

Nginx does not manage FastCGI applications and thus they must be running
before Nginx can talk to them.

A simple option is to use `Supervisor <http://supervisord.org/>`_ or another
FastCGI controller to manage the applications.  An example Supervisor
configuration to work with a rebuilt ``shibboleth-sp`` on 64-bit RHEL/CentOS
looks like::

    [fcgi-program:shibauthorizer]
    command=/usr/lib64/shibboleth/shibauthorizer
    socket=unix:///opt/shibboleth/shibauthorizer.sock
    socket_owner=shibd:shibd
    socket_mode=0660
    user=shibd
    stdout_logfile=/var/log/supervisor/shibauthorizer.log
    stderr_logfile=/var/log/supervisor/shibauthorizer.error.log

    [fcgi-program:shibresponder]
    command=/usr/lib64/shibboleth/shibresponder
    socket=unix:///opt/shibboleth/shibresponder.sock
    socket_owner=shibd:shibd
    socket_mode=0660
    user=shibd
    stdout_logfile=/var/log/supervisor/shibresponder.log
    stderr_logfile=/var/log/supervisor/shibresponder.error.log

Paths, users and permissions may need adjusting for different distributions or
operating environments.  The socket paths are arbitrary; make note of these
socket locations as you will use them to configure Nginx.

In the example above, the web server user (e.g. ``nginx``) would need to be
made part of the ``shibd`` group in order to communicate correctly given the
socket permissions of ``660``. Permissions and ownership can be changed to suit
one's own environment, provided the web server can communicate with the FastCGI
applications sockets and that those applications can correctly access the
Shibboleth internals (e.g. ``shibd``).

Note that the above configuration requires Supervisor 3.0 or above.  If you
are using RHEL/CentOS 6 with EPEL, note that their packaging is only providing
version Supervisor 2.  If this is the case, you will either need to upgrade OSes,
install Supervisor from source (or PyPI), or package the RPMs yourself.


Compile Nginx with Shibboleth module
------------------------------------

Compile Nginx with the ``nginx-http-shibboleth`` custom third-party module,
following instructions at http://wiki.nginx.org/3rdPartyModules.  How you do
this depends on your Nginx installation processes and existing workflow.  In
general, however, you can clone this module from GitHub::

    git clone https://github.com/nginx-shib/nginx-http-shibboleth.git

and add it into your ``configure`` step of Nginx::

    ./configure --add-module=/path/to/nginx-http-shibboleth

Note that you'll almost certainly have other options being passed to
``configure`` at the same time.  It may be easiest to re-build Nginx from your
existing packages for your distribution, and patch the above ``configure``
argument into the build processes.

Also, you will likely need the Nginx module `nginx_headers_more
<http://wiki.nginx.org/HttpHeadersMoreModule>`_ in order to prevent header
spoofing from the client, unless you already have a separate solution in
place.

If you wish to confirm the build was successful, install a version of Nginx
with debugging support, configure full trace logging, and the example
configuration below.  You should notice ``shib request ...`` lines in the
output showing where ``nginx-http-shibboleth`` is up to during a request.


Configure Nginx
---------------

Nginx now needs to be configured with ``location`` blocks that point to both
the FastCGI authorizer and responder.  Specify your FastCGI socket locations,
where required. Note that the ``more_clear_input_headers`` directive is
required to prevent header spoofing from the client, since the Shibboleth
variables are passed around as headers.

.. code:: nginx

   server {
       listen 443 ssl;
       server_name example.org;
       ...

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

       #Resources for the Shibboleth error pages. This can be customised.
       location /shibboleth-sp {
           alias /usr/share/shibboleth/;
       }

       #A secured location.  Here all incoming requests query the
       #FastCGI authorizer.  Watch out for performance issues and spoofing.
       location /secure {
            include shib_clear_headers;
            #Add your attributes here. They get introduced as headers
            #by the FastCGI authorizer so we must prevent spoofing.
            more_clear_input_headers 'displayName' 'mail' 'persistent-id';
            shib_request /shibauthorizer;
            shib_request_use_headers on;
            proxy_pass http://localhost:8080;
        }

        #A secured location, but only a specific sub-path causes Shibboleth
        #authentication.
        location /secure2 {
            proxy_pass http://localhost:8080;

            location = /secure2/shibboleth {
                include shib_clear_headers;
                #Add your attributes here. They get introduced as headers
                #by the FastCGI authorizer so we must prevent spoofing.
                more_clear_input_headers 'displayName' 'mail' 'persistent-id';
                shib_request /shibauthorizer;
                shib_request_use_headers on;
                proxy_pass http://localhost:8080;
            }
        }
   }

Notes
~~~~~

* ``proxy_pass`` can be replaced with any application or configuration that
  should receive the Shibboleth attributes as headers.  Essentially, this is
  what would normally be the backend configured against ``AuthType
  shibboleth`` in Apache.

* The first 3 locations are pure boilerplate for any host that requires
  Shibboleth authentication, so you may wish to template these for reuse
  between hosts.

* The ``/shibboleth-sp`` location provides web resources for default
  Shibboleth error messages. If you customise error pages, or don't care for
  images or styles on error pages, delete this location.

* Take note of the ``more_clear_input_headers`` calls. As the Shibboleth
  authorizer will inject headers into the request before passing the
  request onto the final upstream endpoint, you **must**
  use these directives to protect from spoofing.  You should expand the 
  second call to this directive when you have more incoming attributes 
  from the Shibboleth authorizer.  Or else beware...

* The ``/secure`` location will ask the FastCGI authorizer for attributes for
  **every** request that comes in. This may or may not be desirable.  Keep in
  mind this means that each request will have Shibboleth attributes add before
  being sent onto a backend, and this will happen every time.

*  You may wish to consider only securing a path that creates an application
   session (such as the ``/secure2`` location block), and letting your
   application handle the rest.  Only upon the user hitting this specific URL
   will the authentication process be triggered. This is a authentication
   technique to avoid extra overhead -- set the upstream for the specific
   sub-path to be somewhere an application session is created, and have that
   application session capture the Shibboleth attributes.

   Notice how the rest of the application doesn't refer to the authorizer.
   This means the application can be used anonymously, too. Alternatively,
   you can configure the ``requireSession`` option to be fa

* Adding the ``shib_request`` line into a location isn't all you need to
  do to get the FastCGI authorizer to recognise your path as Shibboleth
  protected.  You need also need to ensure that ``shibd`` is configured to
  accept your paths as well, following the next set of instructions.


Configuring Shibboleth's shibboleth2.xml to recognise secured paths
-------------------------------------------------------------------

Within Apache, you can tell Shibboleth which paths to secure by
using configuration like so in your web server's configuration:

.. code:: apache

   <Location /secure>
       ShibRequestSetting authType shibboleth
       ShibRequestSetting requireSession false
   </Location>
  
With this, Shibboleth is made aware of this configuration automatically.

However, the FastCGI authorizer for Shibboleth operates without such
directives in the web server.  Path protection and request mapping needs to
be configured like it would be for IIS, using the XML-based
``<RequestMapper type="XML">`` configuration.  The same options from
Apache are accepted within the ``RequestMapper`` section of the
``shibboleth2.xml`` configuration file, like this truncated example shows.
This example corresponds to the sample Nginx configuration given above.

.. code:: xml

    <RequestMapper type="XML">
        <RequestMap>
            <Host name="example.org"
                    authType="shibboleth"
                    requireSession="true"
                    redirectToSSL="443">
                <Path name="/secure" />
                <Path name="/secure2/shibboleth" />
                <!-- other Path, PathRegex or Query elements here -->
            </Host>
            <!-- other Host or HostRegex elements here -->
        </RequestMap>
    </RequestMapper>

Notes
~~~~~

* When used with nginx, the ``RequestMapper`` will work with either
  ``type="native"`` or ``type="XML"``.  The latter is recommended
  as nginx has no native commands or ``.htaccess`` so skipping
  those checks leads to performance gains (see `NativeSPRequestMapper
  docs <https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPRequestMapper>`_).

* The Shibboleth FastCGI authorizer must have both ``authType`` **and**
  ``requireSession`` configured for the resultant path.  If they are not
  present, then the authorizer will ignore the path it is passed and the user
  will not be prompted for authentication (and no logging will take place).

* ``<Path>`` names are **case sensitive**.

* You can use other configuration items like ``<HostRegex>`` and
  ``<PathRegex>`` and ``<AccessControl>`` to configure how Shibboleth handles
  incoming requests.  There is no limit on the number of hosts/paths configured.

* Configuration is inherited **downwards** in the XML tree.  So, configure ``authType``
  on a ``<Host>`` element will see it apply to all paths beneath it.  This is
  not required, however; attributes can be placed anywhere you desire.

* Nested ``<Path>`` elements are greedy. Putting a path with
  ``name="shibboleth"`` within a path with ``name="secure"`` really translates
  to a path with ``name="secure/shibboleth"``.

* Upon changing this configuration, ensure the ``shibauthorizer`` and
  ``shibresponder`` applications are hard-restarted, as well as ``shibd``.

Gotchas
-------

If you're experiencing issues with the Shibboleth authorizer or Shibboleth
responder appearing to fail to be invoked, check the following:

* The authorizer requires a ``<Path>`` element in ``shib2.xml`` to be
  *correctly* configured with ``authType`` and ``requireSession`` for auth to
  take place.  If you don't (or say forget to restart ``shibd``), then the
  authorizer will return a ``200 OK`` status response, which equates to
  unconditionally allowing access.
  
* The authorizer and responder require a correctly-configured FastCGI request
  environment in order to accept, match and process requests.  The `default
  fastcgi_params file <https://github.com/nginx/nginx/blob/master/conf/fastcgi_params>`_
  provides a suitable configuration.  If your ``fastcgi_params`` differs from the
  default, check this first.

  * If the environment is not correct, the authorizer and responder will respond with
    ``500 Server Error``, reporting this to the browser::
    
        FastCGI Shibboleth responder should only be used for Shibboleth protocol requests.
        
    As well as this to the ``stderr`` from FastCGI::
    
        shib: doHandler failed to handle the request
        
    In this case, check all the FastCGI environment variables to ensure they're right,
    particularly ``REQUEST_URI`` and ``SERVER_PORT``.
    
    Also check your ``shibboleth2.xml`` configuration's ``<Sessions handlerURL="...">``
    as the FastCGI applications will error in the same way if your ``handlerURL`` and
    its protocol, port and path don't match what's configured within Nginx.  This is
    especially true if using an absolute URL, custom port number or different path to
    the standard `/Shibboleth.sso`.

* No logs will get issued *anywhere* for anything related to the FastCGI
  applications (standard ``shibd`` logging does apply, however).  If you're
  testing for why the authentication cycle doesn't start, try killing your
  FastCGI authorizer and make sure you see a ``502`` error come back from
  Nginx.  If you still get a ``200``, then your ``shib_request`` configuration
  in Nginx is probably wrong and the authorizer isn't being contacted.
  
* When in doubt, hard restart the entire stack, and use something like ``curl``
  to ensure you avoid any browser caching.  
  
* If still in doubt that the Nginx installation has been successfully built
  with the ``nginx-http-shibboleth`` module, run Nginx in debug mode,
  and trace the request accordingly through the logs or console output.


Resources
---------

* http://wiki.nginx.org/HttpHeadersMoreModule
* https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPRequestMapper
* https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPRequestMap
* https://github.com/nginx-shib/nginx-http-shibboleth
* http://davidjb.com/blog/2013/04/setting-up-a-shibboleth-sp-with-fastcgi-support/
* https://github.com/jcu-eresearch/shibboleth-fastcgi/
* https://github.com/jcu-eresearch/nginx-custom-build

Deprecated documentation:

* http://davidjb.com/blog/2013/04/integrating-nginx-and-a-shibboleth-sp-with-fastcgi/
