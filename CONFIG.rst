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
   on``.
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
headers (cookies) are used for authentication to succeed.


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

Paths will need adjusting for Debian-based distributions, and the socket
locations are arbitrary.  Make note of these socket locations as you will
shortly configure Nginx with them.


Compile Nginx with Shibboleth module
--------------------------------------

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


Configure Nginx
---------------


#. Configure one or more servers within your Nginx configuration like so.
   You'll need the socket information for your FastCGI Shibboleth SP
   applications.

   The ``proxy_pass http://localhost:8080`` can be replaced
   with whatever application or configuration should be receiving the
   Shibboleth attributes as headers.  In my case, port 8080 is running Plone,
   a Python-based CMS, but you might anything (PHP, FastCGI, etc) here.
   Essentially, this is what would normally be the backend configured against
   ``AuthType shibboleth`` in Apache.

   .. code:: nginx

      server {
          listen 443 ssl;
          ...

          #FastCGI authorizer for Auth Request module
          location = /shibauthorizer {
              internal;
              include fastcgi_params;
              fastcgi_pass unix:/opt/shibboleth/shibauthorizer.sock;
          }

          #FastCGI responder for SSO
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
              more_clear_input_headers 'Variable-*' 'Shib-*' 'Remote-User' 'REMOTE_USER' 'Auth-Type' 'AUTH_TYPE';

              #Add your attributes here. They get introduced as headers
              #by the FastCGI authorizer so we must prevent spoofing.
              more_clear_input_headers 'displayName' 'mail' 'persistent-id';
              auth_request /shibauthorizer authorizer=on;
              proxy_pass http://localhost:8080; 
          }

          #A secured location, but only a specific sub-path causes Shibboleth
          #authentication.
          location /secure2 {
              proxy_pass http://localhost:8080; 

              location = /secure2/shibboleth {
                  more_clear_input_headers 'Variable-*' 'Shib-*' 'Remote-User' 'REMOTE_USER' 'Auth-Type' 'AUTH_TYPE';
                  #Add your attributes here. They get introduced as headers
                  #by the FastCGI authorizer so we must prevent spoofing.
                  more_clear_input_headers 'displayName' 'mail' 'persistent-id';
                  auth_request /shibauthorizer authorizer=on;
                  proxy_pass http://localhost:8080; 
              }
          }
      }

   An explanation about the above is provided in the comments.  I should note
   that:

   * The first 3 locations are pure boilerplate for any host that requires
     Shibboleth authentication, so you can (and should!) put these into an
     ``include``-able configuration file and reuse them.

   * The ``/shibboleth-sp`` location is purely there to help your default
     install.  If you customise your error pages, feel free to change or delete
     this location.

   * Take note of the ``more_clear_input_headers`` calls. As the Shibboleth
     authorizer will inject headers into the request before passing the
     request onto the final upstream endpoint, you **must**
     use these directives to protect from spoofing.  You should expand the 
     second call to this directive when you have more incoming attributes 
     from the Shibboleth authorizer.  Or else beware...

   * The ``/secure`` location will ask the FastCGI authorizer for attributes
     for **every** request that comes in. This may or may not be what you
     want.  Keep in mind this means that each request will have Shibboleth
     attributes dropped into the request for sending onto backend services,
     and this will happen every time.  Did I mention for **every request**?

   * The ``/secure2`` location only asks the FastCGI authorizer for auth
     on a (very) specific sub-path.  Only upon the user hitting this specific
     URL will the authentication process be triggered. This is a smarter
     authentication technique to avoid extra overhead -- set the upstream
     for the specific sub-path to be somewhere an application session is
     created, and have that application session capture the Shibboleth
     attributes.

     Notice how the rest of the application doesn't refer to the authorizer.
     This means the application can be used anonymously, too. Alternatively,
     you can configure the ``requireSession`` option to be fa

   * Adding the ``auth_request`` line into a location isn't all you need to
     do to get the FastCGI authorizer to recognise your path as Shibboleth
     protected.  You need to follow the instructions below and take care.

#. Save the configuration and follow the next section.  You're almost done.


Configuring Shibboleth to recognise secured paths
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Typically, within Apache, you can tell Shibboleth which paths to secure by
using something like:

.. code:: apache

   <Location /secure>
       ShibRequestSetting authType shibboleth
       ShibRequestSetting requireSession false
   </Location>

However, the FastCGI authorizer for Shibboleth operates without such directives
and thus path protection needs to be configured like it would be for IIS,
using the ``<RequestMapper>`` configuration.  The same options are accepted
within this section of the ``shibboleth2.xml`` configuration file, it's just
that you need to know where to put them.  So let's do that.

  
#. Configure your ``shibboleth2.xml`` file like so.  Find the ``RequestMapper``
   element and replace it with something like the following:

   .. code:: xml

       <RequestMapper type="XML">
           <RequestMap>
               <Host name="eresearch.jcu.edu.au"
                     authType="shibboleth"
                     requireSession="true"
                     redirectToSSL="443">
                   <Path name="/secure" />
                   <Path name="/secure2/shibboleth" />
                   ...
               </Host>
               ...
           </RequestMap>
       </RequestMapper>

   Some notes:

   * The Shibboleth FastCGI authorizer needs to see ``authType`` **and**
     ``requireSession`` configured for the resultant path.  If they are not
     present, then the authorizer will ignore the path it is passed and
     the user will not be prompted for authentication (and you **will**
     tear your hair out because no logging takes place!).

   * ``<Path>`` names are **case sensitive** here.  You have hereby been warned!
     -- although this shouldn't be too surprising to you hopefully.

   * You can use other configuration items like ``<HostRegex>`` and
     ``<PathRegex>`` and ``<AccessControl``> to configure what happens to 
     requests.  Check out the documentation below - there's lots to learn. 

   * An interesting aspect here is that configuration is inherited downwards
     in the XML tree.  So, you could configure something like the ``authType``
     on a ``<Host>`` and have it apply to all paths beneath it.

     You don't need to do this, though.  You may put all the configuration
     attributes onto the ``<Path>`` element, or even move them up to
     higher levels in the tree if you want to reduce duplication.

   * Nested ``<Path>`` elements will see their path segments being greedy.
     So putting a path with ``name="shibboleth"`` within a path with
     ``name="secure"`` really translates to a path with 
     ``name="secure/shibboleth"``.  Whatever takes your fancy here.

#. Once you're done, then restart the Shibboleth daemon, ensure that you
   restart the Shibboleth FastCGI applications, and hard restart Nginx
   just to make sure it finds those sockets::

       service shibd restart
       supervisorctl restart shibauthorizer shibresponder
       service nginx restart

   Assuming, of course, that you're using Supervisor to run your applications.
   You should.  It's easy to work with and fun.  

#. Try loading up your Shibboleth protected URL.  If all goes well, then you
   should get a complete authentication cycle.  If not, check carefully through
   everything above.

Take a look at 
https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPRequestMapper
and
https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPRequestMap
for more information.

Gotchas
-------

If you're experiencing issues with the Shibboleth authorizer appearing to fail
to be invoked, check the following:

* The authorizer requires a ``<Path>`` element in ``shib2.xml`` to be
  *correctly* configured with ``authType`` and ``requireSession`` for auth to
  take place.  If you don't (or say forget to restart ``shibd``), then the
  authorizer will return a ``200 OK`` status response, which equates to
  unconditionally allowing access.

* No logs will get issued *anywhere* for anything related to the FastCGI
  applications (standard ``shibd`` logging does apply, however).  If you're
  testing for why the authentication cycle doesn't start, try killing your
  FastCGI authorizer and make sure you see a ``502`` error come back from
  Nginx.  If you still get a ``200``, then your ``shib_request`` configuration
  in Nginx is probably wrong and the authorizer isn't being contacted.

* When in doubt, hard restart the entire stack, and use something like ``curl``
  to ensure you avoid any browser caching.

* When in serious doubt, install a version of Nginx with debugging support,
  configure full trace logging, and run it with your configuration instead.
  If 

