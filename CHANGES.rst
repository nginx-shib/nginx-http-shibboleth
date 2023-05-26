CHANGES
=======

Unreleased
----------

2.0.2 (2023-05-26)
------------------

* bugfix: nginx crash when accessing uninitialized pointer
* Fix compatibility with nginx 1.23.0+ - change handling of multiple headers
* Switch to GitHub Actions for CI.
* Documentation improvements

2.0.1 (2017-04-06)
------------------

* Add further standard SP variables and correct capitalisation in environment
  params.
* Update Travis CI version tests.
* Document preferred configuration of module.

2.0.0 (2016-05-18)
------------------

* **Backwards incompatibility**: Added ``shib_request_use_headers`` directive
  to require explicit configuration of copying attributes as headers. To
  restore pre-v2.0.0 behaviour add ``shib_request_use_headers on`` to your
  configuration.
* Module can now be built as a dynamic module in Nginx 1.9.11+.
  Static compilation is always possible (and tested).
* Added Travis CI tests.

1.0.0 (2016-02-18)
------------------

- Initial release
