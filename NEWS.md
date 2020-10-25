# NEWS

## Version X.X.X (YYYY-MM-DD)

### Incompatible changes

* Verify the server's certificate by default. <https://github.com/ruby/net-smtp/pull/12>
* Use STARTTLS by default if possible. <https://github.com/ruby/net-smtp/pull/9>

### Improvements

* Net::SMTP.start arguments are keyword arguments <https://github.com/ruby/net-smtp/pull/7>
* Add tls_verify parameter. <https://github.com/ruby/net-smtp/pull/12>
* Add tls_hostname parameter. <https://github.com/ruby/net-smtp/pull/14>
* Add SNI support to net/smtp <https://github.com/ruby/net-smtp/pull/4>

### Fixes

* enable_starttls before disable_tls causes an error. <https://github.com/ruby/net-smtp/pull/10>
* TLS should not check the hostname when verify_mode is disabled. <https://github.com/ruby/net-smtp/pull/6>

## Version 0.1.0 (2019-12-03)

This is the first release of net-smtp gem.
