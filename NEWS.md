# NEWS

## Version 0.3.0

### Improvements

* Add `tls`, `starttls` keyword arguments.
    ```ruby
    # always use TLS connection for port 465.
    Net::SMTP.start(hostname, 465, tls: true)

    # do not use starttls for localhost
    Net::SMTP.start('localhost', starttls: false)
    ```

### Incompatible changes

* The tls_* paramter has been moved from start() to initialize().

## Version 0.2.2 (2021-10-09)

* Add `response` to SMTPError exceptions.
* `Net::SMTP.start()` and `#start()` accepts `ssl_context_params` keyword argument.
* Replace `Timeout.timeout` with socket timeout.
* Remove needless files from gem.
* Add dependency on digest, timeout.

## Version 0.2.1 (2020-11-18)

### Fixes

* Update the license for the default gems to dual licenses.
* Add dependency for net-protocol.

## Version 0.2.0 (2020-11-15)

### Incompatible changes

* Verify the server's certificate by default.
  If you don't want verification, specify `start(tls_verify: false)`.
  <https://github.com/ruby/net-smtp/pull/12>

* Use STARTTLS by default if possible.
  If you don't want starttls, specify:
      ```
      smtp = Net::SMTP.new(hostname, port)
      smtp.disable_starttls
      smtp.start do |s|
        s.send_message ....
      end
      ```
  <https://github.com/ruby/net-smtp/pull/9>

### Improvements

* Net::SMTP.start and Net::SMTP#start arguments are keyword arguments.
      ```
      start(address, port = nil, helo: 'localhost', user: nil, secret: nil, authtype: nil) { |smtp| ... }
      ```
  `password` is an alias of `secret`.
  <https://github.com/ruby/net-smtp/pull/7>

* Add `tls_hostname` parameter to `start()`.
  If you want to use a different hostname than the certificate for the connection, you can specify the certificate hostname with `tls_hostname`.
  <https://github.com/ruby/net-smtp/pull/14>

* Add SNI support to net/smtp <https://github.com/ruby/net-smtp/pull/4>

### Fixes

* enable_starttls before disable_tls causes an error. <https://github.com/ruby/net-smtp/pull/10>
* TLS should not check the hostname when verify_mode is disabled. <https://github.com/ruby/net-smtp/pull/6>

## Version 0.1.0 (2019-12-03)

This is the first release of net-smtp gem.
