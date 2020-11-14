# NEWS

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
