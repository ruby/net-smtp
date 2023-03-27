# frozen_string_literal: true
require 'net/smtp'
require 'stringio'
require 'test/unit'

module Net
  class TestSMTP < Test::Unit::TestCase
    CA_FILE = File.expand_path("../fixtures/cacert.pem", __dir__)
    SERVER_KEY = File.expand_path("../fixtures/server.key", __dir__)
    SERVER_CERT = File.expand_path("../fixtures/server.crt", __dir__)

    class FakeSocket
      attr_reader :write_io

      def initialize out = "250 OK\n"
        @write_io = StringIO.new
        @read_io  = StringIO.new out
      end

      def writeline line
        @write_io.write "#{line}\r\n"
      end

      def readline
        line = @read_io.gets
        raise 'ran out of input' unless line
        line.chop
      end
    end

    def setup
      # Avoid hanging at fake_server_start's IO.select on --jit-wait CI like http://ci.rvm.jp/results/trunk-mjit-wait@phosphorus-docker/3302796
      # Unfortunately there's no way to configure read_timeout for Net::SMTP.start.
      if defined?(RubyVM::JIT) && RubyVM::JIT.enabled?
        Net::SMTP.prepend Module.new {
          def initialize(*)
            super
            @read_timeout *= 5
          end
        }
      end

      @server_threads = []
    end

    def teardown
      @server_threads.each {|th| th.kill; th.join }
    end

    def test_critical
      smtp = Net::SMTP.new 'localhost', 25

      assert_raise RuntimeError do
        smtp.send :critical do
          raise 'fail on purpose'
        end
      end

      assert_kind_of Net::SMTP::Response, smtp.send(:critical),
                     '[Bug #9125]'
    end

    def test_esmtp
      smtp = Net::SMTP.new 'localhost', 25
      assert smtp.esmtp
      assert smtp.esmtp?

      smtp.esmtp = 'omg'
      assert_equal 'omg', smtp.esmtp
      assert_equal 'omg', smtp.esmtp?
    end

    def test_server_capabilities
      if defined? OpenSSL
        port = fake_server_start(starttls: true)
        smtp = Net::SMTP.start('localhost', port, starttls: false)
        assert_equal({"STARTTLS"=>[], "AUTH"=>["PLAIN"]}, smtp.capabilities)
        assert_equal(true, smtp.capable?('STARTTLS'))
        assert_equal(false, smtp.capable?('SMTPUTF8'))
      else
        port = fake_server_start
        smtp = Net::SMTP.start('localhost', port, starttls: false)
        assert_equal({"AUTH"=>["PLAIN"]}, smtp.capabilities)
        assert_equal(false, smtp.capable?('STARTTLS'))
        assert_equal(false, smtp.capable?('SMTPUTF8'))
      end
      smtp.finish
    end

    def test_rset
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, FakeSocket.new

      assert smtp.rset
    end

    def test_mailfrom
      sock = FakeSocket.new
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      assert smtp.mailfrom("foo@example.com").success?
      assert_equal "MAIL FROM:<foo@example.com>\r\n", sock.write_io.string
    end

    def test_mailfrom_with_address
      sock = FakeSocket.new
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      addr = Net::SMTP::Address.new("foo@example.com", size: 12345)
      assert smtp.mailfrom(addr).success?
      assert_equal "MAIL FROM:<foo@example.com> size=12345\r\n", sock.write_io.string
    end

    def test_rcptto
      sock = FakeSocket.new
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      assert smtp.rcptto("foo@example.com").success?
      assert_equal "RCPT TO:<foo@example.com>\r\n", sock.write_io.string
    end

    def test_rcptto_with_address
      sock = FakeSocket.new
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      addr = Net::SMTP::Address.new("foo@example.com", nofty: :failure)
      assert smtp.rcptto(addr).success?
      assert_equal "RCPT TO:<foo@example.com> nofty=failure\r\n", sock.write_io.string
    end

    def test_address
      a = Net::SMTP::Address.new('foo@example.com', 'p0=123', {p1: 456}, p2: nil, p3: '789')
      assert_equal 'foo@example.com', a.address
      assert_equal ['p0=123', 'p1=456', 'p2', 'p3=789'], a.parameters
    end

    def test_auth_plain
      sock = FakeSocket.new
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      assert smtp.auth_plain("foo", "bar").success?
      assert_equal "AUTH PLAIN AGZvbwBiYXI=\r\n", sock.write_io.string
    end

    def test_unsucessful_auth_plain
      sock = FakeSocket.new("535 Authentication failed: FAIL\r\n")
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      err = assert_raise(Net::SMTPAuthenticationError) { smtp.auth_plain("foo", "bar") }
      assert_equal "535 Authentication failed: FAIL\n", err.message
      assert_equal "535", err.response.status
    end

    def test_auth_login
      sock = FakeSocket.new("334 VXNlcm5hbWU6\r\n334 UGFzc3dvcmQ6\r\n235 2.7.0 Authentication successful\r\n")
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      assert smtp.auth_login("foo", "bar").success?
    end

    def test_unsucessful_auth_login
      sock = FakeSocket.new("334 VXNlcm5hbWU6\r\n334 UGFzc3dvcmQ6\r\n535 Authentication failed: FAIL\r\n")
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      err = assert_raise(Net::SMTPAuthenticationError) { smtp.auth_login("foo", "bar") }
      assert_equal "535 Authentication failed: FAIL\n", err.message
      assert_equal "535", err.response.status
    end

    def test_non_continue_auth_login
      sock = FakeSocket.new("334 VXNlcm5hbWU6\r\n235 2.7.0 Authentication successful\r\n")
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      err = assert_raise(Net::SMTPUnknownError) { smtp.auth_login("foo", "bar") }
      assert_equal "235 2.7.0 Authentication successful\n", err.message
      assert_equal "235", err.response.status
    end

    def test_unsuccessful_send_message_server_busy
      sock = FakeSocket.new("400 BUSY\r\n")
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      err = assert_raise(Net::SMTPServerBusy) { smtp.send_message('message', 'ojab@example.com') }
      assert_equal "400 BUSY\n", err.message
      assert_equal "400", err.response.status
    end

    def test_unsuccessful_send_message_syntax_error
      sock = FakeSocket.new("502 SYNTAX ERROR\r\n")
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      err = assert_raise(Net::SMTPSyntaxError) { smtp.send_message('message', 'ojab@example.com') }
      assert_equal "502 SYNTAX ERROR\n", err.message
      assert_equal "502", err.response.status
    end

    def test_unsuccessful_send_message_authentication_error
      sock = FakeSocket.new("530 AUTH ERROR\r\n")
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      err = assert_raise(Net::SMTPAuthenticationError) { smtp.send_message('message', 'ojab@example.com') }
      assert_equal "530 AUTH ERROR\n", err.message
      assert_equal "530", err.response.status
    end

    def test_unsuccessful_send_message_fatal_error
      sock = FakeSocket.new("520 FATAL ERROR\r\n")
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      err = assert_raise(Net::SMTPFatalError) { smtp.send_message('message', 'ojab@example.com') }
      assert_equal "520 FATAL ERROR\n", err.message
      assert_equal "520", err.response.status
    end

    def test_unsuccessful_send_message_unknown_error
      sock = FakeSocket.new("300 UNKNOWN\r\n")
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      err = assert_raise(Net::SMTPUnknownError) { smtp.send_message('message', 'ojab@example.com') }
      assert_equal "300 UNKNOWN\n", err.message
      assert_equal "300", err.response.status
    end

    def test_unsuccessful_data
      sock = FakeSocket.new("250 OK\r\n")
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, sock
      err = assert_raise(Net::SMTPUnknownError) { smtp.data('message') }
      assert_equal "could not get 3xx (250: 250 OK\n)", err.message
      assert_equal "250", err.response.status
    end

    def test_crlf_injection
      smtp = Net::SMTP.new 'localhost', 25
      smtp.instance_variable_set :@socket, FakeSocket.new

      assert_raise(ArgumentError) do
        smtp.mailfrom("foo\r\nbar")
      end

      assert_raise(ArgumentError) do
        smtp.mailfrom("foo\rbar")
      end

      assert_raise(ArgumentError) do
        smtp.mailfrom("foo\nbar")
      end

      assert_raise(ArgumentError) do
        smtp.rcptto("foo\r\nbar")
      end
    end

    def test_tls_connect
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      servers = Socket.tcp_server_sockets("localhost", 0)
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.ca_file = CA_FILE
      ctx.key = File.open(SERVER_KEY) { |f|
        OpenSSL::PKey::RSA.new(f)
      }
      ctx.cert = File.open(SERVER_CERT) { |f|
        OpenSSL::X509::Certificate.new(f)
      }
      sock = nil
      Thread.start do
        s = accept(servers)
        sock = OpenSSL::SSL::SSLSocket.new(s, ctx)
        sock.sync_close = true
        sock.accept
        sock.write("220 localhost Service ready\r\n")
        sock.gets
        sock.write("250 localhost\r\n")
        sock.gets
        sock.write("221 localhost Service closing transmission channel\r\n")
      end
      smtp = Net::SMTP.new("localhost", servers[0].local_address.ip_port, tls_verify: false)
      smtp.enable_tls
      smtp.open_timeout = 1
      smtp.start do
      end
    ensure
      sock&.close
      servers&.each(&:close)
    end

    def test_tls_connect_timeout
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      servers = Socket.tcp_server_sockets("localhost", 0)
      sock = nil
      Thread.start do
        sock = accept(servers)
      end
      smtp = Net::SMTP.new("localhost", servers[0].local_address.ip_port)
      smtp.enable_tls
      smtp.open_timeout = 0.1
      assert_raise(Net::OpenTimeout) do
        smtp.start do
        end
      end
    ensure
      sock&.close
      servers&.each(&:close)
    end

    def test_eof_error_backtrace
      bug13018 = '[ruby-core:78550] [Bug #13018]'
      servers = Socket.tcp_server_sockets("localhost", 0)
      begin
        sock = nil
        t = Thread.start do
          sock = accept(servers)
          sock.close
        end
        smtp = Net::SMTP.new("localhost", servers[0].local_address.ip_port)
        e = assert_raise(EOFError, bug13018) do
          smtp.start do
          end
        end
        assert_equal(EOFError, e.class, bug13018)
        assert(e.backtrace.grep(%r"\bnet/smtp\.rb:").size > 0, bug13018)
      ensure
        sock.close if sock
        servers.each(&:close)
        t.join
      end
    end

    def test_with_tls
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      port = fake_server_start(tls: true)
      smtp = Net::SMTP.new('localhost', port, tls: true, tls_verify: false)
      assert_nothing_raised do
        smtp.start{}
      end

      port = fake_server_start(tls: false)
      smtp = Net::SMTP.new('localhost', port, tls: false)
      assert_nothing_raised do
        smtp.start{}
      end
    end

    def test_with_starttls_always
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      port = fake_server_start(starttls: true)
      smtp = Net::SMTP.new('localhost', port, starttls: :always, tls_verify: false)
      smtp.start{}
      assert_equal(true, @starttls_started)

      port = fake_server_start(starttls: false)
      smtp = Net::SMTP.new('localhost', port, starttls: :always, tls_verify: false)
      assert_raise Net::SMTPUnsupportedCommand do
        smtp.start{}
      end
    end

    def test_with_starttls_auto
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      port = fake_server_start(starttls: true)
      smtp = Net::SMTP.new('localhost', port, starttls: :auto, tls_verify: false)
      smtp.start{}
      assert_equal(true, @starttls_started)

      port = fake_server_start(starttls: false)
      smtp = Net::SMTP.new('localhost', port, starttls: :auto, tls_verify: false)
      smtp.start{}
      assert_equal(false, @starttls_started)
    end

    def test_with_starttls_false
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      port = fake_server_start(starttls: true)
      smtp = Net::SMTP.new('localhost', port, starttls: false, tls_verify: false)
      smtp.start{}
      assert_equal(false, @starttls_started)

      port = fake_server_start(starttls: false)
      smtp = Net::SMTP.new('localhost', port, starttls: false, tls_verify: false)
      smtp.start{}
      assert_equal(false, @starttls_started)
    end

    def test_start
      port = fake_server_start
      smtp = Net::SMTP.start('localhost', port)
      smtp.finish
    end

    def test_start_with_position_argument
      port = fake_server_start(helo: 'myname', user: 'account', password: 'password')
      smtp = Net::SMTP.start('localhost', port, 'myname', 'account', 'password', :plain)
      smtp.finish
    end

    def test_start_with_keyword_argument
      port = fake_server_start(helo: 'myname', user: 'account', password: 'password')
      smtp = Net::SMTP.start('localhost', port, helo: 'myname', user: 'account', secret: 'password', authtype: :plain)
      smtp.finish
    end

    def test_start_password_is_secret
      port = fake_server_start(helo: 'myname', user: 'account', password: 'password')
      smtp = Net::SMTP.start('localhost', port, helo: 'myname', user: 'account', password: 'password', authtype: :plain)
      smtp.finish
    end

    def test_start_invalid_number_of_arguments
      err = assert_raise ArgumentError do
        Net::SMTP.start('localhost', 25, 'myname', 'account', 'password', :plain, :invalid_arg)
      end
      assert_equal('wrong number of arguments (given 7, expected 1..6)', err.message)
    end

    def test_start_with_tls
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      port = fake_server_start(tls: true)
      assert_nothing_raised do
        Net::SMTP.start('localhost', port, tls: true, tls_verify: false){}
      end

      port = fake_server_start(tls: false)
      assert_nothing_raised do
        Net::SMTP.start('localhost', port, tls: false){}
      end
    end

    def test_start_with_starttls_always
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      port = fake_server_start(starttls: true)
      Net::SMTP.start('localhost', port, starttls: :always, tls_verify: false){}
      assert_equal(true, @starttls_started)

      port = fake_server_start(starttls: false)
      assert_raise Net::SMTPUnsupportedCommand do
        Net::SMTP.start('localhost', port, starttls: :always, tls_verify: false){}
      end
    end

    def test_start_with_starttls_auto
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      port = fake_server_start(starttls: true)
      Net::SMTP.start('localhost', port, starttls: :auto, tls_verify: false){}
      assert_equal(true, @starttls_started)

      port = fake_server_start(starttls: false)
      Net::SMTP.start('localhost', port, starttls: :auto, tls_verify: false){}
      assert_equal(false, @starttls_started)
    end

    def test_start_with_starttls_false
      omit "openssl library not loaded" unless defined?(OpenSSL::VERSION)

      port = fake_server_start(starttls: true)
      Net::SMTP.start('localhost', port, starttls: false, tls_verify: false){}
      assert_equal(false, @starttls_started)

      port = fake_server_start(starttls: false)
      Net::SMTP.start('localhost', port, starttls: false, tls_verify: false){}
      assert_equal(false, @starttls_started)
    end

    def test_start_auth_plain
      port = fake_server_start(user: 'account', password: 'password', authtype: 'PLAIN')
      Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :plain){}

      port = fake_server_start(user: 'account', password: 'password', authtype: 'PLAIN')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'invalid', authtype: :plain){}
      end

      port = fake_server_start(user: 'account', password: 'password', authtype: 'LOGIN')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :plain){}
      end
    end

    def test_start_auth_login
      port = fake_server_start(user: 'account', password: 'password', authtype: 'LOGIN')
      Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :login){}

      port = fake_server_start(user: 'account', password: 'password', authtype: 'LOGIN')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'invalid', authtype: :login){}
      end

      port = fake_server_start(user: 'account', password: 'password', authtype: 'PLAIN')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :login){}
      end
    end

    def test_start_auth_cram_md5
      omit "openssl or digest library not loaded" unless defined? OpenSSL or defined? Digest

      port = fake_server_start(user: 'account', password: 'password', authtype: 'CRAM-MD5')
      Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :cram_md5){}

      port = fake_server_start(user: 'account', password: 'password', authtype: 'CRAM-MD5')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'invalid', authtype: :cram_md5){}
      end

      port = fake_server_start(user: 'account', password: 'password', authtype: 'PLAIN')
      assert_raise Net::SMTPAuthenticationError do
        Net::SMTP.start('localhost', port, user: 'account', password: 'password', authtype: :cram_md5){}
      end

      port = fake_server_start(user: 'account', password: 'password', authtype: 'CRAM-MD5')
      smtp = Net::SMTP.new('localhost', port)
      smtp.define_singleton_method(:digest_class) { raise '"openssl" or "digest" library is required' }
      e = assert_raise RuntimeError do
        smtp.start(user: 'account', password: 'password', authtype: :cram_md5){}
      end
      assert_equal('"openssl" or "digest" library is required', e.message)
    end

    def test_start_instance
      port = fake_server_start
      smtp = Net::SMTP.new('localhost', port)
      smtp.start
      smtp.finish
    end

    def test_start_instance_with_position_argument
      port = fake_server_start(helo: 'myname', user: 'account', password: 'password')
      smtp = Net::SMTP.new('localhost', port)
      smtp.start('myname', 'account', 'password', :plain)
      smtp.finish
    end

    def test_start_instance_with_keyword_argument
      port = fake_server_start(helo: 'myname', user: 'account', password: 'password')
      smtp = Net::SMTP.new('localhost', port)
      smtp.start(helo: 'myname', user: 'account', secret: 'password', authtype: :plain)
      smtp.finish
    end

    def test_start_instance_password_is_secret
      port = fake_server_start(helo: 'myname', user: 'account', password: 'password')
      smtp = Net::SMTP.new('localhost', port)
      smtp.start(helo: 'myname', user: 'account', password: 'password', authtype: :plain)
      smtp.finish
    end

    def test_start_instance_invalid_number_of_arguments
      smtp = Net::SMTP.new('localhost')
      err = assert_raise ArgumentError do
        smtp.start('myname', 'account', 'password', :plain, :invalid_arg)
      end
      assert_equal('wrong number of arguments (given 5, expected 0..4)', err.message)
    end

    def test_rcpt_to
      port = fake_server_start
      smtp = Net::SMTP.new('localhost', port)
      smtp.start do |conn|
        conn.send_message "test", "me@example.org", ["you@example.net", "friend@example.net"]
      end
      assert_equal %w[you@example.net friend@example.net], @recipients
    end

    def test_rcpt_to_bad_recipient
      port = fake_server_start
      smtp = Net::SMTP.new('localhost', port)
      smtp.start do |conn|
        assert_raise Net::SMTPSyntaxError do
          conn.send_message "test", "me@example.org", ["you@example.net", "-friend@example.net"]
        end
      end
    end

    def test_rcpt_to_temporary_failure_recipient
      port = fake_server_start
      smtp = Net::SMTP.new('localhost', port)
      smtp.start do |conn|
        assert_raise Net::SMTPServerBusy do
          conn.send_message "test", "me@example.org", ["~you@example.net", "friend@example.net"]
        end
      end
    end

    def test_rcpt_to_nonexistent_recipient_send_message
      port = fake_server_start
      smtp = Net::SMTP.new('localhost', port)
      smtp.start do |conn|
        assert_raise Net::SMTPMailboxPermanentlyUnavailable do
          conn.send_message "test", "me@example.org", ["nonexistent@example.net", "friend@example.net"]
        end
      end
      assert_empty @recipients
    end

    def test_rcpt_to_nonexistent_recipient_rcptto
      port = fake_server_start
      smtp = Net::SMTP.new('localhost', port)
      smtp.start do |conn|
        conn.mailfrom "me@example.org"
        assert_raise Net::SMTPMailboxPermanentlyUnavailable do
          conn.rcptto_list ["friend@example.net", "nonexistent@example.net"]
        end
      end
      assert_equal ["friend@example.net"], @recipients
    end

    private

    def accept(servers)
      Socket.accept_loop(servers) { |s, _| break s }
    end

    def fake_server_start(helo: 'localhost', user: nil, password: nil, tls: false, starttls: false, authtype: 'PLAIN')
      @starttls_started = false
      @recipients = []
      servers = Socket.tcp_server_sockets('localhost', 0)
      @server_threads << Thread.start do
        Thread.current.abort_on_exception = true
        sock = accept(servers)
        if tls || starttls
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.ca_file = CA_FILE
          ctx.key = File.open(SERVER_KEY){|f| OpenSSL::PKey::RSA.new(f)}
          ctx.cert = File.open(SERVER_CERT){|f| OpenSSL::X509::Certificate.new(f)}
        end
        if tls
          sock = OpenSSL::SSL::SSLSocket.new(sock, ctx)
          sock.sync_close = true
          sock.accept
        end
        sock.puts "220 ready\r\n"
        while comm = sock.gets
          case comm.chomp
          when /\AEHLO /
            assert_equal(helo, comm.split[1])
            sock.puts "220-servername\r\n"
            sock.puts "220-STARTTLS\r\n" if starttls
            sock.puts "220 AUTH #{authtype}\r\n"
          when "STARTTLS"
            unless starttls
              sock.puts "502 5.5.1 Error: command not implemented\r\n"
              next
            end
            sock.puts "220 2.0.0 Ready to start TLS\r\n"
            sock = OpenSSL::SSL::SSLSocket.new(sock, ctx)
            sock.sync_close = true
            sock.accept
            @starttls_started = true
          when /\AAUTH /
            unless user
              sock.puts "503 5.5.1 Error: authentication not enabled\r\n"
              next
            end
            _, type, arg = comm.split
            unless authtype.split.map(&:upcase).include? type.upcase
              sock.puts "535 5.7.8 Error: authentication failed: no mechanism available\r\n"
              next
            end
            # The account and password are fixed to "account" and "password".
            result = case type
                     when 'PLAIN'
                       arg == 'AGFjY291bnQAcGFzc3dvcmQ='
                     when 'LOGIN'
                       sock.puts '334 VXNlcm5hbWU6'
                       u = sock.gets.unpack1('m')
                       sock.puts '334 UGFzc3dvcmQ6'
                       p = sock.gets.unpack1('m')
                       u == 'account' && p == 'password'
                     when 'CRAM-MD5'
                       sock.puts "334 PDEyMzQ1Njc4OTAuMTIzNDVAc2VydmVybmFtZT4=\r\n"
                       r = sock.gets&.chomp
                       r == 'YWNjb3VudCAyYzBjMTgxZjkxOGU2ZGM5Mjg3Zjk3N2E1ODhiMzg1YQ=='
                     end
            if result
              sock.puts "235 2.7.0 Authentication successful\r\n"
            else
              sock.puts "535 5.7.8 Error: authentication failed: authentication failure\r\n"
            end
          when /\AMAIL FROM: *<.*>/
            sock.puts "250 2.1.0 Okay\r\n"
          when /\ARCPT TO: *<(.*)>/
            if $1.start_with? "-"
              sock.puts "501 5.1.3 Bad recipient address syntax\r\n"
            elsif $1.start_with? "~"
              sock.puts "450 4.2.1 Try again\r\n"
            elsif $1.start_with? "nonexistent"
              sock.puts "550 5.1.1 User unknown\r\n"
            else
              @recipients << $1
              sock.puts "250 2.1.5 Okay\r\n"
            end
          when "DATA"
            sock.puts "354 Continue (finish with dot)\r\n"
            loop do
              line = sock.gets
              break if line == ".\r\n"
            end
            sock.puts "250 2.6.0 Okay\r\n"
          when "QUIT"
            sock.puts "221 2.0.0 Bye\r\n"
            sock.close
            servers.each(&:close)
            break
          else
            sock.puts "502 5.5.2 Error: command not recognized\r\n"
          end
        end
      end
      port = servers[0].local_address.ip_port
      return port
    end
  end
end
