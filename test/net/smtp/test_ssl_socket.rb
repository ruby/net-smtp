# frozen_string_literal: true
require 'net/smtp'
require 'test/unit'

module Net
  class TestSSLSocket < Test::Unit::TestCase
    class MySMTP < SMTP
      attr_accessor :fake_tcp, :fake_ssl

      def initialize(*args)
        super(*args)
        @open_timeout = nil
      end

      def tcp_socket address, port
        fake_tcp
      end

      def ssl_socket socket, context
        fake_ssl
      end
    end

    require 'stringio'
    class SSLSocket < StringIO
      attr_accessor :sync_close, :closed

      def initialize(*args)
        @closed = false
        super
      end

      def connect
      end

      def close
        self.closed = true
      end

      def post_connection_check omg
      end
    end

    def test_ssl_socket_close_on_connect_fail
      tcp_socket = StringIO.new success_response

      ssl_socket = SSLSocket.new.extend Module.new {
        def connect
          raise OpenSSL::SSL::SSLError, "SSL_connect returned=1 errno=0 state=error: certificate verify failed (Hostname mismatch)"
        end
      }

      connection = MySMTP.new('localhost', 25)
      connection.fake_tcp = tcp_socket
      connection.fake_ssl = ssl_socket

      assert_raise(OpenSSL::SSL::SSLError) do
        connection.start
      end
      assert_equal true, ssl_socket.closed
    end

    def test_ssl_socket_open_on_connect_success
      tcp_socket = StringIO.new success_response

      ssl_socket = SSLSocket.new success_response

      connection = MySMTP.new('localhost', 25)
      connection.fake_tcp = tcp_socket
      connection.fake_ssl = ssl_socket

      connection.start
      assert_equal false, ssl_socket.closed
    end

    def success_response
      [
        '220 smtp.example.com ESMTP Postfix',
        "250-ubuntu-desktop",
        "250-PIPELINING",
        "250-SIZE 10240000",
        "250-VRFY",
        "250-ETRN",
        "250-STARTTLS",
        "250-ENHANCEDSTATUSCODES",
        "250-8BITMIME",
        "250 DSN",
        "220 2.0.0 Ready to start TLS",
      ].join("\r\n") + "\r\n"
    end
  end
end if defined?(OpenSSL)
