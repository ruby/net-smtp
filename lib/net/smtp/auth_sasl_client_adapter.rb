# frozen_string_literal: true

require "net/imap"

module Net
  class SMTP
    SASL = Net::IMAP::SASL

    # Experimental
    #
    # Initialize with a block that runs a command, yielding for continuations.
    class SASLClientAdapter < SASL::ClientAdapter
      include SASL::ProtocolAdapters::SMTP

      RESPONSE_ERRORS = [
        SMTPAuthenticationError,
        SMTPServerBusy,
        SMTPSyntaxError,
        SMTPFatalError,
      ].freeze

      def initialize(...)
        super
        @command_proc ||= client.method(:send_command_with_continuations)
      end

      def authenticate(...)
        super
      rescue SMTPServerBusy, SMTPSyntaxError, SMTPFatalError => error
        raise SMTPAuthenticationError.new(error.response)
      rescue SASL::AuthenticationIncomplete => error
        raise error.response.exception_class.new(error.response)
      end

      def host;               client.address    end
      def response_errors;    RESPONSE_ERRORS   end
      def sasl_ir_capable?;   true              end
      def drop_connection;    client.quit!(exception: :warn) end
      def drop_connection!;   client.disconnect end
    end
  end
end
