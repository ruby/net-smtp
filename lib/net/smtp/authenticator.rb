module Net
  class SMTP
    class Authenticator
      def self.auth_classes
        @classes ||= {}
      end

      def self.auth_type(type)
        type = type.to_s.upcase.tr(?_, ?-).to_sym
        Authenticator.auth_classes[type] = self
      end

      def self.auth_class(type)
        type = type.to_s.upcase.tr(?_, ?-).to_sym
        Authenticator.auth_classes[type]
      end

      attr_reader :smtp

      def initialize(smtp)
        @smtp = smtp
      end

      # @param arg [String] message to server
      # @return [String] message from server
      def continue(arg)
        res = smtp.get_response arg
        raise res.exception_class.new(res) unless res.continue?
        res.string.split[1]
      end

      # @param arg [String] message to server
      # @return [Net::SMTP::Response] response from server
      def finish(arg)
        res = smtp.get_response arg
        raise SMTPAuthenticationError.new(res) unless res.success?
        res
      end

      # @param str [String]
      # @return [String] Base64 encoded string
      def base64_encode(str)
        # expects "str" may not become too long
        [str].pack('m0')
      end
    end
  end
end
