# frozen_string_literal: true

module Net
  class SMTP

    # Curries arguments to SASLAdapter.authenticate.
    class AuthSASLCompatibilityAdapter
      def initialize(mechanism) @mechanism = mechanism end
      def check_args(...) SASL.authenticator(@mechanism, ...) end
      def new(smtp) @sasl_adapter = SASLClientAdapter.new(smtp); self end
      def auth(...) @sasl_adapter.authenticate(@mechanism, ...) end
    end

    Authenticator.auth_classes.default_proc = ->hash, mechanism {
      hash[mechanism] = AuthSASLCompatibilityAdapter.new(mechanism)
    }

  end
end
