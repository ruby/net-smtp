class Net::SMTP
  class AuthPlain < Net::SMTP::Authenticator
    auth_type :plain

    def auth(user_arg = nil, secret_arg = nil,
             authcid: nil, username: nil, user: nil,
             secret: nil, password: nil,
             **)
      user   = req_param authcid, username, user, user_arg, "username (authcid)"
      secret = req_param password, secret, secret_arg,      "secret (password)"
      finish('AUTH PLAIN ' + base64_encode("\0#{user}\0#{secret}"))
    end
  end
end
