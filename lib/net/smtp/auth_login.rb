class Net::SMTP
  class AuthLogin < Net::SMTP::Authenticator
    auth_type :login

    def auth(user_arg = nil, secret_arg = nil,
             authcid: nil, username: nil, user: nil,
             secret: nil, password: nil,
             **)
      user   = req_param authcid, username, user, user_arg, "username (authcid)"
      secret = req_param password, secret, secret_arg,      "secret (password)"
      continue('AUTH LOGIN')
      continue(base64_encode(user))
      finish(base64_encode(secret))
    end
  end
end
