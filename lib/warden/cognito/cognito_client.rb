module Warden
  module Cognito
    class CognitoClient
      include Cognito::Import['user_pools']
      include HasUserPoolIdentifier

      # https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/CognitoIdentityProvider/Types/GetUserResponse.html
      def fetch(access_token)
        client.get_user(access_token: access_token)
      end

      def initiate_auth(email, password)
        client.initiate_auth(
          client_id: user_pool.client_id,
          auth_flow: 'USER_PASSWORD_AUTH',
          auth_parameters: {
            'USERNAME' => email,
            'PASSWORD' => password
          }
        )
      end

      def exchange_token(token, username)
        client.initiate_auth(
          auth_flow: 'REFRESH_TOKEN',
          client_id: user_pool.client_id,
          auth_parameters: {
            'REFRESH_TOKEN' => token,
            'SECRET_HASH' => gen_secret(username)
          }
        )
      end

      private

      def client
        Aws::CognitoIdentityProvider::Client.new region: user_pool.region
      end

      def gen_secret(username)
        message = username + user_pool.client_id
        [OpenSSL::HMAC.digest('SHA256', user_pool.client_secret, message)].pack('m0')
      end

      class << self
        def scope(pool_identifier)
          new.tap do |client|
            client.user_pool = pool_identifier || default_pool_identifier
          end
        end

        private

        def default_pool_identifier
          Warden::Cognito.config.user_pools.first.identifier
        end
      end
    end
  end
end
