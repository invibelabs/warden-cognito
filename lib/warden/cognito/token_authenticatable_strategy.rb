require 'aws-sdk-cognitoidentityprovider'
# rubocop:disable Style/SignalException

module Warden
  module Cognito
    class TokenAuthenticatableStrategy < Warden::Strategies::Base
      METHOD = 'Bearer'.freeze

      attr_reader :helper

      def initialize(env, scope = nil)
        super
        @helper = UserHelper.new
      end

      def valid?
        puts 'in valid?'
        puts token_decoder.inspect
        res = token_decoder.validate!
        puts res
        res
      rescue ::JWT::ExpiredSignature
        true
      rescue StandardError => e
        puts 'valid? error'
        puts e
        puts e.inspect
        false
      end

      def authenticate!
        user = local_user || UserNotFoundCallback.call(cognito_user, token_decoder.pool_identifier)

        fail!(:unknown_user) unless user.present?
        success!(user)
      rescue ::JWT::ExpiredSignature
        fail!(:token_expired)
      rescue StandardError
        fail(:unknown_error)
      end

      def store?
        false
      end

      private

      def cognito_user
        token_decoder.cognito_user
      end

      def local_user
        LocalUserMapper.find token_decoder
      end

      def token_decoder
        @token_decoder ||= RefreshableTokenDecoder.new(token, refresh_token, pool_identifier)
      end

      def pool_identifier
        env['HTTP_X_AUTHORIZATION_POOL_IDENTIFIER']
      end

      def token
        @token ||= extract_token
      end

      def refresh_token
        @refresh_token ||= extract_refresh_token
      end

      def extract_token
        cookies['AccessToken'].first
      end

      def extract_refresh_token
        cookies['RefreshToken'].first
      end

      def cookies
        @cookies ||= CGI::Cookie.parse(env['HTTP_COOKIE'])
      end
    end
  end
end
# rubocop:enable Style/SignalException

Warden::Strategies.add(:cognito_jwt, Warden::Cognito::TokenAuthenticatableStrategy)
