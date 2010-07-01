# Copyright (C) 2010 Marjan Krekoten' (Мар'ян Крекотень)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'oauth'
require 'forwardable'

module GData
  module Auth
    class OAuth
      
      extend Forwardable
      
      def_delegators :request_token, :authorize_url
      
      BASE_URL            = 'https://www.google.com'
      
      REQUEST_TOKEN_URL   = '/accounts/OAuthGetRequestToken'
      AUTHORIZE_TOKEN_URL = '/accounts/OAuthAuthorizeToken'
      ACCESS_TOKEN_URL    = '/accounts/OAuthGetAccessToken'
      
      attr_accessor :api_key, :api_secret
      
      def initialize api_key, api_secret
        @api_key = api_key
        @api_secret = api_secret
      end

      # Get consumer
      def consumer
        @consumer ||= ::OAuth::Consumer.new(api_key, api_secret, {
          :site               => BASE_URL,
          :request_token_path => REQUEST_TOKEN_URL,
          :access_token_path  => ACCESS_TOKEN_URL,
          :authorize_path     => AUTHORIZE_TOKEN_URL
        })
      end
      
      # Get request token
      # :oauth_callback => String, url that google should redirect to
      # :scope          => String, URL identifying the service(s) to be accessed
      def request_token options = {}
        arguments = {}
        arguments[:scope] = options.delete(:scope) if options[:scope]
        @request_token ||= consumer.get_request_token(options, arguments)
      end
      
      # Get access token
      def access_token
        @access_token ||= ::OAuth::AccessToken.new(consumer, @atoken, @asecret)
      end
      
      # Authorize using authorized request token
      def authorize_from_request req_token, req_secret, verifier
        request_token = ::OAuth::RequestToken.new(consumer, req_token, req_secret)
        # Gogole requires content type to be "Content-Type: application/x-www-form-urlencoded"
        access_token = request_token.get_access_token({:oauth_verifier => verifier}, nil, {'Content-Type' => 'application/x-www-form-urlencoded'})
        @atoken, @asecret = access_token.token, access_token.secret
      end
      
      # Authorize from saved access token
      def authorize_from_access atoken, asecret
        @atoken, @asecret = atoken, asecret
      end
      
      # Sign request. Called in GData::Client::Base.make_request
      def sign_request! request
        request.class.class_eval do
          attr_accessor :consumer, :token
        end unless request.respond_to?(:consumer)
        
        request.consumer = consumer
        request.token = access_token
      end
      
    end
  end
end