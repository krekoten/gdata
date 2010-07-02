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
      
      attr_accessor :base_url, :request_token_url, :authorize_token_url, :access_token_url
      
      @base_url            = 'https://www.google.com'
      
      @request_token_url   = '/accounts/OAuthGetRequestToken'
      @authorize_token_url = '/accounts/OAuthAuthorizeToken'
      @access_token_url    = '/accounts/OAuthGetAccessToken'
      
      attr_accessor :api_key, :api_secret
      
      def initialize api_key, api_secret, options = {}
        @api_key = api_key
        @api_secret = api_secret
        
        options.each do |option, value|
          send "#{option}=", value if respond_to? "#{option}="
        end unless options.empty?
      end

      # Get consumer
      def consumer
        @consumer ||= ::OAuth::Consumer.new(api_key, api_secret, {
          :site               => @base_url,
          :request_token_path => @request_token_url,
          :access_token_path  => @access_token_url,
          :authorize_path     => @authorize_token_url
        })
      end
      
      # Get request token
      # :oauth_callback => String, url that google should redirect to
      # :scope          => String, URL identifying the service(s) to be accessed
      def request_token options = {}
        arguments = {}
        arguments[:scope] = options.delete(:scope) if options[:scope]
        # Buzz specific options
        arguments[:domain] = options.delete(:domain) if options[:domain]
        arguments[:iconUrl] = options.delete(:iconUrl) if options[:iconUrl]
        
        @request_token ||= consumer.get_request_token(options, arguments)
      end
      
      # Get access token
      def access_token
        @access_token ||= ::OAuth::AccessToken.new(consumer, @atoken, @asecret)
      end
      
      # Authorize using authorized request token
      def authorize_from_request req_token, req_secret, verifier = nil
        request_token = ::OAuth::RequestToken.new(consumer, req_token, req_secret)
        # Gogole requires content type to be "Content-Type: application/x-www-form-urlencoded"
        params = verifier ? {:oauth_verifier => verifier} : {}
        access_token = request_token.get_access_token(params, nil, {'Content-Type' => 'application/x-www-form-urlencoded'})
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