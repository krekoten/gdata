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

module GData
  module Client
    
    # Client class to wrap working with the Buzz Atom Feed.
    class Buzz < Base
      
      def initialize options = {}
        options[:authsub_scope] ||= 'https://www.googleapis.com/auth/buzz'
        super options
      end
      
      
      # Buzz requires scope and domain params to be present in authorize_url
      # you can override them with
      # :scope - Scope for Buzz
      # :domain - Domain which is requesting permissions
      def authorize_url_with_buzz options = {}
        options[:scope]   ||= @oauth_scope
        options[:domain]  ||= @api_key
        options.inject(authorize_url_without_buzz) do |res, (key, value)|
          res << '&' + CGI.escape(key.to_s) + '=' + CGI.escape(value.to_s)
        end
      end
      
      alias_method :authorize_url_without_buzz, :authorize_url
      alias_method :authorize_url, :authorize_url_with_buzz
      
      private
      
      def _oauth_handler! api_key, api_secret
        self.auth_handler = GData::Auth::OAuth.new(
          api_key,
          api_secret,
          # Buzz requires different authorization endpoint
          {:authorize_token_url => '/buzz/api/auth/OAuthAuthorizeToken'}
        )
      end
    end
  end
end