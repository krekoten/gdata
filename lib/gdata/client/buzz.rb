module GData
  module Client
    
    # Client class to wrap working with the Buzz Atom Feed.
    class Buzz < Base
      
      def initialize options = {}
        options[:authsub_scope] ||= 'https://www.googleapis.com/auth/buzz'
        super options
      end
      
      private
      
      def _oauth_handler!
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