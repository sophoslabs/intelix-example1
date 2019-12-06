# encoding: utf-8
require "logstash/filters/base"
require "vine"
require 'rest-client'
require "vine"
require "json"
require "oauth2"
require 'zache'
require "time"

class LogStash::Filters::IntellixWeb < LogStash::Filters::Base
  config_name "intellix-web"

  # For filed containing the item to lookup. This can point to a field ontaining a File Hash or URL
  config :field, :validate => :string, :required => true
  config :client_id, :validate => :string, :required => true
  config :client_secret, :validate => :string, :required => true
  config :intellix_web_endpoint, :validate => :string, :required => true
  config :intellix_auth_endpoint, :validate => :string, :required => true

  private
  def get_access_token
    @logger.info("Getting access token.")
    
    client = OAuth2::Client.new(
      @client_id,
      @client_secret,
      :site   => @intellix_auth_endpoint,
      :token_url => '/oauth2/token'
    )

    @oauth2_access_token = client.client_credentials.get_token
  end

  private
  def lookup_url(url)
    @logger.info("Looking up " + url)

    time_before = Time.now.to_f
    response = RestClient.get @intellix_web_endpoint + url, {'X-Correlation-ID': SecureRandom.hex, accept: 'application/json', Authorization: @oauth2_access_token.token }
    time_after = Time.now.to_f

    result = JSON.parse(response.body)

    if response.code == 200
      result['elapsed'] = time_after - time_before
      return result
    else
      @logger.error(result)
    end
  end

  public
  def register
    @zache = Zache.new
    @oauth2_access_token = nil
  end # def register

  public
  def filter(event)
    #@logger.info(event)

    protocol = event.get('type')
    if protocol == 'http'
      url = event.to_hash.access(@field)

      if url != nil
        if (@oauth2_access_token == nil) || (@oauth2_access_token.expired?)
          get_access_token()
        end

        url = url.gsub(/\:\d+$/,'')
        threat = @zache.get(url, lifetime: 15 * 60) do
          lookup_url(url)
        end

        threat['url'] = url
      end
    end

    event.set("intellix", threat)


   filter_matched(event)
  end # def filter
end # class LogStash::Filters::IntellixWeb
