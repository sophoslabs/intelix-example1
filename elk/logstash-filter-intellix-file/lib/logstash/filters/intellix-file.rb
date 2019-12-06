# encoding: utf-8
require "logstash/filters/base"
require 'rest-client'
require "vine"
require "json"
require "oauth2"
require "securerandom"

class LogStash::Filters::IntellixFile < LogStash::Filters::Base
  config_name "intellix-file"
  config :client_id, :validate => :string, :required => true
  config :client_secret, :validate => :string, :required => true
  config :intellix_file_endpoint, :validate => :string, :required => true
  config :intellix_auth_endpoint, :validate => :string, :required => true
  config :field, :validate => :string, :required => true

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
  def translate_score(score)
    if (0..19).include?(score)
      return "Malware"
    elsif (20..29).include?(score)
      return "PUA"
    elsif (30..69).include?(score)
      return "Unknown/suspicious"
    elsif (70..100).include?(score)
      return "Known good"
    else
      return "ERR"
    end
  end

  private
  def lookup_hash(sha256)
    time_before = Time.now.to_f
    response = RestClient.get @intellix_file_endpoint + sha256, {'X-Correlation-ID': SecureRandom.hex, content_type: 'application/x-www-form-urlencoded', accept: 'application/json', Authorization: @oauth2_access_token.token }
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
    @oauth2_access_token
  end # def register

  public
  def filter(event)
    @logger.info("Getting access token." + event.get("service")['type'])

    if event.get("service")['type'] == "file_integrity"
      threat_hash = event.to_hash.access(@field)
      # on deletion the sha is nil
      if threat_hash!= nil
  
        if (@oauth2_access_token == nil) || (@oauth2_access_token.expired?)
          get_access_token()
        end
  
        threat_intelligence = lookup_hash(threat_hash)
        threat_intelligence['reputationName'] = translate_score(threat_intelligence['reputationScore'])
  
        event.set("intellix", threat_intelligence)
  
        # filter_matched should go in the last line of our successful code
      end
    end

    filter_matched(event)

  end # def filter
end # class LogStash::Filters::IntellixFile
