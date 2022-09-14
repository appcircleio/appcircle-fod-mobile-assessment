# frozen_string_literal: true

require 'json'
require 'uri'
require 'net/http'

def get_base_url(datacenter)
  if datacenter == 'fed'
    "https://api.#{dc}.fortifygov.com"
  else
    "https://api.#{dc}.fortify.com"
  end
end

def client
  {
    client_id: ENV['AC_FOD_CLIENT_ID'],
    client_secret: ENV['AC_FOD_CLIENT_SECRET'],
    base_url: get_base_url(ENV['AC_FOD_CLIENT_DATACENTER']),
    grant_type: 'client_credentials',
    scope: 'start-scans'
  }
end

def build_http_client
  http_client = Net::HTTP
  proxy_env = ENV['http_proxy'] || ENV['HTTP_PROXY']
  if proxy_env
    proxy       = URI.parse(proxy_env)
    http_client = Net::HTTP::Proxy(proxy.host, proxy.port)
  end
  http_client
end

def authentication(client)
  auth_url = "#{client[:base_url]}/oauth/token"
  headers = {
    'Accept' => 'application/json'
  }

  form = {
    'client_id' => client[:client_id],
    'client_secret' => client[:client_secret],
    'grant_type' => client[:grant_type],
    'scope' => client[:scope]
  }

  encoded_form = URI.encode_www_form(form)
  res = post(auth_url, encoded_form, headers)
  if res.is_a?(Net::HTTPSuccess)
    JSON.parse(res.body)
  else
    throw 'Authentication Error'
  end
end

def get(url, headers)
  uri = URI.parse(url) if url.respond_to? :to_str
  build_http_client.start(uri.host, uri.port) do |http|
    path_query = uri.path + (uri.query ? "?#{uri.query}" : '')
    res = http.get(path_query, headers)
    return res
  end
end

def post(url, data, headers)
  uri = URI.parse(url)
  build_http_client.start(uri.host, uri.port) do |http|
    path_query = uri.path + (uri.query ? "?#{uri.query}" : '')
    res = http.post(path_query, data, headers)
    return res
  end
end

def assessment_types(client, auth, release_id, assessment_type)
  assessment_url = "#{client[:base_url]}/api/v3/releases/#{release_id}/assessment-types?scanType=#{assessment_type}"

  headers = {
    'Accept' => 'application/json',
    'Authorization' => "#{auth['token_type']} #{auth['access_token']}"
  }

  res = get(assessment_url, headers)
  JSON.parse(res.body)
end

def upload_chunk(auth, data, start_date, id, frequency, remediation, frag_no, offset)
  puts "Uploading chunk #{frag_no}"
  headers = {
    'Accept' => 'application/json',
    'Authorization' => "#{auth['token_type']} #{auth['access_token']}",
    'Content-Type' => 'application/octet-stream'
  }
  entitlement_id = ENV['AC_FOD_ENTITLEMENT_ID']
  release_id = ENV['AC_FOD_RELEASE_ID']
  framework_type = ENV['AC_FOD_FRAMEWORK_TYPE']
  platform_type = ENV['AC_FOD_PLATFORM_TYPE']
  time_zone = 'GMT Standard Time'

  url = "#{client[:base_url]}/api/v3/releases/#{release_id}/\
mobile-scans/start-scan?assessmentTypeId=#{id}&entitlementFrequencyType=#{frequency}\
&entitlementId=#{entitlement_id}&fragNo=#{frag_no}&frameworkType=#{framework_type}\
&isRemediationScan=#{remediation}&offset=#{offset}&platformType=#{platform_type}\
&releaseId=#{release_id}&startDate=#{start_date}&timeZone=#{time_zone}"
  res = post(url, data, headers)
  JSON.parse(res.body)
end

def upload(auth, path, id, frequency, remediation)
  chunk_size = 1024 * 1024 # 1 MB
  start_date = Time.now.utc.strftime('%Y-%m-%d %H:%M')

  chunk = 0
  File.open(path, 'r') do |file|
    loop do
      data = file.read(chunk_size)
      offset = chunk * chunk_size
      if file.eof?
        result = upload_chunk(auth, data, start_date, id, frequency, remediation, -1, offset)
        puts "Mobile scan submitted. Scan ID: #{result['scanId']}"
        break
      else
        upload_chunk(auth, data, start_date, id, frequency, remediation, chunk, offset)
      end
      chunk += 1
    end
  end
rescue StandardError => e
  throw "Error during upload #{e}"
end

release_id = ENV['AC_FOD_RELEASE_ID']
assessment_type = ENV['AC_FOD_ASSESSMENT_TYPE']
fod_file_path = ENV['AC_FOD_FILE_PATH']

puts 'Authenticating...'
auth = authentication(client)
puts 'Authenticated.'

puts 'Checking compatible assessments...'
results = assessment_types(client, auth, release_id, assessment_type)

assessment_type_id = nil
frequency_type = nil
is_remediation = 'false'
results['items'].each do |at|
  next unless assessment_type == at['frequencyType']

  assessment_type_id = at['assessmentTypeId']
  frequency_type = at['frequencyType']
  is_remediation = 'true' if at['isRemediation'] == true
end

if assessment_type_id.nil?
  throw "Can't find compatible assessment"
else
  puts 'Compatible assessment found. Uploading...'
  upload(auth, fod_file_path, assessment_type_id, frequency_type, is_remediation)
end
