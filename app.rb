require 'sinatra'
require 'dotenv/load'
require 'httparty'
require 'shopify_api'

Dotenv.load

APP_URL = '39cec6b8.ngrok.io'
API_KEY = ENV['API_KEY']
API_SECRET = ENV['API_SECRET']

set :tokens, {}

helpers do
  def validate_hmac!(hmac, request)
    h = request.params.reject{|k,v| k == 'hmac' || k == 'signature'}
    query = URI.encode_www_form(h)
    digest = OpenSSL::Digest.new('sha256')
    mac = OpenSSL::HMAC.hexdigest(digest, API_SECRET, query)

    halt 403, "Authentication failed. Digest provided was: #{digest}" unless hmac == mac
  end

  def get_shop_access_token!(shop, client_id, client_secret, code)
    return unless settings.tokens[shop].nil?

    url = "https://#{shop}/admin/oauth/access_token"

    payload = {
      client_id: client_id,
      client_secret: client_secret,
      code: code
    }

    response = HTTParty.post(url, body: payload)

    halt 505, 'Something went wrong' unless response.code == 200

    settings.tokens[shop] = response['access_token']
  end

  def instantiate_session(shop)
    session = ShopifyAPI::Session.new(shop, settings.tokens[shop])
    ShopifyAPI::Base.activate_session(session)
  end

  def create_order_webhook
    return if ShopifyAPI::Webhook.find(:all).any?

    webhook = {
      topic: 'orders/create',
      address: "https://#{APP_URL}/firstapp/webhook/order_create",
      format: 'json'
    }

    ShopifyAPI::Webhook.create(webhook)
  end

  def bulk_edit_url
    "https://www.shopify.com/admin/bulk?resource_name=ProductVariant&edit=metafields.test.ingredients:string"
  end

  def verify_webhook!(hmac, data)
    digest = OpenSSL::Digest.new('sha256')
    calculated_hmac = Base64.encode64(OpenSSL::HMAC.digest(digest, API_SECRET, data)).strip

    halt 403, "You're not authorized to perform this action" unless hmac == calculated_hmac
  end
end

get '/firstapp/install' do
  shop = params[:shop]
  scopes = "read_orders,read_products,write_products"

  # construct the installation URL and redirect the merchant
  install_url = "https://#{shop}/admin/oauth/authorize?client_id=#{API_KEY}&scope=#{scopes}&redirect_uri=https://#{APP_URL}/firstapp/auth"

  redirect install_url
end

get '/firstapp/auth' do
  shop = params[:shop]
  code = params[:code]
  hmac = params[:hmac]

  # perform hmac validation to determine if the request is coming from Shopify
  validate_hmac!(hmac, request)

  # if no access token for this particular shop exist,
  # POST the OAuth request and receive the token in the response
  get_shop_access_token!(shop, API_KEY, API_SECRET, code)

  # now that the token is available, instantiate a session
  instantiate_session(shop)

  # create webhook for order creation if it doesn't exist
  create_order_webhook

  # now that the session is activated, redirect to the bulk edit page
  redirect bulk_edit_url
end

post '/firstapp/webhook/order_create' do
  # inspect hmac value in header and verify webhook
  hmac = request.env['HTTP_X_SHOPIFY_HMAC_SHA256']

  request.body.rewind
  data = request.body.read

  verify_webhook!(hmac, data)

  shop = request.env['HTTP_X_SHOPIFY_SHOP_DOMAIN']

  halt 403, "You're not authorized to perform this action" if settings.tokens[shop].nil?

  instantiate_session(shop)

  # parse the request body as JSON data
  json_data = JSON.parse data

  line_items = json_data['line_items']

  line_items.each do |line_item|
    variant_id = line_item['variant_id']

    variant = ShopifyAPI::Variant.find(variant_id)

    variant.metafields.each do |field|
      if field.key == 'ingredients'
        items = field.value.split(',')

        items.each do |item|
          gift_item = ShopifyAPI::Variant.find(item)
          gift_item.inventory_quantity = gift_item.inventory_quantity - 1
          gift_item.save
        end
      end
    end
  end

  return [200, "Webhook notification received successfully"]
end
