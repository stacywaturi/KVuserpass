#include "cpprest/http_client.h"
#include "cpprest/containerstream.h"
#include "cpprest/filestream.h"

#ifdef _WIN32
#include <time.h>
#include <objbase.h>
#else
#include <sys/time.h>
#include <uuid/uuid.h>
#endif

// globals
utility::string_t clientId = _XPLATSTR("");

utility::string_t username = _XPLATSTR("");
utility::string_t password = _XPLATSTR("");
utility::string_t keyVaultName = _XPLATSTR("");
utility::string_t blobContainer = _XPLATSTR("");
bool verbose = false;
//////////////////////////////////////////////////////////////////////////////
//
class KeyVaultClient
{
	//Variables
public:
	utility::string_t tokenType;
	utility::string_t accessToken;
	utility::string_t keyVaultUrl;
	utility::string_t loginUrl;
	utility::string_t resourceUrl;
	utility::string_t keyVaultName;
	utility::string_t keyVaultRegion;

private:
	int status_code;
	web::json::value secret;
	web::json::value key;

	//Methods

private:
	utility::string_t get_https_url(utility::string_t headerValue);
	pplx::task<void> GetLoginUrl();
	pplx::task<void> get_secret(utility::string_t secretName);
	pplx::task<void> get_key(utility::string_t secretName);
	utility::string_t NewGuid();
	utility::string_t read_response_body(web::http::http_response response);

public:
	pplx::task<void> Authenticate(utility::string_t& clientId, /*utility::string_t& clientSecret,*/
		utility::string_t& username, utility::string_t& password, utility::string_t& keyVaultName);
	bool GetSecretValue(utility::string_t secretName, web::json::value& secret);
	bool GetKeyValue(utility::string_t secretName, web::json::value& key);
};
//////////////////////////////////////////////////////////////////////////////
// helper to generate a new guid (currently Linux specific, for Windows we 
// should use ::CoCreateGuid() 
utility::string_t KeyVaultClient::NewGuid()
{
	utility::string_t guid;
#ifdef _WIN32
	GUID wguid;
	::CoCreateGuid(&wguid);
	wchar_t		uuid_str[38 + 1];
	::StringFromGUID2((const GUID&)wguid, uuid_str, sizeof(uuid_str));
#else
	uuid_t uuid;
	uuid_generate_time_safe(uuid);
	char uuid_str[37];
	uuid_unparse_lower(uuid, uuid_str);
#endif
	guid = uuid_str;
	return guid;
}
//////////////////////////////////////////////////////////////////////////////
//
utility::string_t KeyVaultClient::read_response_body(web::http::http_response response)
{
	auto bodyStream = response.body();
	concurrency::streams::stringstreambuf sb;
	auto& target = sb.collection();
	bodyStream.read_to_end(sb).get();
#ifdef _WIN32 // Windows uses UNICODE but result is in UTF8, so we need to convert it
	utility::string_t wtarget;
	wtarget.assign(target.begin(), target.end());
	return wtarget;
#else
	return target;
#endif
}
//////////////////////////////////////////////////////////////////////////////
// Call Azure KeyVault REST API to retrieve a secret
bool KeyVaultClient::GetSecretValue(utility::string_t secretName, web::json::value &secret)
{
	get_secret(secretName).wait();
	secret = this->secret;
	return this->status_code == 200;
}
pplx::task<void> KeyVaultClient::get_secret(utility::string_t secretName)
{
	auto impl = this;
	// create the url path to query the keyvault secret
	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/secrets/") + secretName + _XPLATSTR("?api-version=2015-06-01");

	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	web::http::http_request request(web::http::methods::GET);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	//std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;

			
			impl->secret = web::json::value::parse(target.c_str(), err);
			//std::wcout << impl->secret << std::endl;
			
		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}

//////////////////////////////////////////////////////////////////////////////
// Call Azure KeyVault REST API to retrieve a key
bool KeyVaultClient::GetKeyValue(utility::string_t secretName, web::json::value &secret)
{
	get_key(secretName).wait();
	secret = this->key;
	return this->status_code == 200;
}
pplx::task<void> KeyVaultClient::get_key(utility::string_t secretName)
{
	auto impl = this;
	// create the url path to query the keyvault secret
	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/keys/") + secretName + _XPLATSTR("?api-version=2015-06-01");

	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	web::http::http_request request(web::http::methods::GET);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	//std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;

			
			impl-> key = web::json::value::parse(target.c_str(), err);
			//std::wcout << impl->secret << std::endl;
			
		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}
//////////////////////////////////////////////////////////////////////////////
// helper to parse out https url in double quotes
utility::string_t KeyVaultClient::get_https_url(utility::string_t headerValue)
{
	size_t pos1 = headerValue.find(_XPLATSTR("https://"));
	if (pos1 >= 0) {
		size_t pos2 = headerValue.find(_XPLATSTR("\""), pos1 + 1);
		if (pos2 > pos1) {
			utility::string_t url = headerValue.substr(pos1, pos2 - pos1);
			headerValue = url;
		}
		else {
			utility::string_t url = headerValue.substr(pos1);
			headerValue = url;
		}
	}
	return headerValue;
}
//////////////////////////////////////////////////////////////////////////////
// Make a HTTP POST to oauth2 IDP source to get JWT Token containing
// access token & token type
pplx::task<void> KeyVaultClient::Authenticate(utility::string_t& clientId, /*utility::string_t& clientSecret,*/
	utility::string_t& username, utility::string_t& password, utility::string_t& keyVaultName)
{
	auto impl = this;
	impl->keyVaultName = keyVaultName;

	// make a un-auth'd request to KeyVault to get a response that contains url to IDP
	impl->GetLoginUrl().wait();

	// create the oauth2 authentication request and pass the clientId/Secret as app identifiers
	utility::string_t url = impl->loginUrl + _XPLATSTR("/oauth2/token");
	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	utility::string_t postData = _XPLATSTR("resource=") + web::uri::encode_uri(impl->resourceUrl) + _XPLATSTR("&client_id=") + clientId /*+ _XPLATSTR("&client_secret=") + clientSecret*/
		+ _XPLATSTR("&username=") + username + _XPLATSTR("&password=") + password + _XPLATSTR("&grant_type=password");
	//std::wcout << postData << std::endl;

	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/x-www-form-urlencoded"));
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("return-client-request-id"), _XPLATSTR("true"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	request.set_body(postData);


	// response from IDP is a JWT Token that contains the token type and access token we need for
	// Azure HTTP REST API calls
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;

		impl->status_code = response.status_code();
		if (impl->status_code == 200) {
			utility::string_t target = impl->read_response_body(response);
			std::error_code err;
			web::json::value jwtToken = web::json::value::parse(target.c_str(), err);
			if (err.value() == 0) {
				impl->tokenType = jwtToken[_XPLATSTR("token_type")].as_string();
				impl->accessToken = jwtToken[_XPLATSTR("access_token")].as_string();
			}
		}
	});
}
//////////////////////////////////////////////////////////////////////////////
// Make a HTTP Get to Azure KeyVault unauthorized which gets us a response 
// where the header contains the url of IDP to be used
pplx::task<void> KeyVaultClient::GetLoginUrl()
{
	auto impl = this;
	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/keys/secretname?api-version=2015-06-01");
	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	return client.request(web::http::methods::GET).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		impl->status_code = response.status_code();
		if (impl->status_code == 401) {

			web::http::http_headers& headers = response.headers();
			//std::wcout << response.to_string() << std::endl;

			impl->keyVaultRegion = headers[_XPLATSTR("x-ms-keyvault-region")];
			const utility::string_t& wwwAuth = headers[_XPLATSTR("WWW-Authenticate")];
			// std::wcout << wwwAuth << std::endl;

			// parse WWW-Authenticate header into url links. Format:
			// Bearer authenticate="url", resource="url"
			utility::string_t delimiter = _XPLATSTR(" ");
			size_t count = 0, start = 0, end = wwwAuth.find(delimiter);
			while (end != utility::string_t::npos)
			{
				utility::string_t part = wwwAuth.substr(start, end - start);
				if (count == 1) {
					impl->loginUrl = impl->get_https_url(part);
				}
				start = end + delimiter.length();
				end = wwwAuth.find(delimiter, start);
				count++;
			}
			utility::string_t part = wwwAuth.substr(start, end - start);

			impl->resourceUrl = impl->get_https_url(part);
		}
	});
}
//////////////////////////////////////////////////////////////////////////////
// Read configFile where each line is in format key=value
void GetConfig(utility::string_t configFile)
{
	utility::ifstream_t fin(configFile);
	utility::string_t line;
	utility::istringstream_t sin;
	utility::string_t val;


	while (std::getline(fin, line)) {
		sin.str(line.substr(line.find(_XPLATSTR("=")) + 1));
		sin >> val;
		if (line.find(_XPLATSTR("keyVaultName")) != std::string::npos) {
			keyVaultName = val;
		}
		else if (line.find(_XPLATSTR("clientId")) != std::string::npos) {
			clientId = val;
		}
		else if (line.find(_XPLATSTR("username")) != std::string::npos) {
			username = val;
		}
		else if (line.find(_XPLATSTR("password")) != std::string::npos) {
			password = val;
		}
		else if (line.find(_XPLATSTR("blobContainer")) != std::string::npos) {
			blobContainer = val;
		}
		else if (line.find(_XPLATSTR("verbose")) != std::string::npos) {
			if (val.find(_XPLATSTR("true")) != std::string::npos) {
				verbose = true;
			}
		}
		sin.clear();
	}
}
//////////////////////////////////////////////////////////////////////////////
//
#ifdef _WIN32
int wmain(int argc, wchar_t* argv[])
#else
int main(int argc, char* argv[])
#endif
{
	if (argc < 2) {
		std::wcout << _XPLATSTR("syntax: .\program type [key/secretName]") << std::endl;
	}

	KeyVaultClient kvc;
	utility::string_t type = argv[1];
	utility::string_t secretName = _XPLATSTR("");
	
	if ( argc >= 3) {
	secretName = argv[2];
	//std::wcout << _XPLATSTR("with namess") << std::endl;
	//blobName = argv[3];
	}

	/////////////////////////////////////////////////////////////////////////
	// load values from config file
	GetConfig(_XPLATSTR("vault.conf"));


	///////////////////////////////////////////////////////////////////////////
	//// Authenticate with Azure AD
	std::wcout << _XPLATSTR("Authenticating for KeyVault:") << keyVaultName.c_str() << _XPLATSTR("...") << std::endl;
	std::wcout << _XPLATSTR("clientId : ") << clientId.c_str() << _XPLATSTR("..") << std::endl;

	kvc.Authenticate(clientId, username, password, keyVaultName).wait();

	if (verbose) {
		std::wcout << _XPLATSTR("Azure Region: ") << kvc.keyVaultRegion.c_str() << std::endl;
		std::wcout << _XPLATSTR("ResourceUrl : ") << kvc.resourceUrl.c_str() << std::endl;
		std::wcout << _XPLATSTR("LoginUrl    : ") << kvc.loginUrl.c_str() << std::endl;
		std::wcout << _XPLATSTR("Token Type    : ") << kvc.tokenType.c_str() << _XPLATSTR(" Access Token: ") << kvc.accessToken.c_str() << std::endl;
	}

	///////////////////////////////////////////////////////////////////////////
	//// Get Azure KeyVault secret
	if (type == _XPLATSTR("keys"))
	{
		std::wcout << _XPLATSTR("Querying KeyVault Keys ") << secretName.c_str() << _XPLATSTR("...") << std::endl;
		web::json::value jsonKey;
		bool rc = kvc.GetKeyValue(secretName, jsonKey);

		if (rc == false) {
			std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
			return 1;
		}
		//std::wcout << jsonSecret[_XPLATSTR("kid")] << std::endl;
		std::wcout << jsonKey << std::endl;
		//std::wcout << _XPLATSTR("Secret ID   : ") << (jsonSecret[_XPLATSTR("key")])[_XPLATSTR("kid")] << std::endl;
		//std::wcout << _XPLATSTR("Secret Value: ") << (jsonSecret[_XPLATSTR("key")])[_XPLATSTR("kid")] << std::endl;


	}

	else if (type == _XPLATSTR("secrets"))
	{
		std::wcout << _XPLATSTR("Querying KeyVault Secrets ") << secretName.c_str() << _XPLATSTR("...") << std::endl;
		web::json::value jsonSecret;
		bool rc = kvc.GetSecretValue(secretName, jsonSecret);

		if (rc == false) {
			std::wcout << _XPLATSTR("Secret doesn't exist") << std::endl;
			return 1;
		}
		//std::wcout << jsonSecret[_XPLATSTR("kid")] << std::endl;
		std::wcout << jsonSecret.size() << std::endl;
		std::wcout << _XPLATSTR("Secret ID   : ") << jsonSecret[_XPLATSTR("id")] << std::endl;
		std::wcout << _XPLATSTR("Secret Value: ") << jsonSecret[_XPLATSTR("value")]<< std::endl;

	}
	else {

		std::wcout << _XPLATSTR("Resource doesn't exist") << std::endl;

	}
	
	
	return 0;
}


