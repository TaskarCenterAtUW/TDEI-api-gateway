// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"tdei-plugin/common"
	"time"
)

var helpHTML = `<html>
<head>
<style type=text/css>
*{
    transition: all 0.6s;
}

html {
    height: 100%;
}

body{
    font-family: 'Lato', sans-serif;
    color: #888;
    margin: 0;
}

#main{
    display: table;
    width: 100%;
    height: 100vh;
    text-align: center;
}

.fof{
	  display: table-cell;
	  vertical-align: middle;
}

.fof h1{
	  font-size: 50px;
	  display: inline-block;
	  padding-right: 12px;
}
</style>
</head>

<body>
<div id="main">
    	<div class="fof">
        		<h1>Unauthorized access</h1>
        <p>For API documentation please refer <a href="apidoc">TDEI API DOC</a>
        </p>
    	</div>
</div>

</body>
</html>`

// pluginName is the plugin name
var pluginName = "tdei-api-gateway"

// HandlerRegisterer is the symbol the plugin loader will try to load. It must implement the Registerer interface
var HandlerRegisterer = registerer(pluginName)

type registerer string

func (r registerer) RegisterHandlers(f func(
	name string,
	handler func(context.Context, map[string]interface{}, http.Handler) (http.Handler, error),
)) {
	f(string(r), r.registerHandlers)
}

func (registerer) RegisterLogger(v interface{}) {
	l, ok := v.(common.Logger)
	if !ok {
		return
	}
	common.TDEILogger = l
	common.TDEILogger.Debug(fmt.Sprintf("[PLUGIN: %s] Logger loaded", HandlerRegisterer))
}

func pathContains(a string, list []string) bool {
	for _, subStringUrl := range list {
		if strings.Contains(a, subStringUrl) {
			return true
		}
	}
	return false
}

type Versions struct {
	Versions []Version `json:"versions"`
}
type Version struct {
	Version       string `json:"version"`
	Documentation string `json:"documentation"`
	Specification string `json:"specification"`
}

func (r registerer) registerHandlers(_ context.Context, extra map[string]interface{}, h http.Handler) (http.Handler, error) {
	// //The config variable contains all the keys you have defined in the configuration
	// if the key doesn't exists or is not a map the plugin returns an error and the default handler
	config, ok := extra[pluginName].(map[string]interface{})
	if !ok {
		return h, errors.New("configuration not found")
	}

	// The plugin will look for this path:
	apiKeyHeader, _ := config["api_key_header"].(string)
	authServer, _ := config["auth_server"].(string)
	passThroughUrlsConfig, _ := config["pass-through-urls"].(string)
	passThroughUrls := strings.Split(passThroughUrlsConfig, ",")
	common.TDEILogger.Debug(fmt.Sprintf("TDEI plugin is now configured with HTTP middleware %s", apiKeyHeader))

	// return the actual handler wrapping or your custom logic so it can be used as a replacement for the default http handler
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		authorizationToken := req.Header.Get("Authorization")
		apiKey := req.Header.Get(apiKeyHeader)
		apiDcoumentationUrl, _ := config["tdei-api-documentation-url"].(string)

		common.TDEILogger.Debug("Entered HTTP handler")
		fmt.Println("Entered HTTP handler")

		//api documentation redirect
		if strings.Contains(req.URL.Path, "/api/docs") == true {
			http.Redirect(w, req, apiDcoumentationUrl, http.StatusPermanentRedirect)
			return
		}

		//Pass through url check
		if pathContains(req.URL.Path, passThroughUrls) {
			h.ServeHTTP(w, req)
			return
		}

		if len(authorizationToken) != 0 {
			accessToken, err := extractBearerToken(authorizationToken)
			if err != nil {
				common.TDEILogger.Error("Invalid access token format", err)
				fmt.Println("Invalid access token format", err)
				http.Error(w, "Invalid access token format", http.StatusUnauthorized)
				return
			}

			common.TDEILogger.Debug("Validating Access Token")
			fmt.Println("Validating Access Token")
			bodyReader := bytes.NewBufferString(accessToken)

			requestURL := fmt.Sprintf("%s%s", authServer, "/api/v1/validateAccessToken")
			newReq, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
			newReq.Header.Set("Content-Type", "text/plain")
			if err != nil {
				common.TDEILogger.Error("Error creating the validateAccessToken request with auth service:", err)
				fmt.Println("Error creating the validateAccessToken request with auth service:", err)
				http.Error(w, "Error creating the validateAccessToken request with auth service", http.StatusInternalServerError)
				return
			}

			client := http.Client{
				Timeout: 30 * time.Second,
			}

			res, err := client.Do(newReq)
			if err != nil {
				common.TDEILogger.Error("Error validating the access token request with auth service", err)
				fmt.Println("Error validating the access token request with auth service", err)
				http.Error(w, "Error validating the access token request with auth service", http.StatusInternalServerError)
				return
			} else if res.StatusCode != http.StatusOK {
				common.TDEILogger.Error("Unauthorized request", res)
				fmt.Println("Unauthorized request", res)
				http.Error(w, "Unauthorized request", http.StatusUnauthorized)
				return
			}

			fmt.Println("Authentication successful")
			executedApi, error := processGatewayAPIRequests(config, w, req)
			if error != nil {
				common.TDEILogger.Error("Error processing the api request", err)
				fmt.Println("Error processing the api request", err)
				http.Error(w, "Error processing the api request", http.StatusInternalServerError)
				return
			} else if !executedApi {
				h.ServeHTTP(w, req)
			}
			return
		} else if len(apiKey) != 0 {
			common.TDEILogger.Debug("Validating API Key")
			fmt.Println("Validating API Key")
			bodyReader := bytes.NewBufferString(apiKey)

			requestURL := fmt.Sprintf("%s%s", authServer, "/api/v1/validateApiKey")
			newReq, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
			newReq.Header.Set("Content-Type", "text/plain")
			if err != nil {
				common.TDEILogger.Error("Error creating the api key request with auth service", err)
				fmt.Println("Error creating the api key request with auth service", err)
				http.Error(w, "Error creating the api key request with auth service", http.StatusInternalServerError)
				return
			}

			client := http.Client{
				Timeout: 30 * time.Second,
			}

			res, err := client.Do(newReq)
			if err != nil {
				common.TDEILogger.Error("Error validating the api key request with auth service", err)
				fmt.Println("Error validating the api key request with auth service", err)
				http.Error(w, "Error validating the api key request with auth service", http.StatusInternalServerError)
				return
			} else if res.StatusCode != http.StatusOK {
				common.TDEILogger.Error("Unauthorized request", res)
				fmt.Println("Unauthorized request", res)
				http.Error(w, "Unauthorized request", http.StatusUnauthorized)
				return
			}

			fmt.Println("Authentication successful")

			executedApi, error := processGatewayAPIRequests(config, w, req)
			if error != nil {
				common.TDEILogger.Error("Error processing the api request", err)
				fmt.Println("Error processing the api request", err)
				http.Error(w, "Error processing the api request", http.StatusInternalServerError)
				return
			} else if !executedApi {
				h.ServeHTTP(w, req)
			}
			return

		} else {
			common.TDEILogger.Debug("Error Authorizing")
			fmt.Println("Error Authorizing")
			common.TDEILogger.Error("[Unauthorized Access] API key / Access token not provided.")
			//http.Error(w, "Unauthorized request", http.StatusUnauthorized)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			htmlContent := strings.Replace(helpHTML, "apidoc", apiDcoumentationUrl, 1)
			fmt.Fprint(w, htmlContent)
			return
		}

	}), nil
}

func processGatewayAPIRequests(config map[string]interface{}, w http.ResponseWriter, req *http.Request) (bool, error) {
	apiDcoumentationUrl, _ := config["tdei-api-documentation-url"].(string)
	apiSpecificationUrl, _ := config["tdei-api-specification-url"].(string)
	// Serve /api from Gateway as it is static implementation now
	if strings.Contains(req.URL.Path, "/api/v1/api") == true {
		w.Header().Set("Content-Type", "application/json")

		version := Version{
			Version:       "1.0",
			Documentation: apiDcoumentationUrl,
			Specification: apiSpecificationUrl,
		}

		versions := Versions{
			Versions: []Version{version},
		}

		// Convert the Versions object to JSON
		jsonData, err := json.Marshal(versions)
		if err != nil {
			fmt.Println("Error:", err)
			return false, err
		}

		// Set the HTTP status code to 200
		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)
		return true, nil
	}
	return false, nil
}

// bearerToken extracts the content from the header, striping the Bearer prefix
func extractBearerToken(rawToken string) (string, error) {
	pieces := strings.SplitN(rawToken, " ", 2)

	if len(pieces) < 2 {
		return "", errors.New("token with incorrect bearer format")
	}

	token := strings.TrimSpace(pieces[1])

	return token, nil
}

func main() {}
