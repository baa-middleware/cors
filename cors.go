/*
A Default Config for example is below:
	cors.Config{
		Origins:        "*",
		Methods:        "GET, PUT, POST, DELETE",
		RequestHeaders: "Origin, Authorization, Content-Type",
		ExposedHeaders: "",
		MaxAge: 1 * time.Minute,
		Credentials: true,
		ValidateHeaders: false,
	}
*/
package cors

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/baa.v1"
)

const (
	AllowOriginKey      string = "Access-Control-Allow-Origin"
	AllowCredentialsKey        = "Access-Control-Allow-Credentials"
	AllowHeadersKey            = "Access-Control-Allow-Headers"
	AllowMethodsKey            = "Access-Control-Allow-Methods"
	MaxAgeKey                  = "Access-Control-Max-Age"

	OriginKey         = "Origin"
	RequestMethodKey  = "Access-Control-Request-Method"
	RequestHeadersKey = "Access-Control-Request-Headers"
	ExposeHeadersKey  = "Access-Control-Expose-Headers"
)

const (
	optionsMethod = "OPTIONS"
)

/*
Config defines the configuration options available to control how the CORS middleware should function.
*/
type Config struct {
	// Enabling this causes us to compare Request-Method and Request-Headers to confirm they contain a subset of the Allowed Methods and Allowed Headers
	// The spec however allows for the server to always match, and simply return the allowed methods and headers. Either is supported in this middleware.
	ValidateHeaders bool

	// Comma delimited list of origin domains. Wildcard "*" is also allowed, and matches all origins.
	// If the origin does not match an item in the list, then the request is denied.
	Origins string
	origins []string

	// This are the headers that the resource supports, and will accept in the request.
	// Default is "Authorization".
	RequestHeaders string
	requestHeaders []string

	// These are headers that should be accessable by the CORS client, they are in addition to those defined by the spec as "simple response headers"
	//	 Cache-Control
	//	 Content-Language
	//	 Content-Type
	//	 Expires
	//	 Last-Modified
	//	 Pragma
	ExposedHeaders string

	// Comma delimited list of acceptable HTTP methods.
	Methods string
	methods []string

	// The amount of time in seconds that the client should cache the Preflight request
	MaxAge time.Duration
	maxAge string

	// If true, then cookies and Authorization headers are allowed along with the request.  This
	// is passed to the browser, but is not enforced.
	Credentials bool
	credentials string
}

// One time, do the conversion from our the public facing Configuration,
// to all the formats we use internally strings for headers.. slices for looping
func (config *Config) prepare() {
	config.origins = strings.Split(config.Origins, ", ")
	config.methods = strings.Split(config.Methods, ", ")
	config.requestHeaders = strings.Split(config.RequestHeaders, ", ")
	config.maxAge = fmt.Sprintf("%.f", config.MaxAge.Seconds())

	// Generates a boolean of value "true".
	config.credentials = fmt.Sprintf("%t", config.Credentials)

	// Convert to lower-case once as request headers are supposed to be a case-insensitive match
	for idx, header := range config.requestHeaders {
		config.requestHeaders[idx] = strings.ToLower(header)
	}
}

/*
Cors generates a middleware handler function that works inside of a Gin request
to set the correct CORS headers.  It accepts a cors.Options struct for configuration.
*/
func Cors(config Config) baa.HandlerFunc {
	forceOriginMatch := false

	if config.Origins == "" {
		panic("You must set at least a single valid origin. If you don't want CORS, to apply, simply remove the middleware.")
	}

	if config.Origins == "*" {
		forceOriginMatch = true
	}

	config.prepare()

	// Create the Middleware function
	return func(c *baa.Context) {
		// Read the Origin header from the HTTP request
		currentOrigin := c.Req.Header.Get(OriginKey)
		c.Resp.Header().Add("Vary", OriginKey)

		// CORS headers are added whenever the browser request includes an "Origin" header
		// However, if no Origin is supplied, they should never be added.
		// As it normal request
		if currentOrigin == "" {
			c.Next()
			return
		}

		originMatch := false
		if !forceOriginMatch {
			originMatch = matchOrigin(currentOrigin, config)
		}

		//If not * or origin cannot macth , so cors is not alowed
		if ok := forceOriginMatch || originMatch; !ok {
			c.Break()
			return
		}

		valid := false
		preflight := false

		if c.Req.Method == optionsMethod {
			requestMethod := c.Req.Header.Get(RequestMethodKey)
			if requestMethod != "" {
				preflight = true
				valid = handlePreflight(c, config, requestMethod)
			}
		}

		//If this is a preflight request, we are finished, quit.
		//Otherwise this is a normal request and operations should proceed at normal
		if preflight {
			c.Break()
			return
		}
		valid = handleRequest(c, config)
		//If it reaches here, it was not a valid request
		if !valid {
			c.Break()
			return
		}

		if config.Credentials {
			c.Resp.Header().Set(AllowCredentialsKey, config.credentials)
			// Allowed origins cannot be the string "*" cannot be used for a resource that supports credentials.
			c.Resp.Header().Set(AllowOriginKey, currentOrigin)
		} else if forceOriginMatch {
			c.Resp.Header().Set(AllowOriginKey, "*")
		} else {
			c.Resp.Header().Set(AllowOriginKey, currentOrigin)
		}

		c.Next()
	}
}

func handlePreflight(c *baa.Context, config Config, requestMethod string) bool {
	if ok := validateRequestMethod(requestMethod, config); ok == false {
		return false
	}

	if ok := validateRequestHeaders(c.Req.Header.Get(RequestHeadersKey), config); ok == true {
		c.Resp.Header().Set(AllowMethodsKey, config.Methods)
		c.Resp.Header().Set(AllowHeadersKey, config.RequestHeaders)

		if config.maxAge != "0" {
			c.Resp.Header().Set(MaxAgeKey, config.maxAge)
		}

		return true
	}

	return false
}

func handleRequest(c *baa.Context, config Config) bool {
	if config.ExposedHeaders != "" {
		c.Resp.Header().Set(ExposeHeadersKey, config.ExposedHeaders)
	}

	return true
}

// Case-sensitive match of origin header
func matchOrigin(origin string, config Config) bool {
	for _, value := range config.origins {
		if value == origin {
			return true
		}
	}
	return false
}

// Case-sensitive match of request method
func validateRequestMethod(requestMethod string, config Config) bool {
	if !config.ValidateHeaders {
		return true
	}

	if requestMethod != "" {
		for _, value := range config.methods {
			if value == requestMethod {
				return true
			}
		}
	}

	return false
}

// Case-insensitive match of request headers
func validateRequestHeaders(requestHeaders string, config Config) bool {
	if !config.ValidateHeaders {
		return true
	}

	headers := strings.Split(requestHeaders, ",")

	for _, header := range headers {
		match := false
		header = strings.ToLower(strings.Trim(header, " \t\r\n"))

		for _, value := range config.requestHeaders {
			if value == header {
				match = true
				break
			}
		}

		if !match {
			return false
		}
	}

	return true
}
