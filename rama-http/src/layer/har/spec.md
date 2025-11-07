## HAR 1.2 Spec

This document is intended to describe a **HTTP Archive 1.2** (frozen) format that can be used by HTTP monitoring tools to export collected data.

This markdown document is a cleaned up export of the original source found at time of export (2025-09-03) at:
<http://www.softwareishard.com/blog/har-12-spec/>.

### HTTP Archive v1.2

One of the goals of the HTTP Archive format is to be flexible enough so, it can be adopted across projects and various tools. This should allow effective processing and analyzing data coming from various sources. Notice that resulting HAR file can contain privacy & security sensitive data and user-agents should find some way to notify the user of this fact before they transfer the file to anyone else.

- The format described below is based on HTTP Archive 1.1.
- The format is based on [JSON](http://www.ietf.org/rfc/rfc4627.txt).
- Please follow-up in the [newsgroup](http://groups.google.com/group/http-archive-specification?hl=en).
- An online [HAR viewer](http://www.softwareishard.com/blog/har-viewer/) is available.
- Report any problems in the [issue list](https://code.google.com/archive/p/http-archive-specification/issues).
- See [list of tools](http://www.softwareishard.com/blog/har-adopters/) supporting HAR.

### HAR Data Structure

HAR files are required to be saved in UTF-8 encoding, other encodings are forbidden. The spec requires that tools support and ignore a BOM and allow them to emit one if they like.

Summary of HAR object types:

- [log](#log)
- [creator](#creator)
- [browser](#browser)
- [pages](#pages)
- [pageTimings](#pageTimings)
- [entries](#entries)
- [request](#request)
- [response](#response)
- [cookies](#cookies)
- [headers](#headers)
- [queryString](#queryString)
- [postData](#postData)
- [params](#params)
- [content](#content)
- [cache](#cache)
- [timings](#timings)

## log

This object represents the root of exported data.

{
  "log": {
    "version" : "1.2",
    "creator" : {},
    "browser" : {},
    "pages": [],
    "entries": [],
    "comment": ""
  }
}

- _version \[string\]_ - Version number of the format. If empty, string "1.1" is assumed by default.
- _creator \[object\]_ - Name and version info of the log creator application.
- _browser \[object, optional\]_ - Name and version info of used browser.
- _pages \[array, optional\]_ - List of all exported (tracked) pages. Leave out this field if the application does not support grouping by pages.
- _entries \[array\]_ - List of all exported (tracked) requests.
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

There is one [page](#pages) object for every exported web page and one [entry](#entries)
object for every HTTP request. In case when an HTTP trace tool isn't able to
group requests by a page, the [pages](#pages) object is empty and individual requests doesn't have a parent page.

## creator

_Creator_ and _browser_ objects share the same structure.

```js
"creator": {
  "name": "Firebug",
  "version": "1.6",
  "comment": ""
}
```

## browser

```js
"browser": {
  "name": "Firefox",
  "version": "3.6",
  "comment": ""
}
```

- _name \[string\]_ - Name of the application/browser used to export the log.
- _version \[string\]_ - Version of the application/browser used to export the log.
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

## pages

This object represents list of exported pages.

```js
"pages": [
  {
    "startedDateTime": "2009-04-16T12:07:25.123+01:00",
    "id": "page_0",
    "title": "Test Page",
    "pageTimings": {...},
    "comment": ""
  }
]
```

- _startedDateTime \[string\]_ - Date and time stamp for the beginning of the page load ([ISO 8601](http://www.w3.org/TR/NOTE-datetime) - YYYY-MM-DDThh:mm:ss.sTZD, e.g. 2009-07-24T19:20:30.45+01:00).
- _id \[string\]_ - Unique identifier of a page within the [log](#log). Entries use it to refer the parent page.
- _title \[string\]_ - Page title.
- _pageTimings\[object\]_ - Detailed timing info about page load.
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

## pageTimings

This object describes timings for various events (states) fired during the page load.
All times are specified in milliseconds. If a time info is not available appropriate field is set to -1.

```js
"pageTimings": {
  "onContentLoad": 1720,
  "onLoad": 2500,
  "comment": ""
}
```

- _onContentLoad \[number, optional\]_ - Content of the page loaded.
  Number of milliseconds since page load started (page.startedDateTime).
  Use -1 if the timing does not apply to the current request.
- _onLoad \[number,optional\]_ - Page is loaded (onLoad event fired).
  Number of milliseconds since page load started (page.startedDateTime).
  Use -1 if the timing does not apply to the current request.
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

Depeding on the browser, _onContentLoad_ property represents
**DOMContentLoad** event or **document.readyState == interactive**.

## entries

This object represents an array with all exported HTTP requests.
Sorting entries by _startedDateTime_ (starting from the oldest)
is preferred way how to export data since it can make importing faster.
However the reader application should always make sure the array is sorted (if required for the import).

```js
"entries": [
  {
    "pageref": "page_0",
    "startedDateTime": "2009-04-16T12:07:23.596Z",
    "time": 50,
    "request": {...},
    "response": {...},
    "cache": {...},
    "timings": {},
    "serverIPAddress": "10.0.0.1",
    "connection": "52492",
    "comment": ""
  }
]
```

- _pageref \[string, unique, optional\]_ - Reference to the parent page. Leave out this field if the application does not support grouping by pages.
- _startedDateTime \[string\]_ - Date and time stamp of the request start ([ISO 8601](http://www.w3.org/TR/NOTE-datetime) - YYYY-MM-DDThh:mm:ss.sTZD).
- _time \[number\]_ - Total elapsed time of the request in milliseconds. This is the sum of all timings available in the timings object (i.e. not including -1 values) .
- _request \[object\]_ - Detailed info about the request.
- _response \[object\]_ - Detailed info about the response.
- _cache \[object\]_ - Info about cache usage.
- _timings \[object\]_ - Detailed timing info about request/response round trip.
- _serverIPAddress \[string, optional\]_ (new in 1.2) - IP address of the server that was connected (result of DNS resolution).
- _connection \[string, optional\]_ (new in 1.2) - Unique ID of the parent TCP/IP connection, can be the client or server port number. Note that a port number doesn't have to be unique identifier in cases where the port is shared for more connections. If the port isn't available for the application, any other unique connection ID can be used instead (e.g. connection index). Leave out this field if the application doesn't support this info.
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

## request

This object contains detailed info about performed request.

```js
"request": {
  "method": "GET",
  "url": "http://www.example.com/path/?param=value",
  "httpVersion": "HTTP/1.1",
  "cookies": [],
  "headers": [],
  "queryString" : [],
  "postData" : {},
  "headersSize" : 150,
  "bodySize" : 0,
  "comment" : ""
}
```

- _method \[string\]_ - Request method (GET, POST, ...).
- _url \[string\]_ - Absolute URL of the request (fragments are not included).
- _httpVersion \[string\]_ - Request HTTP Version.
- _cookies \[array\]_ - List of cookie objects.
- _headers \[array\]_ - List of header objects.
- _queryString \[array\]_ - List of query parameter objects.
- _postData \[object, optional\]_ - Posted data info.
- _headersSize \[number\]_ - Total number of bytes from the start of the HTTP request message until (and including) the double CRLF before the body. Set to -1 if the info is not available.
- _bodySize \[number\]_ - Size of the request body (POST data payload) in bytes. Set to -1 if the info is not available.
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

The total request size sent can be computed as follows (if both values are available):

```js
var totalSize = entry.request.headersSize + entry.request.bodySize;
```

## response

This object contains detailed info about the response.

```js
"response": {
  "status": 200,
  "statusText": "OK",
  "httpVersion": "HTTP/1.1",
  "cookies": [],
  "headers": [],
  "content": {},
  "redirectURL": "",
  "headersSize" : 160,
  "bodySize" : 850,
  "comment" : ""
}
```

- _status \[number\]_ - Response status.
- _statusText \[string\]_ - Response status description.
- _httpVersion \[string\]_ - Response HTTP Version.
- _cookies \[array\]_ - List of cookie objects.
- _headers \[array\]_ - List of header objects.
- _content \[object\]_ - Details about the response body.
- _redirectURL \[string\]_ - Redirection target URL from the Location response header.
- _headersSize \[number\]\*_ - Total number of bytes from the start of the HTTP response message until (and including) the double CRLF before the body. Set to -1 if the info is not available.
- _bodySize \[number\]_ - Size of the received response body in bytes. Set to zero in case of responses coming from the cache (304). Set to -1 if the info is not available.
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

_\*headersSize_ - The size of received response-headers is computed only from headers that are really received from the server. Additional headers appended by the browser are not included in this number, but they appear in the list of header objects.

The total response size received can be computed as follows (if both values are available):

```js
var totalSize = entry.response.headersSize + entry.response.bodySize;
```

## cookies

This object contains list of all cookies (used in [request](#request) and [response](#response) objects).

```js
"cookies": [
  {
    "name": "TestCookie",
    "value": "Cookie Value",
    "path": "/",
    "domain": "www.janodvarko.cz",
    "expires": "2009-07-24T19:20:30.123+02:00",
    "httpOnly": false,
    "secure": false,
    "comment": ""
  }
]
```

- _name \[string\]_ - The name of the cookie.
- _value \[string\]_ - The cookie value.
- _path \[string, optional\]_ - The path pertaining to the cookie.
- _domain \[string, optional\]_ - The host of the cookie.
- _expires \[string, optional\]_ - Cookie expiration time. ([ISO 8601](http://www.w3.org/TR/NOTE-datetime) - YYYY-MM-DDThh:mm:ss.sTZD, e.g. 2009-07-24T19:20:30.123+02:00).
- _httpOnly \[boolean, optional\]_ - Set to true if the cookie is HTTP only, false otherwise.
- _secure \[boolean, optional\]_ (new in 1.2) - True if the cookie was transmitted over ssl, false otherwise.
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

## headers

This object contains list of all headers (used in [request](#request) and [response](#response) objects).

```js
"headers": [
  {
    "name": "Accept-Encoding",
    "value": "gzip,deflate",
    "comment": ""
  },
  {
    "name": "Accept-Language",
    "value": "en-us,en;q=0.5",
    "comment": ""
  }
]
```

## queryString

This object contains list of all parameters & values parsed from a query string, if any (embedded in [request](#request) object).

```js
"queryString": [
  {
    "name": "param1",
    "value": "value1",
    "comment": ""
  },
  {
    "name": "param1",
    "value": "value1",
    "comment": ""
  }
]
```

HAR format expects NVP (name-value pairs) formatting of the query string.

postData

This object describes posted data, if any (embedded in [request](#request) object).

```js
"postData": {
  "mimeType": "multipart/form-data",
  "params": [],
  "text" : "plain posted data",
  "comment": ""
}
```

- _mimeType \[string\]_ - Mime type of posted data.
- _params \[array\]_ - List of posted parameters (in case of URL encoded parameters).
- _text \[string\]_ - Plain text posted data
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

Note that _text_ and _params_ fields are mutually exclusive.

## params

List of posted parameters, if any (embedded in [postData](#postData) object).

```js
"params": [
  {
  "name": "paramName",
  "value": "paramValue",
  "fileName": "example.pdf",
  "contentType": "application/pdf",
  "comment": ""
  }
]
````

- _name \[string\]_ - name of a posted parameter.
- _value \[string, optional\]_ - value of a posted parameter or content of a posted file.
- _fileName \[string, optional\]_ - name of a posted file.
- _contentType \[string, optional\]_ - content type of a posted file.
- _comment \[string, optional\] (new in 1.2)_ - A comment provided by the user or the application.

## content

This object describes details about response content (embedded in [response](#response) object).

```js
"content": {
  "size": 33,
  "compression": 0,
  "mimeType": "text/html; charset=utf-8",
  "text": "\\n",
  "comment": ""
}
```

- _size \[number\]_ - Length of the returned content in bytes.
  Should be equal to response.bodySize if there is no compression
  and bigger when the content has been compressed.
- _compression \[number, optional\]_ - Number of bytes saved.
  Leave out this field if the information is not available.
- _mimeType \[string\]_ - MIME type of the response text
  (value of the Content-Type response header).
  The charset attribute of the MIME type is included (if available).
- _text \[string, optional\]_ - Response body sent from the server or loaded from the browser cache.
  This field is populated with textual content only.
  The text field is either HTTP decoded text or a encoded (e.g. "base64")
  representation of the response body. Leave out this field if the information is not available.
- _encoding \[string, optional\]_ (new in 1.2) - Encoding used for response text field e.g "base64".
  Leave out this field if the text field is HTTP decoded (decompressed & unchunked),
  than trans-coded from its original character set into UTF-8.
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

Before setting the text field, the HTTP response is decoded
(decompressed & unchunked), than trans-coded from its original character set into UTF-8.
Additionally, it can be encoded using e.g. base64. Ideally,
the application should be able to unencode a base64 blob and get
a byte-for-byte identical resource to what the browser operated on.

_Encoding field is useful for including binary responses (e.g. images) into the HAR file._

Here is another example with encoded response. The original response is:

```txt
<html\><head\></head\><body/></html\>\\n
```

```js
"content": {
    "size": 33,
    "compression": 0,
    "mimeType": "text/html; charset=utf-8",
    "text": "PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5Lz48L2h0bWw+XG4=",
    "encoding": "base64",
    "comment": ""
}
```

## cache

This objects contains info about a request coming from browser cache.

```js
"cache": {
    "beforeRequest": {},
    "afterRequest": {},
    "comment": ""
}
```

- _beforeRequest \[object, optional\]_ -
  State of a cache entry before the request.
  Leave out this field if the information is not available.
- _afterRequest \[object, optional\]_ -
  State of a cache entry after the request.
  Leave out this field if the information is not available.
- _comment \[string, optional\]_ (new in 1.2) -
  A comment provided by the user or the application.

This is how the object should look like if no cache information are available
(or you can just leave out the entire field).

```js
"cache": {}
```

This is how the object should look like if the the info about
the cache entry before request is not available and there is no cache entry after the request.

```js
"cache": {
    "afterRequest": null
}
```

This is how the object should look like if there in no cache entry before nor after the request.

```js
"cache": {
    "beforeRequest": null,
    "afterRequest": null
}
```

This is how the object should look like to indicate that the entry
was not in the cache but was store after the content was downloaded by the request.

```js
"cache": {
    "beforeRequest": null,
    "afterRequest": {
        "expires": "2009-04-16T15:50:36",
        "lastAccess": "2009-16-02T15:50:34",
        "eTag": "",
        "hitCount": 0,
        "comment": ""
    }
}
```

Both _beforeRequest_ and _afterRequest_ object share the following structure.

```js
"beforeRequest": {
    "expires": "2009-04-16T15:50:36",
    "lastAccess": "2009-16-02T15:50:34",
    "eTag": "",
    "hitCount": 0,
    "comment": ""
}
```

- _expires \[string, optional\]_ - Expiration time of the cache entry.
- _lastAccess \[string\]_ - The last time the cache entry was opened.
- _eTag \[string\]_ - Etag
- _hitCount \[number\]_ - The number of times the cache entry has been opened.
- _comment \[string, optional\]_ (new in 1.2) - A comment provided by the user or the application.

## timings

This object describes various phases within request-response round trip. All times are specified in milliseconds.

```js
"timings": {
    "blocked": 0,
    "dns": -1,
    "connect": 15,
    "send": 20,
    "wait": 38,
    "receive": 12,
    "ssl": -1,
    "comment": ""
}
```

- blocked \[number, optional\] -
  Time spent in a queue waiting for a network connection.
  Use -1 if the timing does not apply to the current request.
- dns \[number, optional\] - DNS resolution time.
  The time required to resolve a host name.
  Use -1 if the timing does not apply to the current request.
- connect \[number, optional\] - Time required to create TCP connection.
  Use -1 if the timing does not apply to the current request.
- send \[number\] - Time required to send HTTP request to the server.
- wait \[number\] - Waiting for a response from the server.
- receive \[number\] - Time required to read entire response from the server (or cache).
- ssl \[number, optional\] (new in 1.2) - Time required for SSL/TLS negotiation.
  If this field is defined then the time is also included in the connect field
  (to ensure backward compatibility with HAR 1.1).
  Use -1 if the timing does not apply to the current request.
- comment \[string, optional\] (new in 1.2) - A comment provided by the user or the application.

The _send_, _wait_ and _receive_ timings are not optional and must have non-negative values.

An exporting tool can omit the _blocked_, _dns_, _connect_ and _ssl_, timings on every request if it is unable to provide them. Tools that can provide these timings can set their values to -1 if they don’t apply. For example, _connect_ would be -1 for requests which re-use an existing connection.

The _time_ value for the request must be equal to the sum of the timings supplied in this section (excluding any -1 values).

Following must be true in case there are no -1 values (_entry_ is an object in _log.entries_) :

```js
entry.time ==
  entry.timings.blocked +
    entry.timings.dns +
    entry.timings.connect +
    entry.timings.send +
    entry.timings.wait +
    entry.timings.receive;
```

### Custom Fields

The specification allows adding new custom fields into the output format. Following rules must be applied:

- Custom fields and elements MUST start with an underscore
  (spec fields should never start with an underscore.
- Parsers MUST ignore all custom fields and elements if the file
  was not written by the same tool loading the file.
- Parsers MUST ignore all non-custom fields that they don't know how
  to parse because the minor version number is greater than the maximum minor version for which they were written.
- Parsers can reject files that contain non-custom fields that they
  know were not present in a specific version of the spec.

### Versioning Scheme

The spec number has following syntax:

```txt
<major-version-number>.<minor-version-number>
```

Where the major version indicates overall backwards compatibility and the minor version indicates incremental changes. So, any backwardly compatible changes to the spec will result in an increase of the minor version. If an existing fields had to be broken then major version would increase (e.g. 2.0).

Examples:

```txt
1.2 -> 1.3
1.111 -> 1.112 (in case of 111 more changes)
1.5 -> 2.0     (2.0 is not compatible with 1.5)
```

So following construct can be used to detect incompatible version if a tool supports HAR since 1.1.

```js
if (majorVersion != 1 || minorVersion < 1) {
  throw "Incompatible version";
}
```

In this example a tool throws an exception if the version is e.g.: 0.8, 0.9, 1.0, but works with 1.1, 1.2, 1.112 etc. Version 2.x would be rejected.

### HAR With Padding

Support for [JSONP](http://en.wikipedia.org/wiki/JSON#JSONP) (JSON with padding) is not part of the core HAR spec. However, it represents very good feature for consuming HAR files online.

In order to server HAR files online the URL might include a callback URL parameter that should wrap HAR into a callback to a function (you might want to use \*.harp extension for HAR files with padding).

http://www.example.com/givememyhar.php?callback=onInputData

Response for the URL above would be:

onInputData({
"log": { ... }
});

- _inputUrl_ specifies an URL of the target HAR file (doesn't have to come from the same domain)
- _callback_ species name of the function the HAR is wrapped in.

### HAR Compression

Compression of the HAR file is not part of the core HAR spec. However, in order to store HAR files more efficiently, it is recommended that you compress HAR files on disk (you might want to use _\*.zhar_ extension for zipped HAR files).

Anyway, an application supporting HAR, is not required to support compressed HAR files. If the application doesn't support compressed HAR then it's the responsibility of the user to decompress before passing the HAR file into it.

[HTTP Compression](http://en.wikipedia.org/wiki/HTTP_compression) is one of the best practices how to speed up web applications and it's also recommended for HAR files.
