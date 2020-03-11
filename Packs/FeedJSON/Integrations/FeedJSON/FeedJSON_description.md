
Fetch indicators from a JSON feed. The integration allows a great amount of user configuration to support different types of JSON feeds.

* **URL** - URL of the feed.
* **Indicator Type** - The type of indicators in the feed.
* **Username + Password** - Credentials to access feeds that require basic authentication. 
These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field and the header value in the **Password** field.
* **JMESPath Extractor** - JMESPath expression for extracting the indicators from. You can check the expression in 
the [JMESPath site](http://jmespath.org/) to verify this expression will return the following array of objects.
* **JSON Indicator Attribute** - JSON attribute whose value is the indicator. Default is 'indicator'.
* **Field Names** - The names to apply the fields in the JSON feed.

## Step by step configuration
As an example, we'll be looking at the IP ranges from Amazon AWS. This feed will ingest indicators of type CIDR. These are the feed instance configuration parameters for our example.

**URL**: https://ip-ranges.amazonaws.com/ip-ranges.json

**Indicator Type** - CIDR

**Credentials** - This feed does not require authentication.

From a quick look at the feed in the web browser, we are going to configure the rest of the parameters:

**JMESPath Extractor** - prefixes[?service=='AMAZON']

**JSON Indicator Attribute** - ip_prefix

**Field Names** - We have 2 fields in this feed - `region,service`. The integration ignores these headers and we have to configure the field names for each indicator.
So we will configure these field names: `region,service`, so that the indicator will be created with these fields.

Now we have successfully configured an instance for the IP ranges from Amazon AWS, once we enable `Fetches indicators` the instance will start pulling indicators.

By clicking `Mapping` in the integration instance, we can map the field names we previously configured to actual indicator fields (except `value` which is the indicator value).
We can use `Set up a new classification rule` using actual data from the feed.
