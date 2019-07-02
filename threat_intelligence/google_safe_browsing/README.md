# Google Safe Browsing

Google Safe Browsing exposes two APIs in order to get information from its services. Each API has its own FAME module.

Important: this module cannot send observables to Google Safe Browsing because there is no API available for this.

## Lookup API (v4)

The Lookup API lets your client applications send URLs to the Google Safe Browsing server to check their status. The API is simple and easy to use, as it avoids the complexities of the Update API.

Advantages:

 - Simple URL checks: You send an HTTP POST request with the actual URLs, and the server responds with the state of the URLs (safe or unsafe).

Drawbacks:

 - Privacy: URLs are not hashed, so the server knows which URLs you look up.
 - Response time: Every lookup request is processed by the server. We don't provide guarantees on lookup response time.

If you are not too concerned about the privacy of the queried URLs, and you can tolerate the latency induced by a network request, consider using the Lookup API since it's fairly easy to use.

## Update API (v4)

The Update API lets your client applications download encrypted versions of the Safe Browsing lists for local, client-side checks of URLs. The Update API is designed for clients that require high frequency, low-latency verdicts. Several web browsers and software platforms use this API to protect large sets of users.

Advantages:

 - Privacy: You exchange data with the server infrequently (only after a local hash prefix match) and using hashed URLs, so the server never knows the actual URLs queried by the clients.
 - Response time: You maintain a local database that contains copies of the Safe Browsing lists; they do not need to query the server every time they want to check a URL.

Drawbacks:

 - Implementation: You need to set up a local database and then download, and periodically update, the local copies of the Safe Browsing lists (stored as variable-length SHA256 hashes).
 - Complex URL checks: You need to know how to canonicalize URLs, create suffix/prefix expressions, and compute SHA256 hashes (for comparison with the local copies of the Safe Browsing lists as well as the Safe Browsing lists stored on the server).

If you are concerned about the privacy of the queried URLs or the latency induced by a network request, use the Update API.

## Installation

Once you chose the API you want to use, you have to configure and enable the appropriate module.

Both modules will require you to get a [Google Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started).

### gglsbl-rest

The module using the Update API requires a local instance of [gglsbl-rest](https://github.com/mlsecproject/gglsbl-rest).

This is a tool that will cache URL lookups and make sure the local database is regularily updated (every 30 minutes).

You can easily install it using the [Docker container](https://hub.docker.com/r/mlsecproject/gglsbl-rest/).

Here is an example `docker-compose.yml` file:

    version: '3'

    services:
        gglsbl-rest:
            image: mlsecproject/gglsbl-rest:v1.5.6
            volumes:
                - ./volumes/gglsbl:/home/gglsbl/db:Z
            ports:
                - 127.0.0.1:5000:5000
            environment:
                - GSB_API_KEY=<YOUR_API_KEY>
