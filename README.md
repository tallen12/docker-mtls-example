A simple test of setting up mutual TLS with nginx and eventually python fastapi.

## Quickstart
Set up certs by using the provided python script through uv.

Generate a root CA:

`uv run generate-root-ca --subject.common-name 'Root CA'`

Generate an intermediate CA:

`uv run generate-intermediate-ca --subject.common-name 'Intermediate CA'`

Create a Certificate Signing Request for a client cert with a given domain:

`uv run cert-manager generate-csr --domain localhost --subject.alternate-names localhost --subject.common-name 'localhost service'`

And a second Certificate Signing Request for a client cert to use with curl:

`uv run cert-manager generate-csr --domain curl --subject.alternate-names curl --subject.common-name 'curl client'`

Process sign the generated CSRs and produce certs from the given CA:

`uv run cert-manager process-csrs --ca-path ./certs/ca/intermediate-ca.cert --ca-key-path ./certs/ca/intermediate-private-key.key`

Create a CA bundle for the root and intermediate certs:

`uv run cert-manager create-ca-bundle`

After setting up certs start up docker-compose:

`docker-compose up -d`

Then try to make a request with curl (make sure to provide the CA bundle so ssl handshake succeeds):

`curl -v https://localhost:8443 --cacert ./certs/ca-bundle.pem`

This should fail with a client cert error, try again but provide the client cert we generated for curl:

`curl -v https://localhost:8443 --cacert ./certs/ca-bundle.pem --cert ./certs/curl.cert --key ./certs/curl.key`