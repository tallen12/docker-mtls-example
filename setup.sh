uv run generate-root-ca --subject.common-name 'Intermediate CA'
uv run generate-intermediate-ca --subject.common-name 'Root CA'
uv run cert-manager generate-csr --domain localhost --subject.alternate-names localhost --subject.common-name 'localhost service'
uv run cert-manager generate-csr --domain curl --subject.alternate-names curl.local --subject.common-name 'curl client'