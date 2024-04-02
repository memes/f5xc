# (Re-)Generate certificate files for testing f5xc
#
# Dependencies:
#  1. cfssl installed and on path
#     use `go get github.com/cloudflare/cfssl/cmd/...` to install
#  2. GNU Make 4.x (or a port with `file` support)
#
# Rules:
#   1. CA cert and key is special; recreation will break any existing cert-key pairs that are in
#      use.
#     i.  CA is automatically created if missing and a host cert is requested (see below).
#     ii. CA cert can be manually created by:-
#         $ make ca.pem
#         which will generate the files ca.pem and ca-key.pem.
#   2. Default goal creates certs for test-user
#        * test-user.p12
#        * test-user.pem
#        * test-user.key.pem
#   3. Other client certificates can be created by executing make _name_.p12,
#      where _name_ will be the CN

PKCS_PASSPHRASE := insecure_passphrase
CA_CONFIG := ca-config.json
CA_CSR := ca-csr.json
CA_CERT := ca.pem

# When on Windows, force shell to be cmd instead of bash or any other shell
ifeq ($(OS),Windows_NT)
SHELL=cmd.exe
endif

define ca-config-content
{
  "signing": {
    "default": {
      "expiry": "240h"
    },
    "profiles": {
      "client": {
        "usages": [
          "signing",
          "key encipherment",
          "client auth"
        ],
        "expiry": "240h"
      }
    }
  }
}
endef

define ca-csr-content
{
  "CN": "F5XC Testing CA",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Laguna Niguel",
      "O": "Matthew Emes",
      "OU": "F5XC",
      "ST": "California"
    }
  ]
}
endef

define client-csr-content
{
  "CN": "!!name!!",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Laguna Niguel",
      "O": "Matthew Emes",
      "OU": "F5XC",
      "ST": "California"
    }
  ]
}
endef

# Default target generates fake certificate for test-user
.PHONY: default
default: test-user.p12

# Delete all certs, keys and csr's, except for those used by the CA
.PHONY: clean
clean:
	-rm $(filter-out $(CA_CERT) $(subst ca,ca-key,$(CA_CERT)) $(CA_CSR) $(CA_CONFIG),$(wildcard *p12 *pem *csr *json))

# Clean-up the CA files too
.PHONY: realclean
realclean: clean
	-rm $(CA_CERT) $(subst ca,ca-key,$(CA_CERT)) $(CA_CSR) $(CA_CONFIG)

# Create a CA cert from CSR file
.PRECIOUS: $(CA_CERT)
$(CA_CERT): $(CA_CSR)
	cfssl gencert -initca $< | cfssljson -bare $(subst .pem,,$@)

# Recreate CA CSR as needed
$(CA_CSR):
	$(file >$@,$(ca-csr-content))

# Recreate CA config as needed
$(CA_CONFIG):
	$(file >$@,$(ca-config-content))

# Create a CSR json file for a client cert
%-csr.json:
	$(file >$@, $(subst !!name!!,$*,$(client-csr-content)))

# General rule to generate a client cert
.PRECIOUS: %.pem
%.pem: %-csr.json $(CA_CERT) $(CA_CONFIG)
	cfssl gencert -ca $(CA_CERT) -ca-key $(subst ca,ca-key,$(CA_CERT)) -config $(CA_CONFIG) -profile client $< | \
	cfssljson -bare $*

# General rule to generate a PKCS#12 package
.PRECIOUS: %.p12
%.p12: %.pem $(CA_CERT)
	openssl pkcs12 -in $< -inkey $(subst .pem,-key.pem,$<) \
		-export -out $@ -passout 'pass:$(PKCS_PASSPHRASE)'
