#!/bin/bash

########################################################
# Split a certificate bundle into multiple certificates
# Arguments:
#   location where all generated certificates are put
########################################################
function split_certificates(){
  cert_path="$1"
  mkdir $cert_path
  echo "$ADDITIONAL_CA_CERT_BUNDLE" | awk -v cert_path="$cert_path" 'BEGIN {x=0;} /BEGIN CERT/{x++} { print > cert_path "/custom." x ".crt"  }'
}

#########################################################
# Import multiple certificates to trust store
# Arguments:
#   Path of all certificates to be imported
#########################################################
function import_cert_to_trust_store(){
  cert_path="$1"
  for file in ${cert_path}/*.crt; do
      if [ -f "$file" ]; then
          keytool -importcert -alias "$file"  \
                  -file "$file" \
                  -trustcacerts \
                  -noprompt -storepass changeit \
                  -keystore ${JAVA_HOME}/jre/lib/security/cacerts
      fi
  done
}

if [ -n "$ADDITIONAL_CA_CERT_BUNDLE" ]; then
  cert_path="/tmp/temp_certs"
  split_certificates $cert_path
  import_cert_to_trust_store $cert_path
fi

./analyzer run "$@"
