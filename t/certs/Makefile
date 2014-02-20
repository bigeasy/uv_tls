all: agent-cert.pem ca-cert.pem


#
# Create Certificate Authority: ca
# ('password' is used for the CA password.)
#
ca-cert.pem: ca.cnf
	openssl req -new -x509 -days 9999 -config ca.cnf -keyout ca-key.pem -out ca-cert.pem

#
# agent is signed by ca.
#
agent-key.pem:
	openssl genrsa -out agent-key.pem 1024

agent-csr.pem: agent.cnf agent-key.pem
	openssl req -new -config agent.cnf -key agent-key.pem -out agent-csr.pem

agent-cert.pem: agent-csr.pem ca-cert.pem ca-key.pem
	openssl x509 -req \
		-extensions v3_req \
		-days 9999 \
		-passin "pass:password" \
		-in agent-csr.pem \
		-CA ca-cert.pem \
		-CAkey ca-key.pem \
		-CAcreateserial \
		-extfile agent.cnf \
		-out agent-cert.pem

agent-verify: agent-cert.pem ca-cert.pem
	openssl verify -CAfile ca-cert.pem agent-cert.pem

clean:
	rm -f *.pem *.srl

.PHONY: all clean test agent-verify
