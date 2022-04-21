# First we generate a base key pair, with a self signed certificate, to sign all other keys
openssl genrsa -out keys/server.key
openssl rsa -in keys/server.key -pubout > keys/public.key
openssl req -new -key keys/server.key -out keys/server.csr
openssl x509 -req -days 365 -in keys/server.csr -signkey keys/server.key -out keys/server.crt
echo 01 > keys/server.srl

# Generating key pairs for bank instances
for var in bftb1 bftb2 bftb3 bftb4
do
	openssl genrsa -out keys/$var\_private_key.key
	openssl rsa -in keys/$var\_private_key.key -pubout > keys/$var\_public_key.key
	openssl req -new -key keys/$var\_private_key.key -out keys/$var.csr
	openssl x509 -req -days 365 -in keys/$var.csr -CA keys/server.crt -CAkey keys/server.key -out keys/$var.crt
	openssl rsa -in keys/$var\_private_key.key -text > keys/$var\_private_key.pem
	openssl pkcs8 -topk8 -inform PEM -outform DER -in keys/$var\_private_key.pem -out keys/$var\_private_key.der -nocrypt
	openssl rsa -in keys/$var\_private_key.pem -pubout -outform DER -out keys/$var\_public_key.der
done

# Generating key pairs for all clients
for var in client1 client2 client3 client4 client5 client6
do
	openssl genrsa -out keys/$var\_private_key.key
	openssl rsa -in keys/$var\_private_key.key -pubout > keys/$var\_public_key.key
	openssl req -new -key keys/$var\_private_key.key -out keys/$var.csr
	openssl x509 -req -days 365 -in keys/$var.csr -CA keys/server.crt -CAkey keys/server.key -out keys/$var.crt
	openssl rsa -in keys/$var\_private_key.key -text > keys/$var\_private_key.pem
	openssl pkcs8 -topk8 -inform PEM -outform DER -in keys/$var\_private_key.pem -out keys/$var\_private_key.der -nocrypt
	openssl rsa -in keys/$var\_private_key.pem -pubout -outform DER -out keys/$var\_public_key.der
done
