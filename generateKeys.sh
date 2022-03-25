# First we generate a base key pair, with a self signed certificate, to sign all other keys
openssl genrsa -out server.key
openssl rsa -in server.key -pubout > public.key
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
echo 01 > server.srl

# Generating bank key
openssl genrsa -out bftp_private_key.key
openssl rsa -in bftp_private_key.key -pubout > bftp_public_key.key
openssl req -new -key bftp_private_key.key -out bftb.csr
openssl x509 -req -days 365 -in bftb.csr -CA server.crt -CAkey server.key -out bftb.crt



# Generating key pairs for all clients

for var in client1 client2 client3 client4 client5
do
	openssl genrsa -out $var\_private_key.key
	openssl rsa -in $var\_private_key.key -pubout > $var\_public_key.key
	openssl req -new -key $var\_private_key.key -out $var.csr
	openssl x509 -req -days 365 -in $var.csr -CA server.crt -CAkey server.key -out $var.crt
done
