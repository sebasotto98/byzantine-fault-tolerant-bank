# Delete existing key stores
rm ks/*.cer
rm ks/*.jks

# for client 1
keytool -genkey -alias client1 -keyalg RSA -keystore ks/client1_KeystoreFile.jks
keytool -export -alias client1 -file ks/client1_Certificate.cer -keystore ks/client1_KeystoreFile.jks

# for client 2
keytool -genkey -alias client2 -keyalg RSA -keystore ks/client2_KeystoreFile.jks
keytool -export -alias client2 -file ks/client2_Certificate.cer -keystore ks/client2_KeystoreFile.jks

# for client 3
keytool -genkey -alias client3 -keyalg RSA -keystore ks/client3_KeystoreFile.jks
keytool -export -alias client3 -file ks/client3_Certificate.cer -keystore ks/client3_KeystoreFile.jks

# for client 4
keytool -genkey -alias client4 -keyalg RSA -keystore ks/client4_KeystoreFile.jks
keytool -export -alias client4 -file ks/client4_Certificate.cer -keystore ks/client4_KeystoreFile.jks

# for client 5
keytool -genkey -alias client5 -keyalg RSA -keystore ks/client5_KeystoreFile.jks
keytool -export -alias client5 -file ks/client5_Certificate.cer -keystore ks/client5_KeystoreFile.jks

# for client 6
keytool -genkey -alias client6 -keyalg RSA -keystore ks/client6_KeystoreFile.jks
keytool -export -alias client6 -file ks/client6_Certificate.cer -keystore ks/client6_KeystoreFile.jks