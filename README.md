# SEC_project

# Generate key pairs for all entities and keyStore

Since this project will mostly be executed on the same computer, we have created a script to generate all the key pairs more easily. In production this script would not be used, since entities must not have access to each others private keys.
To run the script simply execute:

`./generateKeys.sh`


# Generate Key Stores to safely keep keys

To safely store keys we shall use a key store, from the key tool package. To generate this, simply run:

`./generateKeyStore.sh`

Which will generate a key store for each of the six clients.

To generate a keyStore for a specific client use the following command:
``` 
keytool -genkey -alias clientX -keyalg RSA -keystore ks/clientX_KeystoreFile.jks
```

Where clientX is the username of the client. For simplicity we use the client name for the alias but the user may choose any alias. 
This command will ask for a password, a password confirmation, and multiple other fields, that can be left blank. After this it will be asked to confirm everything, just type "y" and press Enter. 


To export the Public Certificate from the created keyStore use the following command: 
``` 
keytool -export -alias clientX -file ks/clientX_Certificate.cer -keystore ks/clientX_KeystoreFile.jks
```
Where the first clientX is the alias chosen previously and the second one is the client's name.

# Compile and execute project

We built this project with the help of maven, which allows for faster and simple compiling and execution.

### Compile

To compile simply go to the main folder (`SEC_PROJECT`), and execute the following command:

`mvn clean compile`

### Run bank server

`mvn exec:java -Dmainclass=pt.tecnico.Bank -Dexec.args="5001 BANK_NAME"`

### Run client server

`mvn exec:java -Dmainclass=pt.tecnico.Client -Dexec.args="5000 5001 BANK_NAME"`

This will run a functional client server, with all command options to execute.

##### Runing with demo application

To run a pre-built exemple, simply pass it as input. We have provided one of these exemples.


`mvn exec:java -Dmainclass=pt.tecnico.Client -Dexec.args="5000 5001 BANK_NAME" < inputExemple`


This inputExemple is an exemple of a possible usage, with all commands being executed.


### Run tests

To run the tests we have provided, it is enough to run

`mvn test`

