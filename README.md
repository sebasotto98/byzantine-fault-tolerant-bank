# SEC_project

# Generate key pairs for all entities and Keystore

Since this project will mostly be executed on the same computer, we have created a script to generate all the key pairs more easily. In production this script would not be used, since entities must not have access to each others private keys.
To run the script simply execute:

`./generateKeys.sh`

# Generate key stores to safely keep keys

To safely store keys we shall use a Keystore, from the Keytool package. To generate this, simply run:

`./generateKeyStore.sh`

Which will generate a Keystore for each of the six clients.

To generate a Keystore for a specific client use the following command:
``` 
keytool -genkey -alias clientX -keyalg RSA -keystore ks/clientX_KeystoreFile.jks
```

Where clientX is the username of the client. For simplicity we use the client name for the alias but the user may choose any alias. 
This command will ask for a password, a password confirmation, and multiple other fields, that can be left blank. After this it will be asked to confirm everything, just type "y" and press Enter. 

To export the Public Certificate from the created Keystore use the following command: 
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

The bank configurations are defined in the "bank.txt" file. When you run a bank instance 
you just need to pass as an argument the name of the bank and the instance will retrieve the necessary 
configurations from that file.

`mvn exec:java -Dmainclass=pt.tecnico.Bank -Dexec.args="BANK_NAME"`

### Run client server

When running a client you need to pass the port as an argument. When initiating the 
application retrieves the bank information from the "bank.txt" file. You also need to pass the number of replicas
and how many byzantine faults the system tolerates. 

`mvn exec:java -Dmainclass=pt.tecnico.Client -Dexec.args="CLIENT_PORT NUMBER_OF_REPLICAS NUMBER_OF_FAULTS"`

This will run a functional client server, with all command options to execute.

### Run tests

To run the tests we have provided you can use:

`mvn -Dtest=TEST_CLASS#TEST_NAME test`
