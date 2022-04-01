# SEC_project

# Generate key pairs for all entities

Since this project will mostly be executed on the same computer, we have created a script to generate all the key pairs more easily. In production this script would not be used, since entities must not have access to each others private keys.
To run the script simply execute:

`./generateKeys.sh`



# Compile and execute project

We built this project with the help of maven, which allows for faster and simple compiling and execution.

### Compile

To compile simply go to the main folder (`SEC_PROJECT`), and execute the following command:

`mvn clean compile`

### Run bank server

`mvn exec:java -Dmainclass=pt.tecnico.Bank -Dexec.args="5001"`

### Run client server

`mvn exec:java -Dmainclass=pt.tecnico.Client -Dexec.args="5000 5001"`

This will run a functional client server, with all command options to execute.

##### Runing with demo application

To run a pre-built exemple, simply pass it as input. We have provided one of these exemples.


`mvn exec:java -Dmainclass=pt.tecnico.Client -Dexec.args="5000 5001" < inputExemple`


This inputExemple is an exemple of a possible usage, with all commands being executed.

