# SEC_project

## Requirements

### Non-functional

#### Security

1. Authentication 
2. Non-repudiation (sender/receiver)

### Functional

1. Current balance (>=0)
2. History (credit/withdrawal)


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
To run a pre-built exemple, simply pass it as input. We have provided one of these exemples.

`mvn exec:java -Dmainclass=pt.tecnico.Client -Dexec.args="5000 5001" < inputExemple`


