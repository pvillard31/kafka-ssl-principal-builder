# Kafka SSL - Principal Builder

Please have a look [here](https://github.com/pvillard31/kafka-ssl-principal-builder/tree/master).

The below is valid for Kafka 1.x+.

### Instructions

Build the code:
````
$ git clone https://github.com/pvillard31/kafka-ssl-principal-builder.git
$ cd kafka-ssl-principal-builder
$ mvn clean install
````

Copy the jar ``target/kafka-ssl-principal-builder-0.0.1-SNAPSHOT.jar`` on your broker nodes, in the lib directory ``/usr/hdf/current/kafka-broker/libs/``

Set the following properties in Ambari (assuming SSL properties have already been set):
````properties
principal.builder.class=kafka.security.auth.CustomPrincipalBuilder_1
kafka.security.identity.mapping.pattern.dn=^.*[Cc][Nn]=([a-zA-Z0-9. ]*).*$
kafka.security.identity.mapping.value.dn=$1
ssl.client.auth=required
````

### Explanations

Please read the [README of the master branch](https://github.com/pvillard31/kafka-ssl-principal-builder/tree/master).
