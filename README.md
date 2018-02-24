# Kafka SSL - Principal Builder

For a Kafka 1.x version, have a look on [this branch](https://github.com/pvillard31/kafka-ssl-principal-builder/tree/kafka_1.x).

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
principal.builder.class=kafka.security.auth.CustomPrincipalBuilder
kafka.security.identity.mapping.pattern.dn=^.*[Cc][Nn]=([a-zA-Z0-9. ]*).*$
kafka.security.identity.mapping.value.dn=$1
ssl.client.auth=required
````

If you don't want to use the CN of the subject as the username, see below explanations.

### Explanations

*Note:* with Kafka 1.0+, the implementation changed a bit. Even though this code remains valid, there is a new interface that is much easier to implement (https://cwiki.apache.org/confluence/display/KAFKA/KIP-189%3A+Improve+principal+builder+interface+and+add+support+for+SASL) and which also provides the possibility to implement the principal builder when using SASL. For a Kafka 1.x version of this code, have a look on [this branch](https://github.com/pvillard31/kafka-ssl-principal-builder/tree/kafka_1.x).

The motivation behind this code is the following: some producers/consumers might not be able to use Kerberos to authenticate against Kafka brokers and, consequently, you can't use SASL\_PLAINTEXT or SASL\_SSL. Since PLAINTEXT is not an option (for obvious security reasons), it remains SSL.

*Note:* when configuring a broker to use SASL\_SSL, the authentication is done using Kerberos, and the SSL part is only to encrypt the communication between the client and the Kafka brokers.

When configuring a broker to use SSL, you will have authentication AND encryption if and only if 2-ways SSL is configured (by setting ``ssl.client.auth=required``). It is **strongly** recommended to always set this property to **required**. (For additional information: https://docs.confluent.io/current/kafka/authentication_ssl.html#ssl-overview).

When 2-ways SSL is enabled, the client will be authenticated using the Subject of the client certificate used to perform the handshake. It means that if the Subject is: ``CN=kafkaClient,OU=OrgUnit,O=My Company``, you will have to set your topic ACLs to allow this user to consume/publish data.

When using [Apache Ranger](https://ranger.apache.org/) to manage authorizations for your Kafka brokers, it's not great to have this kind of username... That's why we want to define a custom principal builder to extract a username from the Subject of the certificate.

In the provided code, I want to expose two properties: a pattern that will be used to match the Subject and extract any capture group I want, and a value to construct the username using the capture groups. I added the two below properties in the ``server.properties`` configuration file on brokers side:

````properties
kafka.security.identity.mapping.pattern.dn=^.*[Cc][Nn]=([a-zA-Z0-9.]*).*$
kafka.security.identity.mapping.value.dn=$1
````

In this case, I only want to extract the CN part of the Subject and use it as the username of the client. If needed, I could use more complex patterns but with my previous example, my client would be authenticated with ``kafkaClient`` as username. It's now easier to define the authorizations on my topic using built-in ACLs or using Apache Ranger.
