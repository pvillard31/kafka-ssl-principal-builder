/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package kafka.security.auth;

import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.SaslServer;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.config.internals.BrokerSecurityConfigs;
import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.PlaintextAuthenticationContext;
import org.apache.kafka.common.security.auth.SaslAuthenticationContext;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.apache.kafka.common.security.kerberos.KerberosName;
import org.apache.kafka.common.security.kerberos.KerberosShortNamer;
import org.apache.kafka.common.utils.Java;

public class CustomPrincipalBuilder_1 implements KafkaPrincipalBuilder {

    private static final String KAFKA_CONF = "/etc/kafka/conf/server.properties";
    private static final Pattern backReferencePattern = Pattern.compile("\\$(\\d+)");

    /**
     * Example: ^CN=(.*?), OU=.*$
     */
    private Pattern dnPattern;

    /**
     * Example: $1
     */
    private String dnValue;

    private KerberosShortNamer kerberosShortNamer;

    public CustomPrincipalBuilder_1() {
        try {
            Properties prop = new Properties();
            prop.load(new FileInputStream(KAFKA_CONF));
            dnPattern = Pattern.compile(prop.getProperty("kafka.security.identity.mapping.pattern.dn"));
            dnValue = prop.getProperty("kafka.security.identity.mapping.value.dn");

            List<String> principalToLocalRules = Arrays.asList(prop.getProperty(BrokerSecurityConfigs.SASL_KERBEROS_PRINCIPAL_TO_LOCAL_RULES_CONFIG).split(","));
            kerberosShortNamer = KerberosShortNamer.fromUnparsedRules(defaultRealm(), principalToLocalRules);
        } catch (Exception e) {
            // nothing to do
        }
    }

    @Override
    public KafkaPrincipal build(AuthenticationContext context) {

        if (context instanceof PlaintextAuthenticationContext) {
            return KafkaPrincipal.ANONYMOUS;

        } else if (context instanceof SslAuthenticationContext) {
            SSLSession sslSession = ((SslAuthenticationContext) context).session();

            try {
                return convertToKafkaPrincipal(sslSession.getPeerPrincipal());
            } catch (SSLPeerUnverifiedException se) {
                return KafkaPrincipal.ANONYMOUS;
            }

        } else if (context instanceof SaslAuthenticationContext) {
            SaslServer saslServer = ((SaslAuthenticationContext) context).server();

            if (SaslConfigs.GSSAPI_MECHANISM.equals(saslServer.getMechanismName())) {
                return applyKerberosShortNamer(saslServer.getAuthorizationID());
            } else {
                return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, saslServer.getAuthorizationID());
            }

        } else {
            throw new IllegalArgumentException("Unhandled authentication context type: " + context.getClass().getName());
        }
    }

    private KafkaPrincipal applyKerberosShortNamer(String authorizationId) {
        KerberosName kerberosName = KerberosName.parse(authorizationId);
        try {
            String shortName = kerberosShortNamer.shortName(kerberosName);
            return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, shortName);
        } catch (IOException e) {
            throw new KafkaException("Failed to set name for '" + kerberosName + "' based on Kerberos authentication rules.", e);
        }
    }

    public KafkaPrincipal convertToKafkaPrincipal(Principal principal) throws KafkaException {
        final KafkaPrincipal defaultPrincipal = new KafkaPrincipal(KafkaPrincipal.USER_TYPE, principal.getName());
        try {
            if ((principal instanceof X500Principal)
                    && !principal.getName().equals(KafkaPrincipal.ANONYMOUS)) {

                if(dnValue == null || dnPattern == null) {
                    return defaultPrincipal;
                }

                final String dn = principal.getName();
                final Matcher m = dnPattern.matcher(dn);
                if (m.matches()) {
                    return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, dn.replaceAll(dnPattern.pattern(), escapeLiteralBackReferences(dnValue, m.groupCount())));
                }
            }

            return defaultPrincipal;
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }

    private static String escapeLiteralBackReferences(final String unescaped, final int numCapturingGroups) {
        if (numCapturingGroups == 0) {
            return unescaped;
        }

        String value = unescaped;
        final Matcher backRefMatcher = backReferencePattern.matcher(value);
        while (backRefMatcher.find()) {
            final String backRefNum = backRefMatcher.group(1);
            if (backRefNum.startsWith("0")) {
                continue;
            }
            final int originalBackRefIndex = Integer.parseInt(backRefNum);
            int backRefIndex = originalBackRefIndex;

            while (backRefIndex > numCapturingGroups && backRefIndex >= 10) {
                backRefIndex /= 10;
            }

            if (backRefIndex > numCapturingGroups) {
                final StringBuilder sb = new StringBuilder(value.length() + 1);
                final int groupStart = backRefMatcher.start(1);

                sb.append(value.substring(0, groupStart - 1));
                sb.append("\\");
                sb.append(value.substring(groupStart - 1));
                value = sb.toString();
            }
        }

        return value;
    }

    private static String defaultRealm() throws ClassNotFoundException, NoSuchMethodException,
    IllegalArgumentException, IllegalAccessException, InvocationTargetException {
        //TODO Find a way to avoid using these proprietary classes as access to Java 9 will block access by default due to the Jigsaw module system
        Object kerbConf;
        Class<?> classRef;
        Method getInstanceMethod;
        Method getDefaultRealmMethod;
        if (Java.isIbmJdk()) {
            classRef = Class.forName("com.ibm.security.krb5.internal.Config");
        } else {
            classRef = Class.forName("sun.security.krb5.Config");
        }
        getInstanceMethod = classRef.getMethod("getInstance", new Class[0]);
        kerbConf = getInstanceMethod.invoke(classRef, new Object[0]);
        getDefaultRealmMethod = classRef.getDeclaredMethod("getDefaultRealm", new Class[0]);
        return (String) getDefaultRealmMethod.invoke(kerbConf, new Object[0]);
    }

}
