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
import java.security.Principal;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.network.Authenticator;
import org.apache.kafka.common.network.TransportLayer;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.PrincipalBuilder;

public class CustomPrincipalBuilder implements PrincipalBuilder {

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

    @Override
    public Principal buildPrincipal(TransportLayer layer, Authenticator authenticator) throws KafkaException {
        try {
            if ((layer.peerPrincipal() instanceof X500Principal)
                    && !layer.peerPrincipal().getName().equals(KafkaPrincipal.ANONYMOUS)) {

                if(dnValue == null || dnPattern == null) {
                    return layer.peerPrincipal();
                }

                final String dn = layer.peerPrincipal().getName();
                final Matcher m = dnPattern.matcher(dn);
                if (m.matches()) {
                    return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, dn.replaceAll(dnPattern.pattern(), escapeLiteralBackReferences(dnValue, m.groupCount())));
                }
            }

            return layer.peerPrincipal();
        } catch (Exception e) {
            throw new KafkaException("Failed to build principal due to: ", e);
        }
    }

    @Override
    public void close() throws KafkaException {
        // nothing to do
    }

    @Override
    public void configure(Map<String, ?> configuration) {
        // it appears that custom properties from server.properties file are not loaded here
        if(dnPattern == null || dnValue == null) {
            try {
                Properties prop = new Properties();
                prop.load(new FileInputStream(KAFKA_CONF));
                dnPattern = Pattern.compile(prop.getProperty("kafka.security.identity.mapping.pattern.dn"));
                dnValue = prop.getProperty("kafka.security.identity.mapping.value.dn");
            } catch (Exception e) {
                // nothing to do
            }
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

}
