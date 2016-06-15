/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */
package io.fabric8.jaas;

/**
 * Created by pantinor on 14/06/16.
 */

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.osgi.framework.ServiceReference;
import org.osgi.service.cm.ConfigurationPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Hook for ConfigAdmin to decrypt on the fly encrypted values without keeping them in clear text in ConfigAdmin databese and its corresponding temporary files.
 */
public class EncryptableConfigurationPlugin implements ConfigurationPlugin {

    StringEncryptor encryptor;

    public static final Logger LOGGER = LoggerFactory.getLogger(EncryptableConfigurationPlugin.class);

    public static final String PREFIX = "ENC";
    public static final Pattern PATTERN = Pattern.compile(PREFIX + "\\((.*)\\)");

    public void modifyConfiguration(ServiceReference<?> reference,
                                    Dictionary<String, Object> properties) {
        Enumeration<String> keys = properties.keys();
        while(keys.hasMoreElements()){
            String key = keys.nextElement();
            String value = (String) properties.get(key);
            if(value.trim().startsWith(PREFIX + "(")){
                Matcher matcher = PATTERN.matcher(value);
                if(matcher.matches()){
                    String group = matcher.group(1);
                    try {
                        String decrypt = encryptor.decrypt(group);
                        properties.put(key, decrypt);
                    }catch(EncryptionOperationNotPossibleException e){
                        LOGGER.warn("Unable to decrypt a token for property [" + key + "] in [" + properties.get("service.pid") +  "] PID. Verify it was encoded according to the configuration of io.fabric8.jasypt PID", e);
                        throw e;
                    }
                }
            }
        }
    }

    public StringEncryptor getEncryptor() {
        return encryptor;
    }

    public void setEncryptor(StringEncryptor encryptor) {
        this.encryptor = encryptor;
    }

}