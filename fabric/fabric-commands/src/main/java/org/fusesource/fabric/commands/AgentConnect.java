/**
 * Copyright (C) FuseSource, Inc.
 * http://fusesource.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.fusesource.fabric.commands;

import org.apache.felix.gogo.commands.Argument;
import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.fusesource.fabric.api.Agent;
import org.fusesource.fabric.commands.support.FabricCommand;

import java.util.List;

@Command(name = "agent-connect", scope = "fabric", description = "Connect to a remote fabric agent")
public class AgentConnect extends FabricCommand {

    @Option(name="-u", aliases={"--username"}, description="Remote user name (Default: admin)", required = false, multiValued = false)
    private String username = "admin";

    @Option(name="-p", aliases={"--password"}, description="Remote user password (Default: admin)", required = false, multiValued = false)
    private String password = "admin";

    @Argument(index = 0, name="agent", description="The agent name", required = true, multiValued = false)
    private String agent = null;

    @Argument(index = 1, name = "command", description = "Optional command to execute", required = false, multiValued = true)
    private List<String> command;

    protected Object doExecute() throws Exception {
        String cmdStr = "";
        if (command != null) {
            StringBuilder sb = new StringBuilder();
            for (String cmd : command) {
                if (sb.length() > 0) {
                    sb.append(' ');
                }
                sb.append(cmd);
            }
            cmdStr = "'" + sb.toString().replaceAll("'", "\\'") + "'";
        }

        Agent a = fabricService.getAgent(agent);
        if (a == null) {
            throw new IllegalArgumentException("Agent " + agent + " does not exist.");
        }
        String sshUrl = a.getSshUrl();
        if (sshUrl == null) {
            throw new IllegalArgumentException("Agent " + agent + " has no SSH URL.");
        }
        String[] ssh = sshUrl.split(":");
        if (ssh.length < 2) {
            throw new IllegalArgumentException("Agent " + agent + " has an invalid SSH URL '" + sshUrl + "'");
        }
        session.execute("ssh -l " + username + " -P " + password + " -p " + ssh[1] + " " + ssh[0] + " " + cmdStr);
        return null;
    }

}
