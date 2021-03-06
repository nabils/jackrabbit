/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.jackrabbit.standalone.cli.info;

import org.apache.jackrabbit.standalone.cli.CommandException;

/**
 * Exception thrown by Info Commands
 */
public class JcrInfoCommandException extends CommandException {
    /**
     * Comment for <code>serialVersionUID</code>
     */
    private static final long serialVersionUID = 3257854259679866933L;

    /**
     * @param message
     *        the message
     */
    public JcrInfoCommandException(String message) {
        super(message);
    }

    /**
     * @param message
     *        the message
     * @param arguments
     *        the arguments
     */
    public JcrInfoCommandException(String message, Object[] arguments) {
        super(message, arguments);
    }

    /**
     * @param message
     *        the message
     * @param cause
     *        the cause
     */
    public JcrInfoCommandException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * @param message
     *        the message
     * @param cause
     *        the cause
     * @param arguments
     *        the arguments
     */
    public JcrInfoCommandException(String message, Throwable cause,
        Object[] arguments) {
        super(message, cause, arguments);
    }
}
