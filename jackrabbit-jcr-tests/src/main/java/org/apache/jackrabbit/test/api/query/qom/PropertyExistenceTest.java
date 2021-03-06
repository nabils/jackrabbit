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
package org.apache.jackrabbit.test.api.query.qom;

import javax.jcr.RepositoryException;
import javax.jcr.Node;
import javax.jcr.query.qom.QueryObjectModel;

/**
 * <code>PropertyExistenceTest</code> performs a test with
 * <code>PropertyExistence</code>.
 */
public class PropertyExistenceTest extends AbstractQOMTest {

    public void testPropertyExistence() throws RepositoryException {
        Node n1 = testRootNode.addNode(nodeName1, testNodeType);
        n1.setProperty(propertyName1, "abc");
        Node n2 = testRootNode.addNode(nodeName2, testNodeType);
        n2.setProperty(propertyName2, "abc");
        superuser.save();

        QueryObjectModel qom = qf.createQuery(
                qf.selector(testNodeType, "s"),
                qf.and(
                        qf.childNode("s", testRoot),
                        qf.propertyExistence("s", propertyName1)
                ), null, null);
        checkQOM(qom, new Node[]{n1});

        qom = qf.createQuery(
                qf.selector(testNodeType, "s"),
                qf.and(
                        qf.childNode("s", testRoot),
                        qf.propertyExistence("s", propertyName2)
                ), null, null);
        checkQOM(qom, new Node[]{n2});
    }
}
