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
package org.apache.jackrabbit.api.security.user;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.principal.PrincipalIterator;
import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.jackrabbit.test.NotExecutableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import java.security.Principal;

/**
 * <code>NestedGroupTest</code>...
 */
public class NestedGroupTest extends AbstractUserTest {

    private static Logger log = LoggerFactory.getLogger(NestedGroupTest.class);

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    private Group createGroup(Principal p) throws RepositoryException, NotExecutableException {
        Group gr = userMgr.createGroup(p);
        save(superuser);
        return gr;
    }

    private void removeGroup(Group gr) throws RepositoryException, NotExecutableException {
        gr.remove();
        save(superuser);
    }

    private boolean addMember(Group gr, Authorizable member) throws RepositoryException, NotExecutableException {
        boolean added = gr.addMember(member);
        save(superuser);
        return added;
    }

    private boolean removeMember(Group gr, Authorizable member) throws RepositoryException, NotExecutableException {
        boolean removed = gr.removeMember(member);
        save(superuser);
        return removed;
    }

    public void testAddGroupAsMember() throws NotExecutableException, RepositoryException {
        Group gr1 = null;
        Group gr2 = null;

        try {
            gr1 = createGroup(getTestPrincipal());
            gr2 = createGroup(getTestPrincipal());

            assertFalse(gr1.isMember(gr2));

            assertTrue(addMember(gr1, gr2));
            assertTrue(gr1.isMember(gr2));

        } finally {
            if (gr1 != null) {
                removeMember(gr1, gr2);
                removeGroup(gr1);
            }
            if (gr2 != null) {
                removeGroup(gr2);
            }
        }
    }

    public void testAddCircularMembers() throws NotExecutableException, RepositoryException {
        Group gr1 = null;
        Group gr2 = null;

        try {
            gr1 = createGroup(getTestPrincipal());
            gr2 = createGroup(getTestPrincipal());

            assertTrue(addMember(gr1, gr2));
            assertFalse(addMember(gr2, gr1));

        } finally {
            if (gr1 != null && gr1.isMember(gr2)) {
                removeMember(gr1, gr2);
            }
            if (gr2 != null && gr2.isMember(gr1)) {
                removeMember(gr2, gr1);
            }
            if (gr1 != null) removeGroup(gr1);
            if (gr2 != null) removeGroup(gr2);
        }
    }

    public void testCyclicMembers2() throws RepositoryException, NotExecutableException {
        Group gr1 = null;
        Group gr2 = null;
        Group gr3 = null;
        try {
            gr1 = createGroup(getTestPrincipal());
            gr2 = createGroup(getTestPrincipal());
            gr3 = createGroup(getTestPrincipal());

            assertTrue(addMember(gr1, gr2));
            assertTrue(addMember(gr2, gr3));
            assertFalse(addMember(gr3, gr1));

        } finally {
            if (gr1 != null) {
                removeMember(gr1, gr2);
            }
            if (gr2 != null) {
                removeMember(gr2, gr3);
                removeGroup(gr2);
            }
            if (gr3 != null) {
                removeMember(gr3, gr1);
                removeGroup(gr3);
            }
            if (gr1 != null) removeGroup(gr1);

        }
    }

    public void testInheritedMembership() throws NotExecutableException, RepositoryException {
        Group gr1 = null;
        Group gr2 = null;
        Group gr3 = null;

        if (!(superuser instanceof JackrabbitSession)) {
            throw new NotExecutableException();
        }

        try {
            gr1 = createGroup(getTestPrincipal());
            gr2 = createGroup(getTestPrincipal());
            gr3 = createGroup(getTestPrincipal());

            assertTrue(addMember(gr1, gr2));
            assertTrue(addMember(gr2, gr3));

            // NOTE: don't test with Group.isMember for not required to detect
            // inherited membership -> rather with PrincipalManager.
            boolean isMember = false;
            PrincipalManager pmgr = ((JackrabbitSession) superuser).getPrincipalManager();
            for (PrincipalIterator it = pmgr.getGroupMembership(gr3.getPrincipal());
                 it.hasNext() && !isMember;) {
                isMember = it.nextPrincipal().equals(gr1.getPrincipal());
            }
            assertTrue(isMember);

        } finally {
            if (gr1 != null && gr1.isMember(gr2)) {
                removeMember(gr1, gr2);
            }
            if (gr2 != null && gr2.isMember(gr3)) {
                removeMember(gr2, gr3);
            }
            if (gr1 != null) removeGroup(gr1);
            if (gr2 != null) removeGroup(gr2);
            if (gr3 != null) removeGroup(gr3);
        }
    }
}