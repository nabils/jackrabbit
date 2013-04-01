package org.custom.security;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.servlet.ServletRepository;

import javax.jcr.*;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;

public class ChangePasswordServlet extends HttpServlet {
    private final Repository repository = new ServletRepository(this);

    @Override
    protected void doGet(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws IOException, ServletException {

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        String userNameToChange = request.getParameter("usernameToChange");
        String oldPassword = request.getParameter("oldPassword");
        String newPassword = request.getParameter("newPassword");

        PrintWriter out = response.getWriter();

        try {
            Session session = repository.login(new SimpleCredentials(username, password.toCharArray()));

            try {
                changePassword(session, userNameToChange, oldPassword, newPassword);
                out.println("Password changed successfully");
            } finally {
                session.logout();
            }
        } catch (Exception e) {
            out.println(ExceptionUtils.getFullStackTrace(e));
        } finally {
            out.close();
        }
    }

    private static final String DEFAULT_USER_ADMIN_GROUP_NAME = "UserAdmin";

    public static User changePassword(Session jcrSession,
                                      String name,
                                      String oldPassword,
                                      String newPassword)
            throws Exception
    {
        if ("anonymous".equals(name)) {
            throw new RepositoryException(
                    "Can not change the password of the anonymous user.");
        }

        User user;
        UserManager userManager = ((JackrabbitSession)jcrSession).getUserManager();
        Authorizable authorizable = userManager.getAuthorizable(name);
        if (authorizable instanceof User) {
            user = (User)authorizable;

        } else {
            throw new Exception("User to update could not be determined");
        }

        //SLING-2069: if the current user is an administrator, then a missing oldPwd is ok,
        // otherwise the oldPwd must be supplied.
        boolean administrator = false;

        // check that the submitted parameter values have valid values.
        if (oldPassword == null || oldPassword.length() == 0) {
            try {
                UserManager um = ((JackrabbitSession)jcrSession).getUserManager();
                User currentUser = (User) um.getAuthorizable(jcrSession.getUserID());
                administrator = currentUser.isAdmin();

                if (!administrator) {
                    //check if the user is a member of the 'User administrator' group
                    Authorizable userAdmin = um.getAuthorizable(DEFAULT_USER_ADMIN_GROUP_NAME);
                    if (userAdmin instanceof Group) {
                        boolean isMember = ((Group)userAdmin).isMember(currentUser);
                        if (isMember) {
                            administrator = true;
                        }
                    }

                }
            } catch ( Exception ex ) {
                //log.warn("Failed to determine if the user is an admin, assuming not. Cause: "+ex.getMessage());
                administrator = false;
            }
            if (!administrator) {
                throw new RepositoryException("Old Password was not submitted");
            }
        }
        if (newPassword == null || newPassword.length() == 0) {
            throw new RepositoryException("New Password was not submitted");
        }

        if (oldPassword != null && oldPassword.length() > 0) {
            // verify old password
            checkPassword(authorizable, oldPassword);
        }

        try {
            ((User) authorizable).changePassword(newPassword);

        } catch (RepositoryException re) {
            throw new RepositoryException("Failed to change user password.", re);
        }

        return user;
    }

    private static void checkPassword(Authorizable authorizable, String oldPassword)
            throws RepositoryException {
        Credentials oldCreds = ((User) authorizable).getCredentials();
        if (oldCreds instanceof SimpleCredentials) {
            char[] oldCredsPwd = ((SimpleCredentials) oldCreds).getPassword();
            if (oldPassword.equals(String.valueOf(oldCredsPwd))) {
                return;
            }
        } else {
            try {
                // CryptSimpleCredentials.matches(SimpleCredentials credentials)
                Class<?> oldCredsClass = oldCreds.getClass();
                Method matcher = oldCredsClass.getMethod("matches",
                        SimpleCredentials.class);
                SimpleCredentials newCreds = new SimpleCredentials(
                        authorizable.getPrincipal().getName(),
                        oldPassword.toCharArray());
                boolean match = (Boolean) matcher.invoke(oldCreds, newCreds);
                if (match) {
                    return;
                }
            } catch (Throwable t) {
                // failure here, fall back to password check failure below
            }
        }

        throw new RepositoryException("Old Password does not match");
    }
}
