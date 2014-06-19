/*
 * The Gemma project.
 * 
 * Copyright (c) 2006-2007 University of British Columbia
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package gemma.gsec.authentication;

import org.apache.commons.beanutils.PropertyUtils;

/**
 * The default exception thrown for unexpected errors occurring within
 * {@link ubic.gemma.security.authentication.UserService}.
 */
public class UserServiceException extends java.lang.RuntimeException {
    /**
     * The serial version UID of this class. Needed for serialization.
     */
    private static final long serialVersionUID = 9057091028307639437L;

    /**
     * Finds the root cause of the parent exception by traveling up the exception tree
     */
    private static Throwable findRootCause( Throwable th ) {
        if ( th != null ) {
            // Reflectively get any exception causes.
            try {
                Throwable targetException = null;

                // java.lang.reflect.InvocationTargetException
                String exceptionProperty = "targetException";
                if ( PropertyUtils.isReadable( th, exceptionProperty ) ) {
                    targetException = ( Throwable ) PropertyUtils.getProperty( th, exceptionProperty );
                } else {
                    exceptionProperty = "causedByException";
                    // javax.ejb.EJBException
                    if ( PropertyUtils.isReadable( th, exceptionProperty ) ) {
                        targetException = ( Throwable ) PropertyUtils.getProperty( th, exceptionProperty );
                    }
                }
                if ( targetException != null ) {
                    th = targetException;
                }
            } catch ( Exception ex ) {
                // just print the exception and continue
                ex.printStackTrace();
            }

            if ( th.getCause() != null ) {
                th = th.getCause();
                th = findRootCause( th );
            }
        }
        return th;
    }

    /**
     * The default constructor for <code>UserServiceException</code>.
     */
    public UserServiceException() {
    }

    /**
     * Constructs a new instance of <code>UserServiceException</code>.
     * 
     * @param message the throwable message.
     */
    public UserServiceException( String message ) {
        super( message );
    }

    /**
     * Constructs a new instance of <code>UserServiceException</code>.
     * 
     * @param message the throwable message.
     * @param throwable the parent of this Throwable.
     */
    public UserServiceException( String message, Throwable throwable ) {
        super( message, findRootCause( throwable ) );
    }

    /**
     * Constructs a new instance of <code>UserServiceException</code>.
     * 
     * @param throwable the parent Throwable
     */
    public UserServiceException( Throwable throwable ) {
        super( findRootCause( throwable ) );
    }
}