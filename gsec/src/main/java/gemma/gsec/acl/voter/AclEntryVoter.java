/*
 * The Gemma project
 * 
 * Copyright (c) 2013 University of British Columbia
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package gemma.gsec.acl.voter;

import gemma.gsec.acl.AclSidRetrievalStrategyImpl;
import gemma.gsec.acl.ValueObjectAwareIdentityRetrievalStrategyImpl;
import gemma.gsec.model.SecuredChild;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Permission;

/**
 * Specialization to allow handling of SecuredChild.
 * 
 * @author Paul
 * @version $Id: AclEntryVoter.java,v 1.3 2013/09/14 16:56:02 paul Exp $
 */
public class AclEntryVoter extends org.springframework.security.acls.AclEntryVoter {

    public AclEntryVoter( AclService aclService, String processConfigAttribute, Permission[] requirePermission ) {
        super( aclService, processConfigAttribute, requirePermission );
        this.setObjectIdentityRetrievalStrategy( new ValueObjectAwareIdentityRetrievalStrategyImpl() );
        this.setSidRetrievalStrategy( new AclSidRetrievalStrategyImpl() );
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.access.vote.AbstractAclVoter#getDomainObjectInstance(java.lang.Object)
     */
    @Override
    protected Object getDomainObjectInstance( MethodInvocation invocation ) {
        Object[] args;
        Class<?>[] params;

        params = invocation.getMethod().getParameterTypes();
        args = invocation.getArguments();

        for ( int i = 0; i < params.length; i++ ) {
            if ( getProcessDomainObjectClass().isAssignableFrom( params[i] ) ) {
                return args[i];
            }
        }

        // Start special case!
        for ( int i = 0; i < params.length; i++ ) {
            if ( SecuredChild.class.isAssignableFrom( params[i] ) ) {
                return ( ( SecuredChild ) args[i] ).getSecurityOwner();
            }
        }

        // voter will abstain.
        return null;

    }

}
