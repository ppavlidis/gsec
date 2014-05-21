/*
 * The Gemma project
 * 
 * Copyright (c) 2013 University of British Columbia
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
package gemma.gsec.acl.afterinvocation;

import gemma.gsec.SecurityService;
import gemma.gsec.acl.ValueObjectAwareIdentityRetrievalStrategyImpl;
import gemma.gsec.model.SecureValueObject;
import gemma.gsec.util.SecurityUtil;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.time.StopWatch;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.afterinvocation.AbstractAclProvider;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;

/**
 * Security check for reading collections of SecureValueObjects, or maps that have SecureValueObjects as keys - map
 * values are NOT checked.
 * <p>
 * As a side effect, it fills in security status information in the value objects, on those object for which permission
 * was granted.
 * 
 * @author cmcdonald
 * @version $Id: AclAfterFilterValueObjectCollectionProvider.java,v 1.9 2013/09/14 16:56:01 paul Exp $
 */
public class AclAfterFilterValueObjectCollectionProvider extends AbstractAclProvider {

    protected static final Log logger = LogFactory.getLog( AclAfterFilterValueObjectCollectionProvider.class );

    @Autowired
    private SecurityService securityService;

    /**
     * @param aclService
     * @param requirePermission
     */
    public AclAfterFilterValueObjectCollectionProvider( AclService aclService, List<Permission> requirePermission ) {
        super( aclService, "AFTER_ACL_VALUE_OBJECT_COLLECTION_READ", requirePermission );
        this.setObjectIdentityRetrievalStrategy( new ValueObjectAwareIdentityRetrievalStrategyImpl() );

    }

    @Override
    @SuppressWarnings("unchecked")
    public final Object decide( Authentication authentication, Object object, Collection<ConfigAttribute> config,
            Object returnedObject ) throws AccessDeniedException {
        Iterator<ConfigAttribute> iter = config.iterator();

        while ( iter.hasNext() ) {
            ConfigAttribute attr = iter.next();

            if ( this.supports( attr ) ) {
                // Need to process the Collection for this invocation
                if ( returnedObject == null ) {
                    logger.debug( "Return object is null, skipping" );
                    return returnedObject;
                }

                Filterer<Object> filterer = null;
                boolean isMap = false;
                if ( returnedObject instanceof Map ) {
                    isMap = true;
                    filterer = new MapFilterer<Object>( ( Map<Object, Object> ) returnedObject );
                } else if ( returnedObject instanceof Collection ) {
                    Collection<Object> collection = ( Collection<Object> ) returnedObject;
                    filterer = new CollectionFilterer<Object>( collection );
                } else if ( returnedObject.getClass().isArray() ) {
                    Object[] array = ( Object[] ) returnedObject;
                    filterer = new ArrayFilterer<Object>( array );
                } else {
                    throw new UnsupportedOperationException( "Must be a Collection" );
                }

                // Locate unauthorised Collection elements
                Iterator<Object> collectionIter = filterer.iterator();

                /*
                 * Collect up the securevalueobjects
                 */
                Collection<SecureValueObject> securablesToFilter = new HashSet<>();
                while ( collectionIter.hasNext() ) {
                    Object domainObject = collectionIter.next();
                    if ( !SecureValueObject.class.isAssignableFrom( domainObject.getClass() ) ) {
                        continue;
                    }
                    securablesToFilter.add( ( SecureValueObject ) domainObject );
                }

                Map<SecureValueObject, Boolean> hasPerm = securityService.hasPermissionVO( securablesToFilter,
                        this.requirePermission, authentication );

                for ( SecureValueObject s : hasPerm.keySet() ) {
                    if ( !hasPerm.get( s ) ) {
                        filterer.remove( s );
                    }
                }

                // Following are only relevant if you are logged in.
                if ( !SecurityUtil.isUserLoggedIn() ) {
                    return filterer.getFilteredObject();
                }

                StopWatch timer = new StopWatch();
                timer.start();

                Collection<SecureValueObject> securables;
                if ( isMap ) {
                    Map<SecureValueObject, ?> filteredObject = ( Map<SecureValueObject, ?> ) filterer
                            .getFilteredObject();
                    if ( filteredObject.isEmpty() ) {
                        return filteredObject;
                    }
                    securables = filteredObject.keySet();
                } else {
                    Collection<SecureValueObject> filteredObject = ( Collection<SecureValueObject> ) filterer
                            .getFilteredObject();
                    if ( filteredObject.isEmpty() ) {
                        return filteredObject;
                    }
                    securables = filteredObject;
                }

                Map<SecureValueObject, Acl> acls = securityService.getAcls( securables );
                Map<SecureValueObject, Boolean> areOwnedByCurrentUser = securityService
                        .areOwnedByCurrentUser( securables );
                boolean userIsAdmin = SecurityUtil.isUserAdmin();

                // Only need to check for write permissions if we can't already infer it.
                Map<SecureValueObject, Boolean> canWrite = new HashMap<>();
                if ( !userIsAdmin && !requirePermission.contains( BasePermission.WRITE ) ) {
                    List<Permission> writePermissions = new ArrayList<>();
                    writePermissions.add( BasePermission.WRITE );
                    canWrite = securityService.hasPermissionVO( securablesToFilter, this.requirePermission,
                            authentication );
                }

                for ( SecureValueObject svo : securables ) {

                    /*
                     * Populate optional fields in the ValueObject.
                     */

                    // this should be fast, but could be even faster.
                    Acl acl = acls.get( svo );
                    assert acl != null;
                    svo.setIsPublic( !SecurityUtil.isPrivate( acl ) );
                    svo.setIsShared( SecurityUtil.isShared( acl ) );
                    svo.setUserOwned( areOwnedByCurrentUser.get( svo ) );

                    if ( svo.getUserOwned() || userIsAdmin || requirePermission.contains( BasePermission.WRITE ) ) {
                        svo.setUserCanWrite( true );
                    } else {
                        svo.setUserCanWrite( canWrite.containsKey( svo ) && canWrite.get( svo ) );
                    }
                }

                if ( timer.getTime() > 100 ) {
                    logger.info( "Fill in security details on " + acls.keySet().size() + " value objects: "
                            + timer.getTime() + "ms" );
                }
                return filterer.getFilteredObject();
            }
        }

        return returnedObject;
    }
}
