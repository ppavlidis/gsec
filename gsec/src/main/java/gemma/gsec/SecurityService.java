/*
 * The Gemma project
 * 
 * Copyright (c) 2012 University of British Columbia
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
package gemma.gsec;

import gemma.gsec.model.Securable;
import gemma.gsec.model.SecureValueObject;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author paul
 * @version $Id: SecurityService.java,v 1.98 2013/09/14 16:56:03 paul Exp $
 */
public interface SecurityService {

    /**
     * This is defined in spring-security AuthenticationConfigBuilder, and can be set in the <security:anonymous />
     * configuration of the <security:http/> namespace config
     */
    public static final String ANONYMOUS = AuthorityConstants.ANONYMOUS_USER_NAME;

    /**
     * @param userName
     * @param groupName
     */
    public abstract void addUserToGroup( String userName, String groupName );

    /**
     * @param securables
     * @return
     */
    public abstract <T extends Securable> Map<T, Boolean> areNonPublicButReadableByCurrentUser( Collection<T> securables );

    /**
     * A securable is considered "owned" if 1) the user is the actual owner assigned in the ACL or 2) the user is an
     * administrator. In other words, for an administrator, the value will always be true.
     * 
     * @param securables
     * @return
     */
    public abstract <T extends Securable> Map<T, Boolean> areOwnedByCurrentUser( Collection<T> securables );

    /**
     * @param securables
     * @return
     * @throws AuthorizationServiceException if the collection is empty, see comments in
     *         {@link gemma.gsec.acl.voter.AclCollectionEntryVoter AclCollectionEntryVoter}
     */
    @Secured({ "ACL_SECURABLE_COLLECTION_READ" })
    public abstract <T extends Securable> Map<T, Boolean> arePrivate( Collection<T> securables );

    /**
     * @throws AuthorizationServiceException if the collection is empty, see comments in
     *         {@link gemma.gsec.acl.voter.AclCollectionEntryVoter AclCollectionEntryVoter}
     */
    @Secured({ "ACL_SECURABLE_COLLECTION_READ" })
    public abstract <T extends Securable> Map<T, Boolean> areShared( Collection<T> securables );

    /**
     * @param securables
     * @return the subset which are private, if any
     */
    public abstract <T extends Securable> Collection<T> choosePrivate( Collection<T> securables );

    /**
     * @param securables
     * @return the subset that are public, if any
     * @throws AuthorizationServiceException if the collection is empty, see comments in
     *         {@link gemma.gsec.acl.voter.AclCollectionEntryVoter AclCollectionEntryVoter}
     */
    @Secured({ "ACL_SECURABLE_COLLECTION_READ" })
    public abstract <T extends Securable> Collection<T> choosePublic( Collection<T> securables );

    /**
     * If the group already exists, an exception will be thrown.
     * 
     * @param groupName
     */
    @Transactional
    public abstract void createGroup( String groupName );

    /**
     * @param s
     * @return list of userNames who can edit the given securable.
     * @throws AuthorizationServiceException if the collection is empty, see comments in
     *         {@link gemma.gsec.acl.voter.AclCollectionEntryVoter AclCollectionEntryVoter}
     */
    @Secured({ "ACL_SECURABLE_READ" })
    public abstract Collection<String> editableBy( Securable s );

    /**
     * Note that this method cannot be secured, but as it only reads permissions on a securable already in scope, it is
     * safe.
     * 
     * @param s
     * @return
     */
    public MutableAcl getAcl( Securable s );

    /**
     * Note that this method cannot be secured, but as it only reads permissions on securables already in scope, it is
     * safe.
     * 
     * @param securables, which could be securedvalueobjects
     * @return
     */
    public <T extends Securable> Map<T, Acl> getAcls( Collection<T> securables );

    /**
     * We make this available to anonymous
     * 
     * @return
     */
    public abstract Integer getAuthenticatedUserCount();

    /**
     * @return user names
     */
    @Secured("GROUP_ADMIN")
    public abstract Collection<String> getAuthenticatedUserNames();

    /**
     * This methods is only available to administrators.
     * 
     * @return collection of all available security ids (basically, user names and group authorities.
     */
    @Secured("GROUP_ADMIN")
    public abstract Collection<Sid> getAvailableSids();

    public String getGroupAuthorityNameFromGroupName( String groupName );

    /**
     * @param s
     * @throws AuthorizationServiceException if the collection is empty, see comments in
     *         {@link gemma.gsec.acl.voter.AclCollectionEntryVoter AclCollectionEntryVoter}
     */
    @Secured({ "ACL_SECURABLE_COLLECTION_READ" })
    public abstract <T extends Securable> Map<T, Collection<String>> getGroupsEditableBy( Collection<T> securables );

    /**
     * @param s
     * @return
     */
    @Secured({ "ACL_SECURABLE_READ" })
    public abstract Collection<String> getGroupsEditableBy( Securable s );

    /**
     * @param s
     * @return
     */
    @Secured({ "ACL_SECURABLE_COLLECTION_READ" })
    public abstract <T extends Securable> Map<T, Collection<String>> getGroupsReadableBy( Collection<T> securables );

    /**
     * @param s
     * @return names of groups which have read access to the securable, limited to groups the current user can read.
     */
    @Secured({ "ACL_SECURABLE_READ" })
    public abstract Collection<String> getGroupsReadableBy( Securable s );

    /**
     * @param userName
     * @return
     */
    public abstract Collection<String> getGroupsUserCanEdit( String userName );

    /**
     * @param s
     * @return
     */
    @Secured("ACL_SECURABLE_READ")
    public abstract Sid getOwner( Securable s );

    /**
     * Pretty much have to be either the owner of the securables or administrator to call this.
     * 
     * @param securables
     * @return
     * @throws AccessDeniedException if the current user is not allowed to access the information.
     */
    @Secured("ACL_SECURABLE_COLLECTION_READ")
    public abstract <T extends Securable> Map<T, Sid> getOwners( Collection<T> securables );

    /**
     * Advanced. Determine if the given securables have the required permissions under the given authentication.
     * <p>
     * Implementation note: This deals with lists to avoid having to compute hashcodes on securables that might not be
     * thawed. But we do avoid fetching ACLs that are not needed.
     * 
     * @param svos
     * @param requiredPermissions
     * @param authentication
     * @return
     */
    public <T extends Securable> List<Boolean> hasPermission( List<T> sos, List<Permission> requiredPermissions,
            Authentication authentication );

    /**
     * @param svos
     * @param requiredPermissions
     * @param authentication
     * @return
     */
    public Map<SecureValueObject, Boolean> hasPermissionVO( Collection<SecureValueObject> svos,
            List<Permission> requiredPermissions, Authentication authentication );

    /**
     * @param svo
     * @param requiredPermissions
     * @param authentication
     * @return
     */
    public boolean hasPermissionVO( SecureValueObject svo, List<Permission> requiredPermissions,
            Authentication authentication );

    /**
     * @param s
     * @return true if the current user can edit the securable
     */
    @Secured("ACL_SECURABLE_READ")
    public abstract boolean isEditable( Securable s );

    /**
     * @param s
     * @param groupName
     * @return
     */
    @Secured("ACL_SECURABLE_READ")
    public abstract boolean isEditableByGroup( Securable s, String groupName );

    /**
     * @param s
     * @param userName
     * @return true if the user has WRITE permissions or ADMIN
     */
    @Secured("ACL_SECURABLE_READ")
    public abstract boolean isEditableByUser( Securable s, String userName );

    /**
     * @param s
     * @return true if the owner is the same as the current authenticated user. Special case: if the owner is an
     *         administrator, and the uc
     */
    public abstract boolean isOwnedByCurrentUser( Securable s );

    /**
     * Convenience method to determine the visibility of an object.
     * 
     * @param s
     * @return true if anonymous users can view (READ) the object, false otherwise. If the object doesn't have an ACL,
     *         return true (be safe!)
     * @see org.springframework.security.acls.jdbc.BasicLookupStrategy
     */
    public abstract boolean isPrivate( Securable s );

    /**
     * Convenience method to determine the visibility of an object.
     * 
     * @param s
     * @return the negation of isPrivate().
     */
    public abstract boolean isPublic( Securable s );

    @Secured("ACL_SECURABLE_READ")
    public abstract boolean isReadableByGroup( Securable s, String groupName );

    public abstract boolean isShared( Securable s );

    /**
     * @param s
     * @param userName
     * @return true if the given user can read the securable, false otherwise. (READ or ADMINISTRATION required)
     */
    @Secured({ "ACL_SECURABLE_READ" })
    public abstract boolean isViewableByUser( Securable s, String userName );

    /**
     * Administrative method to allow a user to get access to an object. This is useful for cases where a data set is
     * loaded by admin but we need to hand it off to a user. If the user is the same as the current owner nothing is
     * done.
     * <p>
     * TODO: consider allowing a groupauthority to be the owner (GROUP_ADMIN) - see bug 2996
     * 
     * @param s
     * @param userName
     */
    @Secured("GROUP_ADMIN")
    public abstract void makeOwnedByUser( Securable s, String userName );

    /**
     * @param objs
     */
    public abstract void makePrivate( Collection<? extends Securable> objs );

    /**
     * Makes the object private.
     * 
     * @param object
     */
    @Secured("ACL_SECURABLE_EDIT")
    public abstract void makePrivate( Securable object );

    /**
     * @param objs
     */
    @Transactional
    public abstract void makePublic( Collection<? extends Securable> objs );

    /**
     * Makes the object public
     * 
     * @param object
     */
    @Secured("ACL_SECURABLE_EDIT")
    public abstract void makePublic( Securable object );

    /**
     * Adds read permission.
     * 
     * @param s
     * @param groupName
     * @throws AccessDeniedException
     */
    @Secured("ACL_SECURABLE_EDIT")
    public abstract void makeReadableByGroup( Securable s, String groupName ) throws AccessDeniedException;

    /**
     * Remove read permissions; also removes write permissions.
     * 
     * @param s
     * @param groupName, with or without GROUP_
     * @throws AccessDeniedException
     */
    @Secured("ACL_SECURABLE_EDIT")
    public abstract void makeUnreadableByGroup( Securable s, String groupName ) throws AccessDeniedException;

    /**
     * Remove write permissions. Leaves read permissions, if present.
     * 
     * @param s
     * @param groupName
     * @throws AccessDeniedException
     */
    @Secured("ACL_SECURABLE_EDIT")
    public abstract void makeUnwriteableByGroup( Securable s, String groupName ) throws AccessDeniedException;

    /**
     * Adds write (and read) permissions.
     * 
     * @param s
     * @param groupName
     * @throws AccessDeniedException
     */
    @Secured("ACL_SECURABLE_EDIT")
    public abstract void makeWriteableByGroup( Securable s, String groupName ) throws AccessDeniedException;

    /**
     * @param s
     * @return list of userNames of users who can read the given securable.
     */
    @Secured("ACL_SECURABLE_EDIT")
    public abstract Collection<String> readableBy( Securable s );

    /**
     * @param userName
     * @param groupName
     */
    public abstract void removeUserFromGroup( String userName, String groupName );

    /**
     * Change the 'owner' of an object to a specific user. Note that this doesn't support making the owner a
     * grantedAuthority.
     * 
     * @param s
     * @param userName
     */
    @Secured("GROUP_ADMIN")
    public abstract void setOwner( Securable s, String userName );

}