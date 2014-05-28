/*
 * The Gemma project.
 * 
 * Copyright (c) 2006-2012 University of British Columbia
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
package gemma.gsec.model;

/**
 * Authority for groups (kind of like a "user role", but for group-based authorization)
 */
public abstract class GroupAuthority implements java.io.Serializable {

    /**
     * Constructs new instances of {@link GroupAuthority}.
     */
    public static final class Factory {
        /**
         * Constructs a new instance of {@link GroupAuthority}.
         */
        public static GroupAuthority newInstance() {
            return new GroupAuthorityImpl();
        }

        /**
         * Constructs a new instance of {@link GroupAuthority}, taking all possible properties (except the
         * identifier(s))as arguments.
         */
        public static GroupAuthority newInstance( String authority ) {
            final GroupAuthority entity = new GroupAuthorityImpl();
            entity.setAuthority( authority );
            return entity;
        }
    }

    /**
     * The serial version UID of this class. Needed for serialization.
     */
    private static final long serialVersionUID = 6376142653264312139L;
    private String authority;

    private Long id;

    /**
     * No-arg constructor added to satisfy javabean contract
     * 
     * @author Paul
     */
    public GroupAuthority() {
    }

    /**
     * Returns <code>true</code> if the argument is an GroupAuthority instance and all identifiers for this entity equal
     * the identifiers of the argument entity. Returns <code>false</code> otherwise.
     */
    @Override
    public boolean equals( Object object ) {
        if ( this == object ) {
            return true;
        }
        if ( !( object instanceof GroupAuthority ) ) {
            return false;
        }
        final GroupAuthority that = ( GroupAuthority ) object;
        if ( this.id == null || that.getId() == null || !this.id.equals( that.getId() ) ) {
            return false;
        }
        return true;
    }

    /**
     * <p>
     * Authority granted to the group
     * </p>
     */
    public String getAuthority() {
        return this.authority;
    }

    /**
     * 
     */
    public Long getId() {
        return this.id;
    }

    /**
     * Returns a hash code based on this entity's identifiers.
     */
    @Override
    public int hashCode() {
        int hashCode = 0;
        hashCode = 29 * hashCode + ( id == null ? 0 : id.hashCode() );

        return hashCode;
    }

    public void setAuthority( String authority ) {
        this.authority = authority;
    }

    public void setId( Long id ) {
        this.id = id;
    }

}