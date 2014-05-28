/*
 * The Gemma project
 * 
 * Copyright (c) 2011 University of British Columbia
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
package gemma.gsec.model;

/**
 * @author pavlidis
 * @version $Id: PersonImpl.java,v 1.2 2013/09/23 07:38:52 paul Exp $
 */
public class PersonImpl extends Person {
    /** The serial version UID of this class. Needed for serialization. */
    private static final long serialVersionUID = -3335182453066930211L;

    /**
     * @see ubic.gemma.model.common.auditAndSecurity.Person#getFullName()
     */
    @Override
    public String getFullName() {
        return this.getName() + " " + this.getLastName();
    }

}