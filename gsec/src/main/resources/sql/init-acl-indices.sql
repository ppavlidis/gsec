alter table ACLOBJECTIDENTITY add unique key acloid (OBJECT_CLASS,OBJECT_ID);
alter table ACLOBJECTIDENTITY add key objectclasskey (OBJECT_CLASS);
alter table ACLOBJECTIDENTITY add key oidkey (OBJECT_ID);
