package com.pf.permissions;

import java.util.logging.Level;

import org.neo4j.graphdb.RelationshipType;

/**
 * Configuration 
 * @author Phillip Friedrich
 *
 */
public class Configuration {
	/**
	 * Maximal pathlength for permission Resolution
	 */
	public static final Integer maxDepth = 20;
	
	/**
	 * Configure logger
	 */
	public static final Level loggingLevel = Level.ALL;
	
	/**
	 * Relationship Types to follow
	 */
	public enum Relationships implements RelationshipType {
		SECURITY,
		SUBRESOURCE,
		IS_MEMBER_OF
	}
}
