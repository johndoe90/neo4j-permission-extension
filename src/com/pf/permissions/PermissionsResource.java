package com.pf.permissions;

import java.nio.charset.Charset;
import java.util.logging.Logger;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.neo4j.graphalgo.GraphAlgoFactory;
import org.neo4j.graphdb.Direction;
import org.neo4j.graphdb.DynamicLabel;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Label;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Path;
import org.neo4j.graphdb.PathExpander;
import org.neo4j.graphdb.PathExpanders;
import org.neo4j.graphdb.Relationship;
import org.neo4j.graphdb.ResourceIterator;
import org.neo4j.graphdb.Transaction;

/**
 * Neo4j Server Unmanages Extension
 * Resolves permissions a certain principal has for a given resource and its subresources.
 * 
 * @author Phillip Friedrich
 *
 */
@javax.ws.rs.Path( "/permissions" )
public class PermissionsResource {
	private final GraphDatabaseService database;
	private static final Logger logger = Logger.getLogger("com.pf.permissions");
	
	public PermissionsResource( @Context GraphDatabaseService database ) {
		this.database = database;
		
		logger.setLevel(Configuration.loggingLevel);
	}
	
	/**
	 * Performs a logical "OR" on each char
	 * @param a - 4 chars long permission String (only 1 or 0)
	 * @param b - 4 chars long permission String (only 1 or 0)
	 * @return - resulting permissions
	 */
	private String mergePermissions(String a, String b) {
		if ( a == null || b == null || a.length() != 4 || b.length() != 4 || !(a + b).matches("[0-1]+")) {
			return "0000";
		}

		String permissions = "";
		for ( int i = 0; i < 4; i++ ) {
			if (a.charAt(i) == '1' || b.charAt(i) == '1') {
				permissions += "1";
			} else {
				permissions += "0";
			}
		}
		
		return permissions;
	}
	
	/**
	 * Checks if String is null or empty
	 * @param value
	 * @return true if value is null or empty, otherwise false
	 */
	private boolean nullOrEmpty(String value) {
		return value == null || value.trim().isEmpty();
	}
	
	/**
	 * Finds the resource with the given properties
	 * @param id - unique resourceId
	 * @param label - resourceLabel
	 * @param idProperty - resourceIdProperty
	 * @return the found resource or null
	 */
	private Node findResource(String id, String label, String idProperty) {
		Node resource = null;
		Label resourceLabel = DynamicLabel.label(label);
		try ( ResourceIterator<Node> resources = database.findNodesByLabelAndProperty(resourceLabel, idProperty, id).iterator() ) {
			if ( resources.hasNext() ) {
				resource = resources.next();
			}
		} 
		
		return resource;
	}
	
	/**
	 * Finds the principal with the given properties
	 * @param id - unique principalId
	 * @param label - principalLabel
	 * @param idProperty - principalIdProperty
	 * @return the found principal or null
	 */
	private Node findPrincipal(String id, String label, String idProperty) {
		Node principal = null;
		Label principalLabel = DynamicLabel.label(label);
		try ( ResourceIterator<Node> principals = database.findNodesByLabelAndProperty(principalLabel, idProperty, id).iterator() ) {
			if ( principals.hasNext() ) {
				principal = principals.next();
			}
		}
		
		return principal;
	}
	
	/**
	 * Build Response object
	 * @param status - HTTP Status
	 * @param body - Response body
	 * @return response object
	 */
	private Response respond(Status status, String body) {
		return Response
				.status( status )
				.header( "Content-Type", "text/plain" )
				.entity( body.getBytes( Charset.forName("UTF-8") ) )
				.build();
	}
	
	/**
	 * Finds all paths between the two nodes
	 * @param startNode
	 * @param endNode
	 * @return all found paths
	 */
	private Iterable<Path> findAllPaths(Node start, Node end) {
		PathExpander<Object> expander = PathExpanders.forTypesAndDirections(
				Configuration.Relationships.SECURITY, Direction.INCOMING, 
				Configuration.Relationships.SUBRESOURCE, Direction.INCOMING, 
				Configuration.Relationships.IS_MEMBER_OF, Direction.INCOMING);
		
		return GraphAlgoFactory.allPaths(expander, Configuration.maxDepth).findAllPaths(start, end);
	}
	
	/**
	 * Get permissions the principal has for the given resource
	 * @param resource - resource Node
	 * @param principal - principal Node
	 * @return permissions
	 */
	private String getPermissions(Node resource, Node principal) {
		String permissions = "0000";
		for ( Path path : findAllPaths(resource, principal) ) {
			Iterable<Relationship> relationships = path.relationships();
			for ( Relationship relationship : relationships ) {
				if ( relationship.getType().name().equals(Configuration.Relationships.SECURITY.toString()) ) {
					permissions = mergePermissions(permissions, relationship.getProperty("permissions").toString());
				}
			}
		}
		
		return permissions;
	}
	
	/**
	 * HTTP endpoint to request the permissions a given principal has for a given resource
	 * 
	 * @param resourceId
	 * @param resourceLabel
	 * @param resourceIdProperty
	 * @param principalId
	 * @param principalLabel
	 * @param principalIdProperty
	 * @return HTTP Status OK (200) if everything worked, 
	 * 		   HTTP Status INTERNAL_SERVER_ERROR (500) if something went wrong,
	 * 		   HTTP Status NOT_FOUND (404) if the resource or principal was not found,
	 * 		   HTTP Status BAD_REQUEST (400) if not all required parameters were set in the request
	 */
	@GET
	public Response permissions( 
			@QueryParam("resourceId") String resourceId,
			@QueryParam("resourceLabel") String resourceLabel,
			@DefaultValue("id") @QueryParam("resourceIdProperty") String resourceIdProperty,
			
			@QueryParam("principalId") String principalId,
			@DefaultValue("Principal") @QueryParam("principalLabel") String principalLabel,
			@DefaultValue("id") @QueryParam("principalIdProperty") String principalIdProperty) {
		
		if ( nullOrEmpty(resourceId) || nullOrEmpty(resourceLabel) || nullOrEmpty(principalId) ) {
			return respond( Status.BAD_REQUEST, "QueryParams resourceId, resourceLabel and principalId are not optional" );
		}
		
		try ( Transaction tx = database.beginTx() ) {	
			Node resource = findResource(resourceId, resourceLabel, resourceIdProperty),
				 principal = findPrincipal(principalId, principalLabel, principalIdProperty);
			
			if ( resource == null || principal == null ) {
				return respond( Status.NOT_FOUND, "resource or principal not found" );
			}
			
			String permissions = getPermissions(resource, principal);
			
			tx.success();
			
			return respond( Status.OK, permissions );
		} catch (Exception e) {
			return respond( Status.INTERNAL_SERVER_ERROR, e.getMessage() );
		}
	}
}
