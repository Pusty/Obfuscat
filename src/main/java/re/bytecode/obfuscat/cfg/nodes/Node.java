package re.bytecode.obfuscat.cfg.nodes;

import java.util.ArrayList;
import java.util.List;

/**
 * A node is an abstraction from one "instruction" / operation
 */
public abstract class Node {
	
	/**
	 * Return a list of all nodes recursively references by this node or their children
	 * @return a list containing all in some way referenced nodes
	 */
	public List<Node> list() {
		ArrayList<Node> l = new ArrayList<Node>();
		
		Node[] children = children();
		if(children != null)
			for(Node c:children) {
				l.addAll(c.list());
			}
		l.add(this);
		return l;
	}
	
	@Override
	public String toString() {
		return "Generic";
	}
	
	/**
	 * Check if this node matches semantically with another node (or with NodeDummy wildcards)
	 * @param o the comparison node
	 * @return whether the nodes semantically match
	 */
	public boolean equalsSemantics(Object o) {
		
	    if (this == o) // if both nodes are the same they match in behavior
	        return true;
	    if (o == null) // if one node is null then they can't match
	        return false;
	    
	    if(o.getClass() == NodeDummy.class) return true; // for pattern matching / wildcard usage
	    
	    if (getClass() != o.getClass()) // if they aren't the same time they can't match
	        return false;
	    
	    if(!checkCriteria((Node) o)) return false; // if their internal non-node specific behavior doesn't match they can't match
		
	    Node[] own = children();
	    Node[] nodes = ((Node) o).children();
	    
	    if(own == null && nodes == null) return true; // if there are no children they match at this point 
	    if((own == null) != (nodes == null)) return false; // if only one has children then they can't match
	    if(nodes.length != own.length) return false; // if the amount of children doesn't match they can't match
	    
	    for(int i=0;i<own.length;i++) {
	    	if(!own[i].equalsSemantics(nodes[i])) return false; // if one child doesn't sementically match then this can't match
	    }
	    
	    return true; // if everything is equal they match
	}

	// Check if internal non-node related behavior matches
	protected boolean checkCriteria(Node o) { return true; }
	
	/**
	 * Replace null nodes with NodeDummy, used for wildcard search and replace operations
	 */
	public abstract  void dumify();
	
	/**
	 * Replace a reference to a search node with the replace node. Also recursively traverse the nodes for references for the search needle.
	 * @param search the needle to search and replace
	 * @param replace the replacement node
	 * @return this object but updated
	 */
	public abstract Node replace(Node search, Node replace);
	
	/**
	 * Return the children of this node
	 * @return the array of children this node references
	 */
	public Node[] children() { return null; }
}
