/* Generated By:JJTree: Do not edit this line. ASTAscendingOrderSpec.java */

package org.apache.jackrabbit.spi.commons.query.sql;

public class ASTAscendingOrderSpec extends SimpleNode {
  public ASTAscendingOrderSpec(int id) {
    super(id);
  }

  public ASTAscendingOrderSpec(JCRSQLParser p, int id) {
    super(p, id);
  }


  /** Accept the visitor. **/
  public Object jjtAccept(JCRSQLParserVisitor visitor, Object data) {
    return visitor.visit(this, data);
  }
}
