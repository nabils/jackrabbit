/* Generated By:JJTree: Do not edit this line. ASTLowerFunction.java */

package org.apache.jackrabbit.spi.commons.query.sql;

public class ASTLowerFunction extends SimpleNode {
  public ASTLowerFunction(int id) {
    super(id);
  }

  public ASTLowerFunction(JCRSQLParser p, int id) {
    super(p, id);
  }


  /** Accept the visitor. **/
  public Object jjtAccept(JCRSQLParserVisitor visitor, Object data) {
    return visitor.visit(this, data);
  }
}
