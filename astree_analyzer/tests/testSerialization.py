import unittest
import clang.cindex
from parser.parse import *
from unittest.mock import MagicMock


class TestASTSerializer(unittest.TestCase):
    def setUp(self):
        self.serializer = ASTSerializer()

    def create_mock_cursor(self, kind, spelling=None, type_spelling=None):
        mock_cursor = MagicMock()
        mock_cursor.kind = kind
        mock_cursor.spelling = spelling
        mock_cursor.type.spelling = type_spelling
        mock_cursor.get_children = MagicMock(return_value=iter([]))
        return mock_cursor

    def test_serialize_integer_literal(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        result = self.serializer._serialize_node(cursor)
        self.assertIn("0", result)

    def test_serialize_floating_literal(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.FLOATING_LITERAL)
        result = self.serializer._serialize_node(cursor)
        self.assertIn("0.0", result)

    def test_serialize_character_literal(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.CHARACTER_LITERAL)
        result = self.serializer._serialize_node(cursor)
        self.assertIn("'*'", result)

    def test_serialize_bool_literal(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.CXX_BOOL_LITERAL_EXPR)
        result = self.serializer._serialize_node(cursor)
        self.assertIn("false", result)

    def test_serialize_string_literal(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.STRING_LITERAL)
        result = self.serializer._serialize_node(cursor)
        self.assertIn('"str"', result)

    def test_serialize_var_decl(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var", type_spelling="int"
        )
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_int", result)

    def test_serialize_function_decl(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.FUNCTION_DECL, spelling="func", type_spelling="void"
        )
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_void", result)

    def test_serialize_binary_operator(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.BINARY_OPERATOR)
        cursor.get_tokens = MagicMock(return_value=iter([MagicMock(spelling="+")]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.BINARY_OPERATOR_+", result)

    def test_serialize_unary_operator(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.UNARY_OPERATOR)
        cursor.get_tokens = MagicMock(return_value=iter([MagicMock(spelling="++")]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.UNARY_OPERATOR_++_pre", result)

    def test_serialize_call_expr(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.CALL_EXPR, spelling="call"
        )
        cursor.displayname = "call"
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.CALL_EXPR_call", result)

    def test_serialize_array_subscript_expr(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR)
        child1 = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        child2 = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        cursor.get_children = MagicMock(return_value=iter([child1, child2]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("0[0]", result)

    def test_serialize_decl_ref_expr(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.DECL_REF_EXPR, spelling="ref", type_spelling="int"
        )
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_int", result)

    def test_serialize_parm_decl(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.PARM_DECL, spelling="param", type_spelling="int"
        )
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_int", result)

    def test_serialize_field_decl(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.FIELD_DECL, spelling="field", type_spelling="int"
        )
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_int", result)

    def test_serialize_unknown_template_argument(self):
        cursor = self.create_mock_cursor(
            ExtendedCursorKind.UNKNOWN_TEMPLATE_ARGUMENT_KIND
        )
        result = self.serializer._serialize_node(cursor)
        self.assertIn("UnknownTemplateArgument", result)

    def test_serialize_with_children(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var", type_spelling="int"
        )
        child = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        cursor.get_children = MagicMock(return_value=iter([child]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_int(0)", result)

    def test_serialize_primitive_replacement(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.STRING_LITERAL)
        result = self.serializer._serialize_node(cursor)
        self.assertIn('"str"', result)

    def test_serialize_identifier_kind(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="id", type_spelling="int"
        )
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_int", result)

    def test_serialize_binary_operator_child(self):
        parent = self.create_mock_cursor(clang.cindex.CursorKind.BINARY_OPERATOR)
        child = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        parent.get_children = MagicMock(return_value=iter([child, child]))
        result = self.serializer._serialize_node(parent)
        self.assertIn("CursorKind.BINARY_OPERATOR(0,0)", result)

    def test_serialize_unary_operator_child(self):
        parent = self.create_mock_cursor(clang.cindex.CursorKind.UNARY_OPERATOR)
        parent.get_tokens = MagicMock(return_value=iter([MagicMock(spelling="++")]))
        child = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        parent.get_children = MagicMock(return_value=iter([child]))
        result = self.serializer._serialize_node(parent)
        self.assertIn("CursorKind.UNARY_OPERATOR_++_pre(0)", result)

    def test_serialize_call_expr_child(self):
        parent = self.create_mock_cursor(
            clang.cindex.CursorKind.CALL_EXPR, spelling="call"
        )
        parent.displayname = "call"
        child = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        parent.get_children = MagicMock(return_value=iter([child]))
        result = self.serializer._serialize_node(parent)
        self.assertIn("CursorKind.CALL_EXPR_call(0)", result)

    def test_serialize_array_subscript_expr_child(self):
        parent = self.create_mock_cursor(clang.cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR)
        child = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        parent.get_children = MagicMock(return_value=iter([child, child]))
        result = self.serializer._serialize_node(parent)
        self.assertIn("0[0]", result)

    def test_serialize_with_multiple_children(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var", type_spelling="int"
        )
        child1 = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        child2 = self.create_mock_cursor(clang.cindex.CursorKind.FLOATING_LITERAL)
        cursor.get_children = MagicMock(return_value=iter([child1, child2]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_int(0,0.0)", result)

    def test_serialize_with_nested_children(self):
        parent = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var", type_spelling="int"
        )
        child = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="nested_var", type_spelling="int"
        )
        grandchild = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        child.get_children = MagicMock(return_value=iter([grandchild]))
        parent.get_children = MagicMock(return_value=iter([child]))
        result = self.serializer._serialize_node(parent)
        self.assertIn("var_0_int(var_1_int(0))", result)

    def test_serialize_function_call(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.CALL_EXPR, spelling="func"
        )
        cursor.displayname = "func"
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.CALL_EXPR_func", result)

    def test_serialize_function_call_with_args(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.CALL_EXPR, spelling="func"
        )
        cursor.displayname = "func"
        arg1 = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        arg2 = self.create_mock_cursor(clang.cindex.CursorKind.FLOATING_LITERAL)
        cursor.get_children = MagicMock(return_value=iter([arg1, arg2]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.CALL_EXPR_func(0,0.0)", result)

    def test_serialize_unknown_kind(self):
        # Create a mock cursor with a kind value that is not recognized
        cursor = self.create_mock_cursor(clang.cindex.CursorKind(9999))

        # Mock the kind and its representation
        cursor.kind = MagicMock()
        cursor.kind.value = 9999
        cursor.kind.__repr__ = lambda s: "CursorKind.UNKNOWN_KIND"
        cursor.kind.name = "UNKNOWN_KIND"

        # Serialize the node
        result = self.serializer._serialize_node(cursor)

        # Verify the serialized output
        self.assertIn("CursorKind.UNKNOWN_KIND", result)

    def test_serialize_decl_with_initializer(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var", type_spelling="int"
        )
        initializer = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        cursor.get_children = MagicMock(return_value=iter([initializer]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_int(0)", result)

    def test_serialize_if_stmt(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.IF_STMT)
        condition = self.create_mock_cursor(clang.cindex.CursorKind.BINARY_OPERATOR)
        then_branch = self.create_mock_cursor(clang.cindex.CursorKind.COMPOUND_STMT)
        else_branch = self.create_mock_cursor(clang.cindex.CursorKind.COMPOUND_STMT)
        cursor.get_children = MagicMock(
            return_value=iter([condition, then_branch, else_branch])
        )
        result = self.serializer._serialize_node(cursor)
        self.assertIn(
            "CursorKind.IF_STMT(CursorKind.BINARY_OPERATOR,CursorKind.COMPOUND_STMT,CursorKind.COMPOUND_STMT)",
            result,
        )

    def test_serialize_for_stmt(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.FOR_STMT)
        init = self.create_mock_cursor(clang.cindex.CursorKind.DECL_STMT)
        condition = self.create_mock_cursor(clang.cindex.CursorKind.BINARY_OPERATOR)
        increment = self.create_mock_cursor(clang.cindex.CursorKind.UNARY_OPERATOR)
        increment.get_tokens = MagicMock(return_value=iter([MagicMock(spelling="++")]))
        body = self.create_mock_cursor(clang.cindex.CursorKind.COMPOUND_STMT)
        cursor.get_children = MagicMock(
            return_value=iter([init, condition, increment, body])
        )
        result = self.serializer._serialize_node(cursor)
        self.assertIn(
            "CursorKind.FOR_STMT(CursorKind.DECL_STMT,CursorKind.BINARY_OPERATOR,CursorKind.UNARY_OPERATOR_++_pre,CursorKind.COMPOUND_STMT)",
            result,
        )

    def test_serialize_for_with_nested_if_stmt(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.FOR_STMT)
        init = self.create_mock_cursor(clang.cindex.CursorKind.DECL_STMT)
        condition = self.create_mock_cursor(clang.cindex.CursorKind.BINARY_OPERATOR)
        increment = self.create_mock_cursor(clang.cindex.CursorKind.UNARY_OPERATOR)
        increment.get_tokens = MagicMock(return_value=iter([MagicMock(spelling="++")]))
        body = self.create_mock_cursor(clang.cindex.CursorKind.IF_STMT)
        cursor.get_children = MagicMock(
            return_value=iter([init, condition, increment, body])
        )
        result = self.serializer._serialize_node(cursor)
        self.assertIn(
            "CursorKind.FOR_STMT(CursorKind.DECL_STMT,CursorKind.BINARY_OPERATOR,CursorKind.UNARY_OPERATOR_++_pre,CursorKind.IF_STMT)",
            result,
        )

    def test_serialize_function_decl_with_params(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.FUNCTION_DECL, spelling="func", type_spelling="void"
        )
        param1 = self.create_mock_cursor(
            clang.cindex.CursorKind.PARM_DECL, spelling="param1", type_spelling="int"
        )
        param2 = self.create_mock_cursor(
            clang.cindex.CursorKind.PARM_DECL, spelling="param2", type_spelling="float"
        )
        cursor.get_children = MagicMock(return_value=iter([param1, param2]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_void(var_1_int,var_2_float)", result)

    def test_serialize_function_decl_with_body(self):
        cursor = self.create_mock_cursor(
            clang.cindex.CursorKind.FUNCTION_DECL, spelling="func", type_spelling="void"
        )
        body = self.create_mock_cursor(clang.cindex.CursorKind.COMPOUND_STMT)
        cursor.get_children = MagicMock(return_value=iter([body]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("var_0_void(CursorKind.COMPOUND_STMT)", result)

    def test_serialize_decl_stmt(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.DECL_STMT)
        decl = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var", type_spelling="int"
        )
        cursor.get_children = MagicMock(return_value=iter([decl]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.DECL_STMT(var_0_int)", result)

    def test_serialize_decl_stmt_with_multiple_var_decl(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.DECL_STMT)
        var_decl1 = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var1", type_spelling="int"
        )
        var_decl2 = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var2", type_spelling="float"
        )
        cursor.get_children = MagicMock(return_value=iter([var_decl1, var_decl2]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.DECL_STMT(var_0_int,var_1_float)", result)

    def test_serialize_expr_stmt(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.UNEXPOSED_EXPR)
        expr = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        cursor.get_children = MagicMock(return_value=iter([expr]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.UNEXPOSED_EXPR(0)", result)

    def test_serialize_return_stmt(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.RETURN_STMT)
        expr = self.create_mock_cursor(clang.cindex.CursorKind.INTEGER_LITERAL)
        cursor.get_children = MagicMock(return_value=iter([expr]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.RETURN_STMT(0)", result)

    def test_serialize_return_with_expression(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.RETURN_STMT)
        expr = self.create_mock_cursor(clang.cindex.CursorKind.BINARY_OPERATOR)
        cursor.get_children = MagicMock(return_value=iter([expr]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.RETURN_STMT(CursorKind.BINARY_OPERATOR)", result)

    def test_serialize_compound_stmt_with_expr(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.COMPOUND_STMT)
        expr_stmt = self.create_mock_cursor(clang.cindex.CursorKind.UNEXPOSED_EXPR)
        cursor.get_children = MagicMock(return_value=iter([expr_stmt]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.COMPOUND_STMT(CursorKind.UNEXPOSED_EXPR)", result)

    def test_serialize_decl_stmt_with_var_decl(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.DECL_STMT)
        var_decl = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var", type_spelling="int"
        )
        cursor.get_children = MagicMock(return_value=iter([var_decl]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.DECL_STMT(var_0_int)", result)

    def test_serialize_decl_stmt_with_multiple_var_decl(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.DECL_STMT)
        var_decl1 = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var1", type_spelling="int"
        )
        var_decl2 = self.create_mock_cursor(
            clang.cindex.CursorKind.VAR_DECL, spelling="var2", type_spelling="float"
        )
        cursor.get_children = MagicMock(return_value=iter([var_decl1, var_decl2]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.DECL_STMT(var_0_int,var_1_float)", result)

    def test_serialize_decl_stmt_with_nested_compound_stmt(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.DECL_STMT)
        compound_stmt = self.create_mock_cursor(clang.cindex.CursorKind.COMPOUND_STMT)
        cursor.get_children = MagicMock(return_value=iter([compound_stmt]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn("CursorKind.DECL_STMT(CursorKind.COMPOUND_STMT)", result)

    def test_serialize_if_with_nested_compound_stmt(self):
        cursor = self.create_mock_cursor(clang.cindex.CursorKind.IF_STMT)
        condition = self.create_mock_cursor(clang.cindex.CursorKind.BINARY_OPERATOR)
        then_branch = self.create_mock_cursor(clang.cindex.CursorKind.COMPOUND_STMT)
        cursor.get_children = MagicMock(return_value=iter([condition, then_branch]))
        result = self.serializer._serialize_node(cursor)
        self.assertIn(
            "CursorKind.IF_STMT(CursorKind.BINARY_OPERATOR,CursorKind.COMPOUND_STMT)",
            result,
        )


if __name__ == "__main__":
    unittest.main()
