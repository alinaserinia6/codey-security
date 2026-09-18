"""
Code Analyst Agent - Focused on static code analysis and code quality assessment
"""

import os
from typing import Dict, List, Any
from pathlib import Path
from tree_sitter import Language, Parser
import tree_sitter_cpp as tscpp

class CodeAnalystAgent:
    """Code Analyst Agent, responsible for static code analysis"""
    
    def __init__(self, llm_config: Dict[str, Any]):
        self.llm_config = llm_config
        self.name = "Code Analyst"
        self.role = "Static code analysis and code quality assessment"
        
        # Initialize Tree-sitter parser
        self.language = Language(tscpp.language())
        self.parser = Parser(self.language)
        
    def analyze_code_file(self, file_path: str) -> Dict[str, Any]:
        """Analyse a single code file"""
        
        if not os.path.exists(file_path):
            return {"error": f"File does not exist: {file_path}"}
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
                
            # Parse code with Tree-sitter
            tree = self.parser.parse(bytes(code_content, 'utf-8'))
            
            analysis_result = {
                "file_path": file_path,
                "file_size": len(code_content),
                "line_count": code_content.count('\n') + 1,
                "functions": self._extract_functions(tree.root_node, code_content),
                "classes": self._extract_classes(tree.root_node, code_content),
                "includes": self._extract_includes(tree.root_node, code_content),
                "complexity_metrics": self._calculate_complexity(tree.root_node, code_content),
                "potential_issues": self._identify_issues(tree.root_node, code_content)
            }
            
            return analysis_result
            
        except Exception as e:
            return {"error": f"Error while analysing file: {str(e)}"}
    
    def _extract_functions(self, node, code_content: str) -> List[Dict[str, Any]]:
        """Extract function information"""
        functions = []
        
        def traverse(node):
            if node.type == 'function_definition':
                # Get function name
                name_node = None
                for child in node.children:
                    if child.type == 'function_declarator':
                        for subchild in child.children:
                            if subchild.type == 'identifier':
                                name_node = subchild
                                break
                        break
                
                if name_node:
                    func_info = {
                        "name": code_content[name_node.start_byte:name_node.end_byte],
                        "start_line": node.start_point[0] + 1,
                        "end_line": node.end_point[0] + 1,
                        "line_count": node.end_point[0] - node.start_point[0] + 1,
                        "parameters": self._extract_parameters(node, code_content),
                        "return_type": self._extract_return_type(node, code_content)
                    }
                    functions.append(func_info)
            
            for child in node.children:
                traverse(child)
        
        traverse(node)
        return functions
    
    def _extract_classes(self, node, code_content: str) -> List[Dict[str, Any]]:
        """Extract class information"""
        classes = []
        
        def traverse(node):
            if node.type == 'class_specifier':
                name_node = None
                for child in node.children:
                    if child.type == 'type_identifier':
                        name_node = child
                        break
                
                if name_node:
                    class_info = {
                        "name": code_content[name_node.start_byte:name_node.end_byte],
                        "start_line": node.start_point[0] + 1,
                        "end_line": node.end_point[0] + 1,
                        "line_count": node.end_point[0] - node.start_point[0] + 1,
                        "methods": self._extract_class_methods(node, code_content),
                        "members": self._extract_class_members(node, code_content)
                    }
                    classes.append(class_info)
            
            for child in node.children:
                traverse(child)
        
        traverse(node)
        return classes
    
    def _extract_includes(self, node, code_content: str) -> List[str]:
        """Extract included header files"""
        includes = []
        
        def traverse(node):
            if node.type == 'preproc_include':
                include_text = code_content[node.start_byte:node.end_byte]
                includes.append(include_text.strip())
            
            for child in node.children:
                traverse(child)
        
        traverse(node)
        return includes
    
    def _calculate_complexity(self, node, code_content: str) -> Dict[str, Any]:
        """Calculate code complexity metrics"""
        
        complexity_metrics = {
            "cyclomatic_complexity": 0,
            "nesting_depth": 0,
            "function_count": 0,
            "class_count": 0,
            "max_function_length": 0
        }
        
        # Simplified cyclomatic complexity calculation
        decision_points = 0
        max_depth = 0
        current_depth = 0
        
        def traverse(node):
            nonlocal decision_points, max_depth, current_depth
            
            # Decision point nodes
            if node.type in ['if_statement', 'while_statement', 'for_statement', 
                           'switch_statement', 'case_statement', 'conditional_expression']:
                decision_points += 1
            
            # Nesting depth
            if node.type in ['compound_statement', 'if_statement', 'while_statement', 'for_statement']:
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            
            for child in node.children:
                traverse(child)
            
            if node.type in ['compound_statement', 'if_statement', 'while_statement', 'for_statement']:
                current_depth -= 1
        
        traverse(node)
        
        complexity_metrics["cyclomatic_complexity"] = decision_points + 1
        complexity_metrics["nesting_depth"] = max_depth
        
        return complexity_metrics
    
    def _identify_issues(self, node, code_content: str) -> List[Dict[str, Any]]:
        """Identify potential code issues"""
        issues = []
        
        def traverse(node):
            # Check for overlong functions
            if node.type == 'function_definition':
                line_count = node.end_point[0] - node.start_point[0] + 1
                if line_count > 50:
                    issues.append({
                        "type": "long_function",
                        "severity": "warning",
                        "line": node.start_point[0] + 1,
                        "message": f"Function is too long ({line_count} lines), consider splitting it"
                    })
            
            # Check for deep nesting
            if self._calculate_nesting_depth(node) > 4:
                issues.append({
                    "type": "deep_nesting",
                    "severity": "warning", 
                    "line": node.start_point[0] + 1,
                    "message": "Nesting depth is too deep, affecting code readability"
                })
            
            for child in node.children:
                traverse(child)
        
        traverse(node)
        return issues
    
    def _calculate_nesting_depth(self, node) -> int:
        """Calculate the nesting depth of a node"""
        if not node.children:
            return 0
        
        max_child_depth = 0
        for child in node.children:
            if child.type in ['compound_statement', 'if_statement', 'while_statement', 'for_statement']:
                child_depth = self._calculate_nesting_depth(child)
                max_child_depth = max(max_child_depth, child_depth)
        
        if node.type in ['compound_statement', 'if_statement', 'while_statement', 'for_statement']:
            return max_child_depth + 1
        else:
            return max_child_depth
    
    def _extract_parameters(self, node, code_content: str) -> List[str]:
        """Extract function parameters"""
        # Simplified implementation; more complex parsing would be needed in practice
        return []
    
    def _extract_return_type(self, node, code_content: str) -> str:
        """Extract function return type"""
        # Simplified implementation; more complex parsing would be needed in practice
        return "unknown"
    
    def _extract_class_methods(self, node, code_content: str) -> List[str]:
        """Extract class methods"""
        # Simplified implementation; more complex parsing would be needed in practice
        return []
    
    def _extract_class_members(self, node, code_content: str) -> List[str]:
        """Extract class member variables"""
        # Simplified implementation; more complex parsing would be needed in practice
        return []
    
    def generate_analysis_report(self, analysis_result: Dict[str, Any]) -> str:
        """Generate analysis report"""
        
        if "error" in analysis_result:
            return f"Analysis failed: {analysis_result['error']}"
        
        report = f"""
        ## Code Analysis Report - {analysis_result['file_path']}

        ### Basic Information
        - File size: {analysis_result['file_size']} bytes
        - Lines of code: {analysis_result['line_count']} lines
        - Number of functions: {len(analysis_result['functions'])}
        - Number of classes: {len(analysis_result['classes'])}

        ### Complexity Metrics
        - Cyclomatic complexity: {analysis_result['complexity_metrics']['cyclomatic_complexity']}
        - Maximum nesting depth: {analysis_result['complexity_metrics']['nesting_depth']}

        ### Included Headers
        {chr(10).join(f"- {inc}" for inc in analysis_result['includes'])}

        ### Function List
        {chr(10).join(f"- {func['name']} (lines {func['start_line']}-{func['end_line']})" for func in analysis_result['functions'])}

        ### Potential Issues
        {chr(10).join(f"- Line {issue['line']}: {issue['message']} ({issue['severity']})" for issue in analysis_result['potential_issues'])}

        ### Recommendations
        1. Keep function length moderate (recommended no more than 50 lines)
        2. Reduce nesting depth (recommended no more than 4 levels)
        3. Add appropriate comments and documentation
        4. Consider refactoring complex functions
        """
        
        return report
 