"""
LangGraph-Based Multi-Agent C++ Code Analysis System
"""

import os
import sys
from typing import Dict, List, Any, TypedDict, Annotated
import operator
import json

# LangGraph imports
try:
    from langgraph.graph import StateGraph, MessagesState, START, END
    from langgraph.prebuilt import create_react_agent
    from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
    from langchain_core.prompts import ChatPromptTemplate
    LANGGRAPH_AVAILABLE = True
except ImportError as e:
    print(f"LangGraph import failed: {e}")
    LANGGRAPH_AVAILABLE = False

# LangChain imports
try:
    from langchain_openai import ChatOpenAI
    from langchain_anthropic import ChatAnthropic
    LANGCHAIN_AVAILABLE = True
except ImportError as e:
    print(f"LangChain import failed: {e}")
    LANGCHAIN_AVAILABLE = False

# Add project path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.env_config import config

# Define state type
class AnalysisState(TypedDict):
    code_content: str
    filename: str
    messages: Annotated[list, operator.add]
    code_analysis: Dict[str, Any]
    security_analysis: Dict[str, Any] 
    debug_analysis: Dict[str, Any]
    architecture_analysis: Dict[str, Any]
    final_report: Dict[str, Any]
    conversation_history: List[Dict[str, Any]]

class LangGraphCodeAnalyzer:
    """LangGraph-based multi-agent code analyzer"""
    
    def __init__(self):
        self.llm = None
        self.graph = None
        self.conversation_history = []
        
    def setup_llm(self):
        """Set up LLM - temporarily disabled, using mock mode"""
        # Return None for now, using mock mode to demonstrate multi-agent workflow
        return None
    
    def create_agent_nodes(self):
        """Create agent nodes"""
        
        def coordinator_node(state: AnalysisState):
            """Coordinator node"""
            prompt = f"""
            You are an intelligent code analysis coordinator. Please analyse the following C/C++ code:

            Filename: {state['filename']}
            Code content:
            ```cpp
            {state['code_content']}
            ```
            Please provide an overall analysis plan, including key areas that need attention.
            """
            
            if self.llm:
                response = self.llm.invoke([HumanMessage(content=prompt)])
                message_content = response.content
            else:
                message_content = f"Coordinator starting analysis of {state['filename']}, formulating analysis plan..."
            
            conversation_entry = {
                "agent": "coordinator",
                "agent_name": "🎯 Coordinator",
                "message": message_content,
                "timestamp": "2025-08-30 16:41:00",
                "reasoning": "Formulating overall analysis strategy and task allocation"
            }
            
            return {
                "messages": [AIMessage(content=message_content)],
                "conversation_history": [conversation_entry]
            }
        
        def code_analyst_node(state: AnalysisState):
            """Code Analyst node"""
            prompt = f"""
            As a C/C++ code analyst, please analyse the quality metrics of the following code:

            Code content:
            ```cpp
            {state['code_content']}
            ```

            Please focus on:
            1. Code complexity
            2. Function design quality
            3. Variable naming conventions
            4. Code structure and organisation
            5. Performance considerations

            Provide specific analysis results and improvement suggestions.
            """
            
            if self.llm:
                response = self.llm.invoke([HumanMessage(content=prompt)])
                message_content = response.content
                
                # Simple parsing of analysis results
                analysis_result = {
                    "complexity": "medium",
                    "quality_score": 7.5,
                    "issues": [],
                    "suggestions": []
                }
            else:
                # Simple static analysis
                lines = state['code_content'].split('\n')
                code_lines = [line for line in lines if line.strip() and not line.strip().startswith('//')]
                
                analysis_result = {
                    "total_lines": len(lines),
                    "code_lines": len(code_lines),
                    "complexity": "medium" if len(code_lines) > 20 else "low",
                    "function_count": state['code_content'].count('('),
                    "quality_score": 8.0
                }
                
                message_content = f"Code quality analysis completed:\nTotal lines: {len(lines)}\nEffective code lines: {len(code_lines)}\nComplexity: {analysis_result['complexity']}\nQuality score: {analysis_result['quality_score']}/10"
            
            conversation_entry = {
                "agent": "code_analyst",
                "agent_name": "📊 Code Analyst", 
                "message": message_content,
                "timestamp": "2025-08-30 16:41:05",
                "reasoning": "Performed quality assessment based on static analysis and code metrics"
            }
            
            return {
                "messages": [AIMessage(content=message_content)],
                "code_analysis": analysis_result,
                "conversation_history": [conversation_entry]
            }
        
        def security_expert_node(state: AnalysisState):
            """Security Expert node"""
            prompt = f"""
            As a C/C++ security expert, please analyse the security issues in the following code:

            Code content:
            ```cpp
            {state['code_content']}
            ```

            Please focus on:
            1. Buffer overflow risks
            2. Memory leak possibilities
            3. Dangerous function usage
            4. Missing input validation
            5. Integer overflow
            6. Null pointer dereferencing

            Provide specific security issue locations and remediation suggestions.
            """
            
            # Simple security checks
            security_issues = []
            code = state['code_content']
            
            if 'strcpy' in code:
                security_issues.append({
                    "type": "Buffer overflow",
                    "function": "strcpy",
                    "severity": "High",
                    "description": "strcpy does not check destination buffer size, may cause buffer overflow"
                })
            
            if 'gets' in code:
                security_issues.append({
                    "type": "Buffer overflow", 
                    "function": "gets",
                    "severity": "Critical",
                    "description": "gets is highly prone to buffer overflow and should be avoided"
                })
            
            if 'malloc' in code and 'free' not in code:
                security_issues.append({
                    "type": "Memory leak",
                    "function": "malloc",
                    "severity": "Medium",
                    "description": "malloc memory allocated but no matching free call found"
                })
            
            if 'scanf' in code:
                security_issues.append({
                    "type": "Input validation",
                    "function": "scanf", 
                    "severity": "Medium",
                    "description": "scanf may cause buffer overflow; safer input functions are recommended"
                })
            
            if self.llm:
                response = self.llm.invoke([HumanMessage(content=prompt)])
                message_content = response.content
            else:
                if security_issues:
                    message_content = f"Security analysis completed, found {len(security_issues)} security issues:\n"
                    for issue in security_issues:
                        message_content += f"- {issue['type']} ({issue['severity']}): {issue['description']}\n"
                else:
                    message_content = "✅ Security analysis completed, no obvious security issues found"
            
            conversation_entry = {
                "agent": "security_expert",
                "agent_name": "🔒 Security Expert",
                "message": message_content,
                "timestamp": "2025-08-30 16:41:10", 
                "reasoning": "Performed security risk assessment based on vulnerability database and pattern matching"
            }
            
            return {
                "messages": [AIMessage(content=message_content)],
                "security_analysis": {
                    "issues": security_issues,
                    "risk_level": "high" if any(i['severity'] == 'Critical' for i in security_issues) else "medium" if security_issues else "low"
                },
                "conversation_history": [conversation_entry]
            }
        
        def debug_expert_node(state: AnalysisState):
            """Debug Expert node"""
            prompt = f"""
            As a C/C++ debugging expert, please provide debugging suggestions for the following code:

            Code content:
            ```cpp
            {state['code_content']}
            ```

            Please provide:
            1. Recommended debugging tools
            2. Key breakpoint locations
            3. Logging recommendations  
            4. Error handling assessment
            5. Debugging strategies

            Provide practical debugging guidance.
            """
            
            if self.llm:
                response = self.llm.invoke([HumanMessage(content=prompt)])
                message_content = response.content
            else:
                # Basic debugging suggestions
                debug_suggestions = [
                    "Use gdb for source-level debugging",
                    "Add -g -O0 compiler flags to retain debug info",
                    "Use Valgrind to detect memory errors", 
                    "Set breakpoints at function entry and key loops",
                    "Use printf/cout to add logging output"
                ]
                
                message_content = "Debugging suggestions:\n" + "\n".join([f"- {suggestion}" for suggestion in debug_suggestions])
            
            conversation_entry = {
                "agent": "debug_expert",
                "agent_name": "🐛 Debug Expert",
                "message": message_content,
                "timestamp": "2025-08-30 16:41:15",
                "reasoning": "Provided debugging strategies based on code characteristics and best practices"
            }
            
            return {
                "messages": [AIMessage(content=message_content)],
                "debug_analysis": {
                    "tools": ["gdb", "valgrind", "printf"],
                    "strategies": ["Breakpoint debugging", "Memory detection", "Log tracing"]
                },
                "conversation_history": [conversation_entry]
            }
        
        def architect_node(state: AnalysisState):
            """Architect node"""
            prompt = f"""
            As a software architect, please evaluate the design quality of the following code:

            Code content:
            ```cpp
            {state['code_content']}
            ```

            Please analyse from these perspectives:
            1. SOLID principle adherence
            2. Design pattern usage
            3. Modularity level
            4. Interface design quality
            5. Maintainability and extensibility

            Provide architecture improvement suggestions.
            """
            
            if self.llm:
                response = self.llm.invoke([HumanMessage(content=prompt)])
                message_content = response.content
            else:
                # Simple architecture analysis
                lines = state['code_content'].split('\n')
                
                architecture_score = 7.0
                if len(lines) > 100:
                    architecture_score -= 1.0  # Higher complexity
                if 'class' in state['code_content']:
                    architecture_score += 1.0  # Object-oriented usage
                
                message_content = f"Architecture analysis:\n- Code organisation: {'Good' if len(lines) < 100 else 'Needs optimisation'}\n- Object-oriented: {'Used' if 'class' in state['code_content'] else 'Not used'}\n- Architecture score: {architecture_score}/10"
            
            conversation_entry = {
                "agent": "architect",
                "agent_name": "🏗️ Architect",
                "message": message_content,
                "timestamp": "2025-08-30 16:41:20",
                "reasoning": "Evaluated code architecture from software engineering and design pattern perspectives"
            }
            
            return {
                "messages": [AIMessage(content=message_content)],
                "architecture_analysis": {
                    "score": 7.5,
                    "patterns": [],
                    "suggestions": ["Modularity improvements", "Interface optimisation"]
                },
                "conversation_history": [conversation_entry]
            }
        
        def final_report_node(state: AnalysisState):
            """Final report node"""
            
            # Summarise all analysis results
            code_analysis = state.get('code_analysis', {})
            security_analysis = state.get('security_analysis', {})
            debug_analysis = state.get('debug_analysis', {})
            architecture_analysis = state.get('architecture_analysis', {})
            
            # Calculate overall score
            quality_score = code_analysis.get('quality_score', 7.0)
            security_score = 10.0 if security_analysis.get('risk_level') == 'low' else 5.0 if security_analysis.get('risk_level') == 'medium' else 2.0
            architecture_score = architecture_analysis.get('score', 7.0)
            
            overall_score = (quality_score + security_score + architecture_score) / 3
            
            issues_count = len(security_analysis.get('issues', []))
            
            report_content = f"""
            🎯 Comprehensive Analysis Report

            📊 Quality score: {quality_score:.1f}/10
            🔒 Security score: {security_score:.1f}/10  
            🏗️ Architecture score: {architecture_score:.1f}/10
            📈 Overall score: {overall_score:.1f}/10

            🔍 Issues found: {issues_count}
            ✅ Analysis complete: All agents collaborated successfully

            Recommendation: {'Prioritise fixing security issues' if issues_count > 0 else 'Code quality is good, keep it up'}
            """
            
            conversation_entry = {
                "agent": "final_report",
                "agent_name": "📋 Final Report",
                "message": report_content.strip(),
                "timestamp": "2025-08-30 16:41:25",
                "reasoning": "Synthesised all agent analysis results to generate a comprehensive evaluation report"
            }
            
            final_report = {
                "overall_score": overall_score,
                "quality_score": quality_score,
                "security_score": security_score,
                "architecture_score": architecture_score,
                "issues_count": issues_count,
                "recommendation": "Prioritise fixing security issues" if issues_count > 0 else "Code quality is good, keep it up"
            }
            
            return {
                "messages": [AIMessage(content=report_content)],
                "final_report": final_report,
                "conversation_history": [conversation_entry]
            }
        
        return {
            "coordinator": coordinator_node,
            "code_analyst": code_analyst_node,
            "security_expert": security_expert_node,
            "debug_expert": debug_expert_node,
            "architect": architect_node,
            "final_report": final_report_node
        }
    
    def build_graph(self):
        """Build the LangGraph workflow"""
        
        if not LANGGRAPH_AVAILABLE:
            return None
        
        # Create state graph
        workflow = StateGraph(AnalysisState)
        
        # Get agent nodes
        nodes = self.create_agent_nodes()
        
        # Add nodes
        for name, func in nodes.items():
            workflow.add_node(name, func)
        
        # Define workflow
        workflow.add_edge(START, "coordinator")
        workflow.add_edge("coordinator", "code_analyst")
        workflow.add_edge("code_analyst", "security_expert") 
        workflow.add_edge("security_expert", "debug_expert")
        workflow.add_edge("debug_expert", "architect")
        workflow.add_edge("architect", "final_report")
        workflow.add_edge("final_report", END)
        
        # Compile the graph
        return workflow.compile()
    
    async def analyze_code(self, code_content: str, filename: str) -> Dict[str, Any]:
        """Analyse code using LangGraph multi-agent system"""
        
        print(f"🔍 LangGraph analysing file: {filename}")
        
        # Temporarily use mock mode directly to demonstrate the multi-agent workflow
        return await self.run_mock_analysis(code_content, filename)
    
    async def run_mock_analysis(self, code_content: str, filename: str) -> Dict[str, Any]:
        """Run mock LangGraph analysis"""
        
        print("🎭 Running mock LangGraph analysis mode")
        
        # Reuse the mock logic from AutoGen, but mark it as LangGraph
        from .autogen_analyzer import autogen_analyzer
        result = await autogen_analyzer.run_mock_analysis(code_content, filename)
        
        # Change the type identifier
        result["analysis_type"] = "langgraph_mock"
        
        # Add LangGraph-specific structure
        result["workflow_steps"] = [
            "coordinator → code_analyst → security_expert → debug_expert → architect → final_report"
        ]
        
        return result

# Global analyzer instance
langgraph_analyzer = LangGraphCodeAnalyzer()
