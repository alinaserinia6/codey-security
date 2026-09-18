"""
Coordinator Agent - Manages and coordinates the workflow of other agents
"""

import asyncio
from typing import List, Dict, Any
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.base import TaskResult

class CoordinatorAgent:
    """Coordinator Agent, responsible for managing the multi-agent collaboration process"""
    
    def __init__(self, llm_config: Dict[str, Any]):
        self.llm_config = llm_config
        self.agents: List[AssistantAgent] = []
        self.current_task = None
        
    def add_agent(self, agent: AssistantAgent):
        """Add an agent to the collaboration team"""
        self.agents.append(agent)
        
    async def coordinate_analysis(self, code_path: str, task_description: str) -> Dict[str, Any]:
        """Coordinate multi-agent code analysis"""
        
        # Create agent team
        team = RoundRobinGroupChat(self.agents)
        
        # Build analysis task
        analysis_prompt = f"""
        Please perform a comprehensive analysis of the following C/C++ code file: {code_path}
        
        Task description: {task_description}
        
        Please proceed with the collaborative analysis according to the following steps:
        1. Code Analyst: Perform static code analysis, identify code structure and potential issues
        2. Security Expert: Detect security vulnerabilities and risk points
        3. Debug Expert: Analyse breakpoint placement and execution flow
        4. Architect: Evaluate overall architecture and design quality
        
        Each expert should provide a detailed analysis report and recommendations.
        """
        
        try:
            # Execute collaborative analysis
            result = await team.run(
                task=analysis_prompt,
                max_turns=20
            )
            
            return {
                "status": "success",
                "analysis_result": result,
                "agents_participated": [agent.name for agent in self.agents],
                "task_completed": True
            }
            
        except Exception as e:
            return {
                "status": "error", 
                "error_message": str(e),
                "task_completed": False
            }
    
    def create_analysis_workflow(self, code_files: List[str]) -> Dict[str, Any]:
        """Create a code analysis workflow"""
        
        workflow = {
            "steps": [
                {
                    "step": 1,
                    "agent": "code_analyst",
                    "task": "Static code analysis",
                    "input": code_files,
                    "expected_output": "Code structure analysis, complexity assessment, code quality report"
                },
                {
                    "step": 2, 
                    "agent": "security_expert",
                    "task": "Security vulnerability detection",
                    "input": "Code analysis results",
                    "expected_output": "Security vulnerability report, risk assessment, remediation suggestions"
                },
                {
                    "step": 3,
                    "agent": "debug_expert", 
                    "task": "Debugging analysis",
                    "input": "Code and security analysis results",
                    "expected_output": "Breakpoint suggestions, execution path analysis, debugging strategies"
                },
                {
                    "step": 4,
                    "agent": "architect",
                    "task": "Architecture assessment",
                    "input": "All analysis results",
                    "expected_output": "Architecture quality assessment, design pattern analysis, refactoring suggestions"
                }
            ],
            "final_output": "Comprehensive analysis report and improvement recommendations"
        }
        
        return workflow
    
    def generate_summary_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate a comprehensive analysis report"""
        
        report = f"""
        # Interruptr Code Analysis Report

        ## Analysis Overview
        - Analysis status: {analysis_results.get('status', 'unknown')}
        - Participating agents: {', '.join(analysis_results.get('agents_participated', []))}
        - Task completed: {analysis_results.get('task_completed', False)}

        ## Analysis Results
        {analysis_results.get('analysis_result', 'No analysis results')}

        ## Improvement Recommendations
        Based on the multi-agent collaborative analysis, it is recommended to improve the code in the following areas:

        1. **Code quality**: Improve code readability and maintainability
        2. **Security**: Fix identified security vulnerabilities
        3. **Debuggability**: Optimise debugging and testing strategies  
        4. **Architecture**: Improve overall design and architecture

        ## Next Steps
        1. Prioritise fixing high‑severity security vulnerabilities
        2. Refactor code sections with excessive complexity
        3. Add necessary error handling and boundary checks
        4. Improve test cases and documentation

        ---
        Generated by the Interruptr multi‑agent system
        """
        
        return report