"""
Multi-Agent C++ Code Analysis System Based on AutoGen
"""

import os
import sys
from typing import Dict, Any

# AutoGen imports
try:
    from autogen_agentchat.agents import AssistantAgent
    from autogen_agentchat.teams import RoundRobinGroupChat
    from autogen_agentchat.ui import Console
    from autogen_core import CancellationToken
    AUTOGEN_AVAILABLE = True
except ImportError as e:
    print(f"AutoGen import failed: {e}")
    AUTOGEN_AVAILABLE = False

# LangChain imports for LLM integration
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic

# Add project path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

class AutoGenCodeAnalyzer:
    """Multi-agent code analyzer based on AutoGen"""
    
    def __init__(self):
        self.agents = {}
        self.conversation_history = []
        self.analysis_results = {}
        
    def setup_llm_clients(self):
        """Set up LLM clients"""
        llm_configs = {}
        
        # OpenAI configuration
        if config.openai_api_key:
            llm_configs["openai"] = {
                "config_list": [{
                    "model": config.openai_model,
                    "api_key": config.openai_api_key,
                    "base_url": config.openai_base_url,
                    "temperature": config.openai_temperature
                }]
            }
        
        # Anthropic Claude configuration
        if config.anthropic_api_key:
            llm_configs["anthropic"] = {
                "config_list": [{
                    "model": config.anthropic_model,
                    "api_key": config.anthropic_api_key,
                    "base_url": config.anthropic_base_url,
                    "temperature": config.anthropic_temperature
                }]
            }
        
        return llm_configs
    
    def create_agents(self):
        """Create a specialized agent team"""
        
        llm_configs = self.setup_llm_clients()
        
        # If no LLM configuration is available, use mock mode
        if not llm_configs:
            print("⚠️ No LLM configuration found; using mock mode")
            return self.create_mock_agents()
        
        # Use the first available LLM configuration
        primary_llm = list(llm_configs.values())[0]
        
        # Coordinator agent
        self.agents["coordinator"] = AssistantAgent(
            name="Coordinator",
            model_client=primary_llm,
            system_message="""You are an intelligent code analysis coordinator. Your responsibilities are:
            1. Receive C/C++ code submitted by the user
            2. Coordinate other expert agents for analysis
            3. Organise and summarise all analysis results
            4. Prioritise fixes and provide recommendations

            Please remain professional, accurate, and ensure comprehensive analysis.
            """,
            description="Responsible for coordinating the entire analysis workflow"
        )
        
        # Code analyst
        self.agents["code_analyst"] = AssistantAgent(
            name="Code Analyst",
            model_client=primary_llm,
            system_message="""You are a professional C/C++ code analyst. Your expertise includes:
            1. Static code analysis and metrics
            2. Calculating cyclomatic complexity and code quality indicators
            3. Checking code structure and organisation
            4. Identifying performance issues and optimisation suggestions

            Please provide a detailed code quality analysis report.
            """,
            description="Focused on code quality and structural analysis"
        )
        
        # Security expert
        self.agents["security_expert"] = AssistantAgent(
            name="Security Expert",
            model_client=primary_llm,
            system_message="""You are a C/C++ security vulnerability expert. Your expertise includes:
            1. Buffer overflow detection
            2. Memory leak and dangling pointer analysis
            3. Dangerous function usage checks
            4. Input validation and boundary checking
            5. Common security vulnerability pattern recognition

            Please focus on security issues and provide specific vulnerability locations and remediation suggestions.
            """,
            description="Focused on security vulnerability detection and analysis"
        )
        
        # Debug expert
        self.agents["debug_expert"] = AssistantAgent(
            name="Debug Expert",
            model_client=primary_llm,
            system_message="""You are a C/C++ debugging expert. Your expertise includes:
            1. Analysing code debuggability
            2. Suggesting breakpoint placement
            3. Recommending debugging tools and techniques
            4. Error handling and exception analysis
            5. Logging and monitoring recommendations

            Please provide practical debugging strategies and tool suggestions.
            """,
            description="Focused on debugging strategies and tool recommendations"
        )
        
        # Architect
        self.agents["architect"] = AssistantAgent(
            name="Architect",
            model_client=primary_llm,
            system_message="""You are a software architecture expert. Your expertise includes:
            1. Design pattern identification and recommendations
            2. SOLID principle checking
            3. Code organisation and modularisation analysis
            4. Interface design and dependency management
            5. Maintainability and extensibility assessment

            Please analyse code design quality from an architectural perspective.
            """,
            description="Focused on software architecture and design pattern analysis"
        )
        
        # Critic (use a different LLM if available)
        critic_llm = llm_configs.get("anthropic", primary_llm)
        self.agents["critic"] = AssistantAgent(
            name="Critic",
            model_client=critic_llm,
            system_message="""You are a rigorous code critic. Your responsibilities are:
            1. Synthesise the analysis results from all experts
            2. Provide objective quality scoring
            3. Point out possible omissions in the analysis
            4. Prioritise improvements
            5. Give a final evaluation conclusion

            Please maintain a critical mindset to ensure accuracy and completeness of the analysis.
            """,
            description="Responsible for final quality assessment and critical analysis"
        )
        
        return True
    
    def create_mock_agents(self):
        """Create mock agents (when no LLM configuration is available)"""
        
        class MockAgent:
            def __init__(self, name, role):
                self.name = name
                self.role = role
            
            async def generate_response(self, message):
                # Return mock responses
                responses = {
                    "Coordinator": f"I am the Coordinator, received analysis request: {message[:50]}...",
                    "Code Analyst": "Performing static code analysis...",
                    "Security Expert": "Detecting security vulnerabilities...",
                    "Debug Expert": "Analysing debugging requirements...", 
                    "Architect": "Evaluating architecture design...",
                    "Critic": "Conducting comprehensive assessment..."
                }
                return responses.get(self.name, "Processing...")
        
        agent_configs = [
            ("Coordinator", "Coordinate analysis workflow"),
            ("Code Analyst", "Code quality analysis"),
            ("Security Expert", "Security vulnerability detection"),
            ("Debug Expert", "Debugging strategy recommendations"),
            ("Architect", "Architecture design analysis"),
            ("Critic", "Comprehensive quality assessment")
        ]
        
        for name, role in agent_configs:
            self.agents[name] = MockAgent(name, role)
        
        return False  # Indicates mock mode is being used
    
    async def analyze_code(self, code_content: str, filename: str) -> Dict[str, Any]:
        """Analyse code using multi-agent system"""
        
        print(f"🔍 Starting analysis of file: {filename}")
        print(f"📝 Code length: {len(code_content)} characters")
        
        # Create agents
        has_real_llm = self.create_agents()
        
        if has_real_llm:
            return await self.run_autogen_analysis(code_content, filename)
        else:
            return await self.run_mock_analysis(code_content, filename)
    
    async def run_autogen_analysis(self, code_content: str, filename: str) -> Dict[str, Any]:
        """Run real AutoGen multi-agent analysis"""
        
        if not AUTOGEN_AVAILABLE:
            print("⚠️ AutoGen is unavailable; using mock mode")
            return await self.run_mock_analysis(code_content, filename)
        
        try:
            # Create team chat
            team = RoundRobinGroupChat([
                self.agents["coordinator"],
                self.agents["code_analyst"], 
                self.agents["security_expert"],
                self.agents["debug_expert"],
                self.agents["architect"],
                self.agents["critic"]
            ])
            
            # Prepare analysis prompt
            analysis_prompt = f"""
                Please analyse the following C/C++ code file: {filename}

                Code content:
                {code_content}

                Each expert should analyse according to their own expertise:
                1. Coordinator: overall coordination and process management
                2. Code Analyst: code quality, complexity, performance analysis
                3. Security Expert: security vulnerabilities, memory safety, dangerous function detection
                4. Debug Expert: debugging suggestions, breakpoint recommendations, tool advice
                5. Architect: design patterns, SOLID principles, architecture quality
                6. Critic: comprehensive assessment, scoring, improvement suggestions

                Please provide detailed and specific analysis results.
                """
            
            # Run analysis
            import sys
            result = await team.run(
                task=analysis_prompt,
                cancellation_token=CancellationToken()
            )
            
            # Organise conversation history
            conversation_history = []
            if hasattr(result, 'messages'):
                for message in result.messages:
                    conversation_history.append({
                        "agent": getattr(message, 'source', 'unknown'),
                        "agent_name": f"🤖 {getattr(message, 'source', 'unknown')}",
                        "message": getattr(message, 'content', str(message)),
                        "timestamp": "2025-08-30 16:40:00",  # Simplified timestamp
                        "reasoning": f"Based on the professional analysis of {getattr(message, 'source', 'unknown')}"
                    })
            
            return {
                "analysis_type": "autogen_real",
                "filename": filename,
                "agent_conversations": conversation_history,
                "summary": {
                    "total_agents": len(self.agents),
                    "total_messages": len(conversation_history),
                    "analysis_complete": True
                },
                "file_info": {
                    "filename": filename,
                    "total_lines": len(code_content.split('\n')),
                    "code_size": len(code_content)
                }
            }
            
        except Exception as e:
            print(f"❌ AutoGen analysis failed: {e}")
            return await self.run_mock_analysis(code_content, filename)
    
    async def run_mock_analysis(self, code_content: str, filename: str) -> Dict[str, Any]:
        """Run mock multi-agent analysis"""
        
        print("🎭 Running mock multi-agent analysis mode")
        
        # Simple code analysis
        lines = code_content.split('\n')
        code_lines = [line for line in lines if line.strip() and not line.strip().startswith('//')]
        
        # Detect issues
        security_issues = []
        if 'strcpy' in code_content:
            security_issues.append("strcpy function detected, may cause buffer overflow")
        if 'gets' in code_content:
            security_issues.append("gets function detected, highly prone to buffer overflow")
        if 'malloc' in code_content and 'free' not in code_content:
            security_issues.append("malloc found but no matching free; possible memory leak")
        
        # Mock agent conversations
        conversations = [
            {
                "agent": "coordinator",
                "agent_name": "🎯 Coordinator",
                "message": f"Starting analysis of file {filename}, total {len(lines)} lines. Distributing tasks to expert agents.",
                "timestamp": "2025-08-30 16:40:01",
                "reasoning": "Initialising multi-agent collaborative analysis process"
            },
            {
                "agent": "code_analyst", 
                "agent_name": "📊 Code Analyst",
                "message": f"Code structure analysis completed:\n- Total lines: {len(lines)}\n- Effective code lines: {len(code_lines)}\n- Function count: {code_content.count('(')}\n- Complexity: medium",
                "timestamp": "2025-08-30 16:40:05",
                "reasoning": "Performed code metric statistics based on static analysis"
            },
            {
                "agent": "security_expert",
                "agent_name": "🔒 Security Expert", 
                "message": f"Security analysis results:\n{''.join(['- ' + issue + chr(10) for issue in security_issues]) if security_issues else '✅ No obvious security issues detected'}",
                "timestamp": "2025-08-30 16:40:08",
                "reasoning": "Scanned for common C/C++ security vulnerability patterns"
            },
            {
                "agent": "debug_expert",
                "agent_name": "🐛 Debug Expert",
                "message": "Debugging suggestions:\n- Suggest using gdb for debugging\n- Set breakpoints at critical locations\n- Enable compiler warning options\n- Use Valgrind to detect memory issues",
                "timestamp": "2025-08-30 16:40:12",
                "reasoning": "Provided debugging strategies based on code characteristics"
            },
            {
                "agent": "architect",
                "agent_name": "🏗️ Architect",
                "message": f"Architecture assessment:\n- Code organisation: {'simple' if len(code_lines) < 50 else 'complex'}\n- Function design: needs further modularisation\n- Suggests following SOLID principles",
                "timestamp": "2025-08-30 16:40:16",
                "reasoning": "Evaluated code design from a software engineering perspective"
            },
            {
                "agent": "critic",
                "agent_name": "🧐 Critic",
                "message": f"Comprehensive assessment:\n- Code quality: {'good' if not security_issues else 'needs improvement'}\n- Security score: {8 if not security_issues else 4}/10\n- Recommendation: {'maintain current standards' if not security_issues else 'prioritise fixing security issues'}",
                "timestamp": "2025-08-30 16:40:20",
                "reasoning": "Synthesised all expert opinions for final evaluation"
            },
            {
                "agent": "coordinator",
                "agent_name": "🎯 Coordinator",
                "message": f"Analysis complete! Found {len(security_issues)} potential issues. Suggestions to fix by priority.",
                "timestamp": "2025-08-30 16:40:24",
                "reasoning": "Aggregated analysis results and developed action plan"
            }
        ]
        
        return {
            "analysis_type": "autogen_mock",
            "filename": filename,
            "agent_conversations": conversations,
            "security_issues": security_issues,
            "code_metrics": {
                "total_lines": len(lines),
                "code_lines": len(code_lines),
                "complexity": "medium",
                "function_count": code_content.count('(')
            },
            "summary": {
                "total_agents": len(self.agents),
                "issues_found": len(security_issues),
                "overall_score": 8 if not security_issues else 4
            },
            "file_info": {
                "filename": filename,
                "total_lines": len(lines),
                "code_size": len(code_content)
            }
        }

# Global analyzer instance
autogen_analyzer = AutoGenCodeAnalyzer()
