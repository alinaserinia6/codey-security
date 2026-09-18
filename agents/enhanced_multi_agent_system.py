"""
Enhanced Multi-Agent System
Includes Critic and Reviewer roles for more comprehensive code analysis
"""

import asyncio
from typing import Dict, List, Any, Optional
import json
from datetime import datetime
from dataclasses import dataclass
import sys
from pathlib import Path

# Add project root directory to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from env_config import config

@dataclass
class AgentConfig:
    """Agent configuration"""
    name: str
    role: str
    llm_provider: str
    system_message: str
    temperature: float = 0.1
    max_tokens: int = 4000

class LLMInterface:
    """LLM interface abstraction layer"""
    
    @staticmethod
    async def call_openai(prompt: str, system_message: str) -> str:
        """Call OpenAI API"""
        try:
            from openai import AsyncOpenAI
            
            client = AsyncOpenAI(
                api_key=config.openai_api_key,
                base_url=config.openai_base_url
            )
            
            response = await client.chat.completions.create(
                model=config.openai_model,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt}
                ],
                temperature=config.openai_temperature,
                max_tokens=config.openai_max_tokens
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            return f"OpenAI call failed: {str(e)}"
    
    @staticmethod
    async def call_anthropic(prompt: str, system_message: str) -> str:
        """Call Anthropic Claude API"""
        try:
            from anthropic import AsyncAnthropic
            
            client = AsyncAnthropic(
                api_key=config.anthropic_api_key
            )
            
            response = await client.messages.create(
                model=config.anthropic_model,
                max_tokens=config.anthropic_max_tokens,
                temperature=config.anthropic_temperature,
                system=system_message,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            return response.content[0].text
            
        except Exception as e:
            return f"Anthropic call failed: {str(e)}"
    
    @staticmethod
    async def call_gemini(prompt: str, system_message: str) -> str:
        """Call Google Gemini API"""
        try:
            import google.generativeai as genai
            
            genai.configure(api_key=config.gemini_api_key)
            model = genai.GenerativeModel(config.gemini_model)
            
            full_prompt = f"{system_message}\n\n{prompt}"
            response = await model.generate_content_async(
                full_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=config.gemini_temperature,
                    max_output_tokens=config.gemini_max_tokens
                )
            )
            
            return response.text
            
        except Exception as e:
            return f"Gemini call failed: {str(e)}"
    
    @staticmethod
    async def call_ollama(prompt: str, system_message: str) -> str:
        """Call Ollama local inference"""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": config.ollama_model,
                    "prompt": f"{system_message}\n\n{prompt}",
                    "stream": False,
                    "options": {
                        "temperature": config.ollama_temperature,
                        "num_predict": config.ollama_max_tokens
                    }
                }
                
                async with session.post(
                    f"{config.ollama_base_url}/api/generate",
                    json=payload
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get("response", "Ollama response is empty")
                    else:
                        return f"Ollama call failed: HTTP {response.status}"
                        
        except Exception as e:
            return f"Ollama call failed: {str(e)}"

class EnhancedAgent:
    """Enhanced agent class"""
    
    def __init__(self, agent_config: AgentConfig):
        self.config = agent_config
        self.conversation_history: List[Dict[str, str]] = []
        
    async def process(self, prompt: str, context: Optional[Dict] = None) -> str:
        """Process input and return response"""
        
        # Add context information
        if context:
            enhanced_prompt = f"""
Context information:
{json.dumps(context, ensure_ascii=False, indent=2)}

Task:
{prompt}
"""
        else:
            enhanced_prompt = prompt
        
        # Select calling method based on LLM provider
        if self.config.llm_provider == "openai":
            response = await LLMInterface.call_openai(enhanced_prompt, self.config.system_message)
        elif self.config.llm_provider == "claude":
            response = await LLMInterface.call_anthropic(enhanced_prompt, self.config.system_message)
        elif self.config.llm_provider == "gemini":
            response = await LLMInterface.call_gemini(enhanced_prompt, self.config.system_message)
        elif self.config.llm_provider == "ollama":
            response = await LLMInterface.call_ollama(enhanced_prompt, self.config.system_message)
        else:
            response = f"Unsupported LLM provider: {self.config.llm_provider}"
        
        # Record conversation history
        self.conversation_history.append({
            "timestamp": datetime.now().isoformat(),
            "prompt": enhanced_prompt,
            "response": response
        })
        
        return response

class EnhancedMultiAgentSystem:
    """Enhanced multi-agent system"""
    
    def __init__(self):
        self.agents: Dict[str, EnhancedAgent] = {}
        self.analysis_results: Dict[str, Any] = {}
        self.conversation_log: List[Dict[str, Any]] = []
        
        self._initialize_agents()
    
    def _initialize_agents(self):
        """Initialize all agents"""
        
        # Coordinator - GPT-4 (strong coordination capabilities)
        coordinator_config = AgentConfig(
            name="coordinator",
            role="Coordinator",
            llm_provider=config.coordinator_llm,
            system_message="""You are the coordinator of the Interruptr system, responsible for managing the entire code analysis process.
Your responsibilities:
1. Decompose complex analysis tasks
2. Coordinate the work of expert agents
3. Integrate analysis results
4. Ensure completeness and accuracy of the analysis
5. Generate the final comprehensive report

Always maintain an objective and professional attitude to ensure an orderly analysis process."""
        )
        
        # Code Analyst - Claude (deep analytical capabilities)
        code_analyst_config = AgentConfig(
            name="code_analyst",
            role="Code Analyst", 
            llm_provider=config.code_analyst_llm,
            system_message="""You are a professional C/C++ code analyst with deep programming experience.
Your expertise:
1. Static code analysis and structure parsing
2. Code complexity calculation and quality assessment
3. Coding standards and best practice checks
4. Performance bottleneck identification
5. Code maintainability evaluation

Please provide a detailed and accurate analysis report, including specific improvement suggestions."""
        )
        
        # Security Expert - Claude (specialised security analysis)
        security_expert_config = AgentConfig(
            name="security_expert",
            role="Security Expert",
            llm_provider=config.security_expert_llm,
            system_message="""You are an expert in C/C++ security, focused on identifying and analysing security vulnerabilities.
Your expertise:
1. Buffer overflow detection
2. Memory leak and dangling pointer analysis
3. Integer overflow and underflow checking
4. Format string vulnerability identification
5. Race condition analysis
6. Encryption and authentication issues

Please provide a detailed security risk assessment and specific remediation plans."""
        )
        
        # Debug Expert - GPT-4 (rich debugging experience)
        debug_expert_config = AgentConfig(
            name="debug_expert",
            role="Debug Expert",
            llm_provider=config.debug_expert_llm,
            system_message="""You are an experienced debugging expert, skilled in analysing program execution flows and locating issues.
Your expertise:
1. Intelligent breakpoint placement recommendations
2. Program execution path analysis
3. Variable state tracking strategies
4. Exception and error handling analysis
5. Test case design
6. Debugging tool usage suggestions

Please provide practical debugging strategies and specific breakpoint suggestions."""
        )
        
        # Architect - Claude (architecture design capabilities)
        architect_config = AgentConfig(
            name="architect",
            role="Architect",
            llm_provider=config.architect_llm,
            system_message="""You are a software architect, focused on overall code design and architecture quality.
Your expertise:
1. Software architecture pattern identification and evaluation
2. Code organisation structure analysis
3. Module coupling and cohesion assessment
4. Design principle compliance checking
5. Scalability and maintainability analysis
6. Refactoring suggestions and architecture improvements

Please provide professional design recommendations from an architectural perspective."""
        )
        
        # Critic - Gemini (multi‑angle questioning)
        critic_config = AgentConfig(
            name="critic",
            role="Critic",
            llm_provider=config.critic_llm,
            system_message="""You are an independent critic, responsible for critically reviewing the analysis results of other agents.
Your responsibilities:
1. Question the reasonableness of analysis conclusions
2. Look for overlooked issues and risks
3. Verify the feasibility of suggestions
4. Raise objections and alternative solutions
5. Ensure comprehensiveness and objectivity of the analysis

Maintain a critical mindset and provide constructive questions and different perspectives."""
        )
        
        # Reviewer - Ollama local (independent verification)
        reviewer_config = AgentConfig(
            name="reviewer",
            role="Reviewer",
            llm_provider=config.reviewer_llm,
            system_message="""You are an independent reviewer, responsible for the final audit and verification of all analysis results.
Your responsibilities:
1. Verify the accuracy of analysis results
2. Check the logical consistency of conclusions
3. Confirm the practicality of suggestions
4. Identify contradictions and inconsistencies
5. Provide final quality assurance

Conduct a strict review to ensure the quality and reliability of the output."""
        )
        
        # Create agent instances
        configs = [
            coordinator_config, code_analyst_config, security_expert_config,
            debug_expert_config, architect_config, critic_config, reviewer_config
        ]
        
        for agent_config in configs:
            self.agents[agent_config.name] = EnhancedAgent(agent_config)
    
    def _log_conversation(self, sender: str, receiver: str, message: str, message_type: str = "analysis"):
        """Log a conversation entry"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "type": message_type
        }
        self.conversation_log.append(entry)
    
    async def analyze_code_file(self, file_path: str, code_content: str) -> Dict[str, Any]:
        """Execute the complete code analysis workflow"""
        
        print(f"🚀 Starting analysis of file: {file_path}")
        
        # Round 1: Basic analysis
        print("\n📊 Round 1: Basic expert analysis...")
        
        # 1. Code Analyst analysis
        code_analysis_prompt = f"""
Please analyse the following C/C++ code file:

File path: {file_path}
Code content:
```c
{code_content}
```

Please provide a detailed code quality analysis report.
"""
        
        code_analysis = await self.agents["code_analyst"].process(code_analysis_prompt)
        self.analysis_results["code_quality"] = code_analysis
        self._log_conversation("system", "code_analyst", code_analysis_prompt)
        self._log_conversation("code_analyst", "system", code_analysis)
        print("✅ Code quality analysis completed")
        
        # 2. Security Expert analysis
        security_analysis_prompt = f"""
Based on the code quality analysis results, please perform security vulnerability detection:

Code analysis results:
{code_analysis}

Original code:
```c
{code_content}
```

Please focus on detecting security risks and vulnerabilities.
"""
        
        security_analysis = await self.agents["security_expert"].process(
            security_analysis_prompt,
            {"code_analysis": code_analysis}
        )
        self.analysis_results["security"] = security_analysis
        self._log_conversation("system", "security_expert", security_analysis_prompt)
        self._log_conversation("security_expert", "system", security_analysis)
        print("✅ Security analysis completed")
        
        # 3. Debug Expert analysis
        debug_analysis_prompt = f"""
Based on the previous analysis results, please provide debugging suggestions:

Code quality analysis:
{code_analysis}

Security analysis:
{security_analysis}

Please recommend breakpoint locations and debugging strategies.
"""
        
        debug_analysis = await self.agents["debug_expert"].process(
            debug_analysis_prompt,
            {"code_analysis": code_analysis, "security_analysis": security_analysis}
        )
        self.analysis_results["debug"] = debug_analysis
        self._log_conversation("system", "debug_expert", debug_analysis_prompt)
        self._log_conversation("debug_expert", "system", debug_analysis)
        print("✅ Debugging analysis completed")
        
        # 4. Architect analysis
        architecture_analysis_prompt = f"""
Based on all analysis results, please perform an architecture assessment:

Code quality: {code_analysis}
Security analysis: {security_analysis}
Debugging analysis: {debug_analysis}

Please provide design suggestions from an architectural perspective.
"""
        
        architecture_analysis = await self.agents["architect"].process(
            architecture_analysis_prompt,
            {
                "code_analysis": code_analysis,
                "security_analysis": security_analysis,
                "debug_analysis": debug_analysis
            }
        )
        self.analysis_results["architecture"] = architecture_analysis
        self._log_conversation("system", "architect", architecture_analysis_prompt)
        self._log_conversation("architect", "system", architecture_analysis)
        print("✅ Architecture analysis completed")
        
        # Round 2: Critique and review
        print("\n🤔 Round 2: Critic review...")
        
        # 5. Critic review
        critic_prompt = f"""
Please perform a critical review of the following analysis results:

Code quality analysis: {code_analysis}
Security analysis: {security_analysis}
Debugging analysis: {debug_analysis}
Architecture analysis: {architecture_analysis}

Question these conclusions, look for overlooked issues, and raise different perspectives.
"""
        
        critic_review = await self.agents["critic"].process(
            critic_prompt,
            self.analysis_results
        )
        self.analysis_results["critic_review"] = critic_review
        self._log_conversation("system", "critic", critic_prompt)
        self._log_conversation("critic", "system", critic_review)
        print("✅ Critic review completed")
        
        # Round 3: Final verification
        print("\n🔍 Round 3: Reviewer verification...")
        
        # 6. Reviewer verification
        reviewer_prompt = f"""
Please perform the final validation of the entire analysis process:

All analysis results:
{json.dumps(self.analysis_results, ensure_ascii=False, indent=2)}

Critic's opinion: {critic_review}

Verify the accuracy, consistency, and completeness of the analysis, and provide a final assessment.
"""
        
        final_review = await self.agents["reviewer"].process(
            reviewer_prompt,
            self.analysis_results
        )
        self.analysis_results["final_review"] = final_review
        self._log_conversation("system", "reviewer", reviewer_prompt)
        self._log_conversation("reviewer", "system", final_review)
        print("✅ Final review completed")
        
        # Round 4: Coordinator summarises
        print("\n📋 Round 4: Coordinator summary...")
        
        # 7. Coordinator generates final report
        coordinator_prompt = f"""
Based on the analysis results from all agents, please generate the final comprehensive report:

Full analysis results:
{json.dumps(self.analysis_results, ensure_ascii=False, indent=2)}

Synthesise all viewpoints and produce a structured final report.
"""
        
        final_report = await self.agents["coordinator"].process(
            coordinator_prompt,
            self.analysis_results
        )
        self.analysis_results["final_report"] = final_report
        self._log_conversation("system", "coordinator", coordinator_prompt)
        self._log_conversation("coordinator", "system", final_report)
        print("✅ Final report generation completed")
        
        return {
            "status": "completed",
            "file_path": file_path,
            "analysis_results": self.analysis_results,
            "conversation_log": self.conversation_log,
            "agent_summary": self._generate_agent_summary()
        }
    
    def _generate_agent_summary(self) -> Dict[str, Any]:
        """Generate agent work summary"""
        summary = {}
        
        for agent_name, agent in self.agents.items():
            summary[agent_name] = {
                "role": agent.config.role,
                "llm_provider": agent.config.llm_provider,
                "interactions": len(agent.conversation_history),
                "status": "completed"
            }
        
        return summary

# Usage example
async def main():
    """Main function example"""
    
    # Create the enhanced multi-agent system
    system = EnhancedMultiAgentSystem()
    
    # Analyse an example file
    file_path = "examples/unsafe_code.c"
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code_content = f.read()
        
        # Execute analysis
        result = await system.analyze_code_file(file_path, code_content)
        
        # Save results
        output_file = f"analysis_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        print(f"\n🎉 Analysis completed! Results saved to: {output_file}")
        print(f"📊 Number of agents involved: {len(result['agent_summary'])}")
        print(f"💬 Number of conversation entries: {len(result['conversation_log'])}")
        
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
    except Exception as e:
        print(f"❌ Analysis failed: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
