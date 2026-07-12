from typing import TypedDict, List, Dict, Any, Optional

class ValidationIssue(TypedDict):
    field: str
    message: str
    severity: str  # "error", "warning"

class ValidationResult(TypedDict):
    valid: bool
    score: float
    issues: List[ValidationIssue]

class AgentState(TypedDict):
    """LangGraph State dictionary to maintain context across nodes."""
    raw_config: str
    source_filename: str
    target_device_type: str
    source_vendor: str  # "cisco" or "arista"
    
    # Trace log for reporting
    trace_log: List[Dict[str, str]]
    
    # Agent 1: Deterministic Parsing
    legacy_parsed_data: Dict[str, Any]
    
    # Agent 2: Intent Mapping (LLM + RAG)
    extracted_intent: Dict[str, Any] 
    decision_metadata: List[Dict[str, Any]] # For confidence scores and reasoning
    rag_context: str
    
    # Agent 3: Schema Normalization
    normalized_intent: Dict[str, Any]
    
    # Agent 4: Validation
    validation_result: Optional[ValidationResult]
    
    # Agent 5: YAML Generation
    final_yaml_output: str
    final_output_path: str
    
    iteration_count: int
    
    # Agent 6: Report Generation
    report_path: str
