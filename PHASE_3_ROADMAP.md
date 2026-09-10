# Phase 3 Roadmap: GDB Interface & Advanced Local Analysis

## Overview

Phase 3 focuses on **local GDB integration** and **advanced memory/register analysis**. These features work entirely offline (no remote service) and enhance Baldrick's debugging capabilities for interactive use.

## Phase 3 Scope

Phase 3 is divided into two concurrent tracks:

### Track A: GDB Python Extension (Weeks 1-4)
### Track B: Advanced Analysis Features (Weeks 2-5)

---

## Track A: GDB Python Extension

### Goal
Enable Baldrick to act as a backend for GDB, providing enhanced symbol resolution, memory analysis, and backtrace decoding within the familiar GDB environment.

### 3.1: GDB Interface Design (Week 1)

**Deliverable**: GDB command protocol specification and architecture

#### 3.1.1 GDB Python API Bridge
```python
# baldrick/gdb_bridge.py

class BaldrickGDBBridge:
    """Interface between GDB and Baldrick analysis engine."""
    
    def __init__(self, baldrick_db_path: str):
        self.db = ProcessDatabase(manager)
    
    # GDB commands that invoke Baldrick
    async def gdb_decode_backtrace(self, frame_list: list[dict]) -> list[dict]:
        """Enhanced backtrace decoding for current inferior."""
        # Input: GDB frame info (address, function, file, line)
        # Output: Enhanced frame info with symbol analysis, memory type, etc.
    
    async def gdb_analyze_address(self, address: int) -> dict:
        """Analyze a single address from inferior memory."""
        # Return: {symbol, file, line, memory_type, anomalies, register_context}
    
    async def gdb_find_symbol(self, name: str) -> list[dict]:
        """Find all symbols matching pattern."""
        # Return: [{address, type, section, file, binary}]
    
    async def gdb_memory_summary(self, start: int, end: int) -> dict:
        """Summarize memory region (type, permissions, anomalies)."""
    
    async def gdb_analyze_register_state(self, registers: dict) -> dict:
        """Interpret register values (pointers, strings, etc.)."""
```

#### 3.1.2 GDB Command Definitions
```python
# baldrick/gdb_commands.py

# Commands to register with GDB
BALDRICK_COMMANDS = {
    "baldrick backtrace-analyze": {
        "description": "Decode and analyze backtrace with Baldrick",
        "usage": "baldrick backtrace-analyze",
        "handler": "analyze_backtrace_command",
    },
    "baldrick address-analyze": {
        "description": "Analyze address at cursor or argument",
        "usage": "baldrick address-analyze [address]",
        "handler": "analyze_address_command",
    },
    "baldrick memory-regions": {
        "description": "List memory regions with type classification",
        "usage": "baldrick memory-regions [address | start end]",
        "handler": "memory_regions_command",
    },
    "baldrick symbol-find": {
        "description": "Find symbols by pattern",
        "usage": "baldrick symbol-find <pattern>",
        "handler": "symbol_find_command",
    },
    "baldrick register-interpret": {
        "description": "Interpret registers (pointers, strings, etc.)",
        "usage": "baldrick register-interpret [register_name]",
        "handler": "register_interpret_command",
    },
}
```

#### 3.1.3 GDB Pretty-Printers
```python
# baldrick/gdb_printers.py

class BacktraceFramePrinter:
    """Pretty-print enhanced backtrace frames."""
    
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        # Format: "#0  0x400a1c in main() at main.c:42 [TEXT] ← nice memory type indicator
        return formatted_frame

class MemoryRegionPrinter:
    """Pretty-print memory region analysis."""
    
    def to_string(self):
        # Format: 0x7fff0000-0x7fff1000 rw-p [STACK] (16KB)
        return formatted_region
```

### 3.2: GDB Native Commands (Week 2)

**Deliverable**: GDB integration module with command handlers

#### 3.2.1 Command Handlers
```python
# baldrick/gdb_integration.py

async def analyze_backtrace_command(gdb_context):
    """
    GDB Command: baldrick backtrace-analyze
    
    Decodes current backtrace with:
    - Symbol resolution
    - Memory type classification
    - Anomaly detection
    - Register context analysis
    """
    current_thread = gdb_context.selected_thread()
    frames = await extract_frames_from_inferior(current_thread)
    
    # Run through Baldrick analysis
    analysis = await baldrick_bridge.analyze_backtrace(frames)
    
    # Format and display
    display_backtrace_analysis(analysis)

async def analyze_address_command(gdb_context, address: int):
    """
    GDB Command: baldrick address-analyze <addr>
    
    Shows:
    - Symbol name and offset
    - Source file and line
    - Memory region type
    - Anomalies (RWX, writable code, etc.)
    - Register if address in any register
    """
    analysis = await baldrick_bridge.analyze_address(address)
    display_address_analysis(analysis)

async def memory_regions_command(gdb_context, start: int, end: int):
    """
    GDB Command: baldrick memory-regions [start end]
    
    Shows all memory regions in range with:
    - Address range
    - Permissions
    - Type (HEAP, STACK, TEXT, etc.)
    - Anomalies
    - Path/binary name
    """
    regions = await baldrick_bridge.get_memory_regions(start, end)
    display_memory_table(regions)
```

#### 3.2.2 Data Extraction from Inferior
```python
# baldrick/gdb_inferior.py

async def extract_frames_from_inferior(thread):
    """Extract frame info from GDB inferior."""
    frames = []
    frame = gdb.newest_frame()
    
    while frame is not None:
        frames.append({
            "address": frame.pc(),
            "function": frame.name(),
            "file": frame.filename(),
            "line": frame.line(),
            "register_state": extract_registers(frame),
        })
        frame = frame.older()
    
    return frames

async def extract_memory_maps_from_inferior(process):
    """Extract memory maps from /proc/PID/maps for running process."""
    # For live process: read /proc/{pid}/maps
    # Return MemoryMapping objects
    pass

async def extract_register_state_from_inferior(thread):
    """Extract all registers from thread."""
    registers = {}
    for reg_name in get_architecture_registers(process.arch):
        try:
            val = thread.registers[reg_name].integer_value()
            registers[reg_name] = val
        except:
            pass
    return registers
```

### 3.3: GDB Integration Testing (Week 3)

**Deliverable**: Test suite for GDB integration

```python
# tests/test_gdb_integration.py

@pytest.mark.requires_gdb
async def test_gdb_backtrace_analyze():
    """Test backtrace analysis in GDB context."""
    # Start GDB with test program
    # Set breakpoint
    # Run to breakpoint
    # Execute: baldrick backtrace-analyze
    # Verify output contains: address, symbol, file, memory type
    pass

@pytest.mark.requires_gdb
async def test_gdb_address_analyze():
    """Test single address analysis."""
    # Analyze address in code section
    # Verify: symbol, file, line, memory_type=TEXT
    pass

@pytest.mark.requires_gdb
async def test_gdb_memory_regions():
    """Test memory region listing."""
    # Get memory regions for running process
    # Verify: heap, stack, libraries classified correctly
    pass
```

### 3.4: GDB Installation & Documentation (Week 4)

**Deliverable**: GDB plugin installation script and user guide

```bash
# baldrick/gdb_setup.sh

# Install Baldrick GDB plugin
# - Copy gdb_integration.py to ~/.gdbinit.d/
# - Register commands with GDB
# - Load automatically on GDB startup
```

**Documentation**: `GDB_INTEGRATION_GUIDE.md`
- Installation instructions
- Command reference
- Usage examples
- Troubleshooting

---

## Track B: Advanced Analysis Features

### Goal
Provide rich, contextual debugging information: register interpretation, heap analysis, corruption detection, stack unwinding validation.

### 3.5: Register Interpretation Engine (Week 2)

**Deliverable**: Register value analysis and interpretation

#### 3.5.1 Register State Analysis
```python
# baldrick/register_analyzer.py

class RegisterInterpreter:
    """Interpret CPU register values in context."""
    
    def __init__(self, architecture: Architecture, memory_layout: dict):
        self.arch = architecture
        self.memory = memory_layout
    
    def interpret_register(self, reg_name: str, value: int) -> dict:
        """
        Interpret register value.
        
        Returns:
        {
            "register": "rax",
            "value": "0x400a1c",
            "interpretation": "code pointer → main()+0x1c",
            "likely_type": "instruction pointer",
            "memory_type": "TEXT",
            "related_symbols": ["main", "malloc"],
        }
        """
        interpretations = []
        
        # Is it a code pointer?
        if self._is_code_address(value):
            symbol = self._resolve_symbol(value)
            interpretations.append({
                "type": "code_pointer",
                "symbol": symbol,
                "memory_region": self._classify_address(value),
            })
        
        # Is it a heap pointer?
        if self._is_heap_address(value):
            interpretations.append({
                "type": "heap_pointer",
                "size": self._estimate_heap_block_size(value),
                "allocation_pattern": self._detect_pattern(value),
            })
        
        # Is it a stack pointer?
        if self._is_stack_address(value):
            interpretations.append({
                "type": "stack_pointer",
                "depth": self._estimate_stack_depth(value),
                "local_vars": self._find_local_variables(value),
            })
        
        # Could it be a string?
        if self._might_be_string(value):
            try:
                string_val = self._read_string(value, max_length=256)
                interpretations.append({
                    "type": "string_pointer",
                    "value": string_val,
                    "length": len(string_val),
                })
            except:
                pass
        
        return {
            "register": reg_name,
            "value": hex(value),
            "interpretations": interpretations,
            "confidence": self._calculate_confidence(interpretations),
        }
    
    def interpret_all_registers(self, register_state: dict) -> dict:
        """Interpret all registers in current state."""
        interpretations = {}
        for reg_name, value in register_state.items():
            interpretations[reg_name] = self.interpret_register(reg_name, value)
        
        return {
            "registers": interpretations,
            "calling_convention_state": self._analyze_calling_convention(),
            "local_variables": self._reconstruct_locals(),
        }
```

#### 3.5.2 Data Type Inference
```python
# baldrick/type_inference.py

class TypeInferencer:
    """Infer types from memory patterns and registers."""
    
    def infer_heap_block_structure(self, address: int) -> dict:
        """
        Infer structure of heap block at address.
        
        Returns:
        {
            "address": 0x123456,
            "header": {"magic": 0xdeadbeef, "size": 256, "freed": false},
            "data_region": {"type": "likely_string" | "array" | "struct" | "unknown"},
            "patterns": [{"offset": 0, "pattern": "text", "confidence": 0.9}],
        }
        """
        pass
    
    def infer_struct_layout(self, address: int, size: int) -> dict:
        """Infer structure layout from memory dump."""
        pass
    
    def infer_array_structure(self, address: int, element_size: int) -> dict:
        """Infer array structure from pointer."""
        pass
```

### 3.6: Heap Analysis (Week 3)

**Deliverable**: Heap corruption detection and analysis

#### 3.6.1 Heap Inspector
```python
# baldrick/heap_analyzer.py

class HeapAnalyzer:
    """Analyze heap structure and detect corruption."""
    
    async def analyze_heap(self) -> dict:
        """
        Analyze entire heap.
        
        Returns:
        {
            "heap_regions": [...],
            "total_allocated": 1024000,
            "total_free": 256000,
            "fragmentation": 0.25,
            "corruption_risk": "high",
            "anomalies": [
                {
                    "type": "use_after_free",
                    "address": 0x123456,
                    "severity": "critical",
                    "evidence": ["freed marker present", "writes detected"],
                },
                {
                    "type": "buffer_overflow",
                    "address": 0x234567,
                    "severity": "high",
                    "evidence": ["size exceeded", "adjacent block header corrupted"],
                },
            ],
        }
        """
        pass
    
    async def find_free_list(self) -> list[dict]:
        """Find and parse heap free list."""
        pass
    
    async def detect_heap_overflow(self) -> list[dict]:
        """Detect buffer overflows by header corruption."""
        pass
    
    async def detect_use_after_free(self) -> list[dict]:
        """Detect use-after-free patterns."""
        pass
    
    async def visualize_heap_map(self) -> str:
        """Generate ASCII heap layout visualization."""
        pass
```

### 3.7: Stack Unwinding Validation (Week 4)

**Deliverable**: Validate and repair corrupted stack frames

#### 3.7.1 Stack Frame Validator
```python
# baldrick/stack_validator.py

class StackUnwindValidator:
    """Validate and repair corrupted stack frames."""
    
    async def validate_unwind_chain(self, frames: list[dict]) -> dict:
        """
        Validate backtrace frame chain for corruption.
        
        Returns:
        {
            "frames": [
                {
                    "address": 0x400a1c,
                    "is_valid": true,
                    "confidence": 0.95,
                    "anomalies": [],
                },
                {
                    "address": 0x123456,
                    "is_valid": false,
                    "confidence": 0.3,
                    "anomalies": ["not in code section", "frame pointer broken"],
                    "suggested_next": [0x400b00, 0x500000],
                },
            ],
            "corruption_detected": true,
            "repair_options": [...],
        }
        """
        pass
    
    async def attempt_frame_repair(self, frame: dict) -> dict:
        """Try to recover corrupted frame."""
        pass
    
    async def heuristic_unwind(self, initial_address: int) -> list[dict]:
        """Unwind stack using heuristics if frame chain broken."""
        # - Look for return address patterns on stack
        # - Validate against code sections
        # - Estimate frame boundaries
        pass
```

### 3.8: Advanced Analysis CLI Commands (Week 4)

**Deliverable**: New CLI commands for advanced analysis

```bash
# New Phase 3 commands
baldrick analyze-registers --pid PID              # Interpret registers
baldrick analyze-heap --pid PID                   # Full heap analysis
baldrick find-corruption --pid PID                # Detect corruption patterns
baldrick validate-backtrace --pid PID < TRACE    # Validate frame chain
baldrick memory-visualization --pid PID           # ASCII memory layout
baldrick stack-unwind-heuristic --pid PID        # Heuristic unwinding
```

---

## Phase 3 Deliverables Summary

| Feature | Status | Files | Tests |
|---------|--------|-------|-------|
| **GDB Bridge** | New | gdb_bridge.py | test_gdb_bridge.py |
| **GDB Commands** | New | gdb_commands.py | test_gdb_commands.py |
| **GDB Integration** | New | gdb_integration.py | test_gdb_integration.py |
| **Register Interpreter** | New | register_analyzer.py | test_register_analyzer.py |
| **Heap Analyzer** | New | heap_analyzer.py | test_heap_analyzer.py |
| **Stack Validator** | New | stack_validator.py | test_stack_validator.py |
| **Type Inference** | New | type_inference.py | test_type_inference.py |
| **Memory Visualization** | New | memory_visualizer.py | test_memory_visualizer.py |
| **CLI Commands** | Extended | cli/main.py | test_cli_phase3.py |

### Code Statistics (Estimated)
- **New implementation code**: ~2,000 lines
- **Test code**: ~1,500 lines
- **Documentation**: 5 comprehensive guides

### Performance Targets
- **Register interpretation**: <5ms per register
- **Heap analysis**: <500ms for typical heap
- **Stack validation**: <100ms for 100-frame trace
- **Memory visualization**: <200ms for ASCII output

---

## Phase 3 Success Criteria

### Functional
- [ ] GDB commands fully functional with example program
- [ ] Register interpretation working for all supported architectures
- [ ] Heap corruption detected in test case
- [ ] Stack unwinding validation accurate >90%
- [ ] All CLI commands implemented and tested

### Performance
- [ ] Register interpretation <5ms per register
- [ ] Heap analysis <500ms
- [ ] No memory leaks in GDB integration
- [ ] CLI commands complete in <1s

### Quality
- [ ] 100% type safety (mypy)
- [ ] >80% test coverage
- [ ] All new code properly documented
- [ ] Integration tests passing

### Documentation
- [ ] GDB Integration Guide
- [ ] Register Interpreter Guide
- [ ] Heap Analysis Guide
- [ ] Stack Unwinding Guide
- [ ] Updated CLAUDE.md

---

## Timeline (Estimated: 5 weeks)

```
Week 1: GDB Interface Design + Register Interpreter basics
Week 2: GDB Native Commands + Register Interpreter completion
Week 3: GDB Integration Testing + Heap Analyzer
Week 4: GDB Installation & Docs + Stack Validator + Advanced CLI
Week 5: Integration testing, documentation, stabilization
```

---

## Dependencies & Prerequisites

### Required
- ✅ Phase 2 completion (backtrace decoding, memory analysis)
- ✅ Architecture abstraction layer
- GDB 10.0+ with Python support
- Python 3.12+ (already required)

### Optional
- ptrace permissions for live process analysis
- Debug symbols in binaries (for best results)

---

## Transition to Phase 4

Phase 3 completes local, offline debugging capabilities. Phase 4 will add:
- Remote service (FastAPI)
- Live GDB session support
- Network debugging capabilities

See `PHASE_4_ROADMAP.md` for details.

---

**Phase 3 Status**: 📋 **PLANNED AND READY FOR IMPLEMENTATION**
