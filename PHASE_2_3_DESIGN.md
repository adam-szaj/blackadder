# Phase 2.3 Design: Enhanced Memory Analysis

## Context

Phase 2.2 successfully parses ELF core dumps and reconstructs memory layout. Phase 2.3 extends this with:
1. **Register State Extraction**: Parse PT_NOTE sections for CPU registers
2. **Memory Region Classification**: Identify heap, stack, vdso, vsyscall, JIT regions
3. **Memory Analysis**: Detect patterns (leaks, corruption, anomalies)

## Scope

### 2.3.1: Register State Extraction

**Goal**: Extract CPU registers (RSP, RBP, RIP, etc.) from core dump PT_NOTE sections

**Design**:

#### 1. New ORM Model (models.py)

```python
class ProcessRegisterState(SQLModel, table=True):
    """CPU register state from core dump PT_NOTE sections."""
    
    id: Optional[int] = Field(default=None, primary_key=True)
    process_id: int = Field(foreign_key="processsnapshot.id", index=True)
    
    # General purpose registers (x86-64)
    rax: Optional[int] = None
    rbx: Optional[int] = None
    rcx: Optional[int] = None
    rdx: Optional[int] = None
    rsi: Optional[int] = None
    rdi: Optional[int] = None
    rbp: Optional[int] = None  # Frame pointer
    rsp: Optional[int] = None  # Stack pointer
    rip: Optional[int] = None  # Instruction pointer (crash location)
    
    # Special registers
    r8: Optional[int] = None
    r9: Optional[int] = None
    r10: Optional[int] = None
    r11: Optional[int] = None
    r12: Optional[int] = None
    r13: Optional[int] = None
    r14: Optional[int] = None
    r15: Optional[int] = None
    
    # Flags
    eflags: Optional[int] = None
    
    # Relationships
    process: ProcessSnapshot = Relationship(back_populates="register_state")
```

Add to ProcessSnapshot:
```python
register_state: Optional["ProcessRegisterState"] = Relationship(back_populates="process")
```

#### 2. PT_NOTE Parser (coredump.py enhancement)

```python
class CoreDumpParser:
    async def extract_register_state(self, core_path: str) -> dict:
        """
        Extract register state from PT_NOTE section.
        
        Strategy:
        1. Parse readelf -n output for NT_PRSTATUS note
        2. Extract register values from note
        3. Return {reg_name: value, ...}
        
        Returns:
            {
                'rax': 0x...,
                'rbx': 0x...,
                'rip': 0x...,  # Crash location
                'rsp': 0x...,
                'rbp': 0x...,
                ...
            }
        """
        pass
    
    @staticmethod
    def parse_elf_notes(readelf_output: str) -> list[dict]:
        """
        Parse readelf -n output for PT_NOTE sections.
        
        Extract:
        - Note type (NT_PRSTATUS, NT_FPREGSET, etc.)
        - Note name
        - Descriptor (raw data)
        
        Returns:
            [
                {
                    'type': 'NT_PRSTATUS',
                    'name': 'CORE',
                    'descriptor': b'...',
                },
                ...
            ]
        """
        pass
    
    @staticmethod
    def parse_nt_prstatus(descriptor_bytes: bytes) -> dict:
        """
        Parse NT_PRSTATUS structure to extract registers.
        
        NT_PRSTATUS layout (x86-64):
        - siginfo (128 bytes)
        - pid, ppid, pgrp, sid (16 bytes)
        - utime, stime, cutime, cstime (32 bytes)
        - elf_gregset_t (registers, 18 * 8 bytes)
        - fpvalid (4 bytes)
        
        Returns:
            {
                'pid': int,
                'signal': int,
                'rax': int,
                'rbx': int,
                ...
            }
        """
        pass
```

---

### 2.3.2: Memory Region Classification

**Goal**: Identify memory region types (heap, stack, mmap, etc.)

**Design**:

#### 1. New ORM Model (models.py)

```python
class MemoryRegionType(str, Enum):
    """Classification of memory region type."""
    UNKNOWN = "unknown"
    TEXT = "text"          # .text section (executable)
    DATA = "data"          # .data section
    HEAP = "heap"          # Heap region
    STACK = "stack"        # Stack region
    VDSO = "vdso"          # Virtual dynamic shared object
    VSYSCALL = "vsyscall"  # vsyscall page
    JIT = "jit"            # JIT compiled code
    MMAP = "mmap"          # mmap'd region
    VVAR = "vvar"          # vvar region
    ANON = "anon"          # Anonymous mapping

class MemoryRegionAnalysis(SQLModel, table=True):
    """Analysis results for a memory region."""
    
    id: Optional[int] = Field(default=None, primary_key=True)
    mapping_id: int = Field(foreign_key="memorymapping.id", index=True)
    
    # Classification
    region_type: MemoryRegionType = Field(default=MemoryRegionType.UNKNOWN)
    confidence: float = Field(default=0.0)  # 0.0-1.0 confidence in classification
    
    # Analysis results
    is_writable: bool = False
    is_executable: bool = False
    likely_corrupted: bool = False  # Potential memory corruption detected
    anomalies: str = ""  # JSON-serialized list of detected anomalies
    
    # Relationships
    mapping: MemoryMapping = Relationship(back_populates="analysis")
```

Add to MemoryMapping:
```python
analysis: Optional["MemoryRegionAnalysis"] = Relationship(back_populates="mapping")
```

#### 2. Memory Analyzer Module (memory_analyzer.py)

```python
class MemoryAnalyzer:
    """Analyze and classify memory regions."""
    
    def __init__(self, config):
        self.config = config
    
    async def analyze_process_memory(
        self,
        process_id: int,
        session: AsyncSession,
    ) -> dict[int, MemoryRegionAnalysis]:
        """
        Analyze all memory mappings in a process.
        
        For each MemoryMapping:
        1. Classify region type (heap, stack, vdso, etc.)
        2. Detect potential corruption
        3. Identify anomalies
        
        Returns:
            {mapping_id: MemoryRegionAnalysis, ...}
        """
        pass
    
    @staticmethod
    def classify_region(
        pathname: str,
        start_addr: int,
        end_addr: int,
        perms: str,
        offset: int,
        register_state: Optional[dict] = None,
    ) -> tuple[MemoryRegionType, float]:
        """
        Classify memory region type and confidence.
        
        Heuristics:
        - pathname contains "heap" or start after data section → HEAP
        - near RSP/RBP → STACK
        - pathname contains "vdso" → VDSO
        - pathname contains "vsyscall" → VSYSCALL
        - pathname contains ".so" → MMAP library
        - permissions contains "x" and large size → likely JIT
        - filename is binary name → TEXT/DATA
        
        Returns:
            (MemoryRegionType, confidence: 0.0-1.0)
        """
        pass
    
    @staticmethod
    def detect_anomalies(
        region_type: MemoryRegionType,
        perms: str,
        size: int,
        pathname: str,
    ) -> list[str]:
        """
        Detect potential memory anomalies.
        
        Examples:
        - Executable heap (heap + x permission)
        - Writable stack (stack + w permission, unusual for some systems)
        - Oversized region (> 1GB allocation)
        - Suspicious naming patterns
        
        Returns:
            List of anomaly descriptions
        """
        pass
    
    @staticmethod
    def check_corruption_markers(
        region_type: MemoryRegionType,
        perms: str,
        size: int,
    ) -> bool:
        """
        Check for common memory corruption patterns.
        
        Heuristics:
        - Executable heap (code injection)
        - Heap after stack (memory layout violation)
        - RWX region (unusual, often exploited)
        
        Returns:
            True if potential corruption detected
        """
        pass
```

---

### 2.3.3: Memory Introspection API

**Goal**: Provide high-level queries about memory layout

**Design**:

#### ProcessDatabase Enhancement

```python
class ProcessDatabase:
    async def analyze_memory_layout(
        self,
        process_id: int,
        register_state: Optional[dict] = None,
    ) -> dict:
        """
        Analyze and classify all memory regions.
        
        Returns:
            {
                'regions': {
                    'stack': {...},
                    'heap': {...},
                    'vdso': {...},
                    'libraries': [...],
                    'other': [...]
                },
                'anomalies': [...],
                'corruption_risk': float,
            }
        """
        pass
    
    async def find_region_by_address(
        self,
        process_id: int,
        address: int,
    ) -> Optional[tuple[MemoryMapping, MemoryRegionAnalysis]]:
        """Find and analyze region containing address."""
        pass
    
    async def get_stack_info(
        self,
        process_id: int,
    ) -> Optional[dict]:
        """Get stack region info and bounds."""
        pass
    
    async def get_heap_regions(
        self,
        process_id: int,
    ) -> list[dict]:
        """Get all heap regions (may be fragmented)."""
        pass
```

---

### 2.3.4: CLI Integration

```python
@app.command()
async def analyze_memory(
    pid: int = typer.Option(..., "--pid", "-p", help="Process snapshot ID"),
    db: Optional[str] = typer.Option(None, "--db", "-d"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Show detailed analysis"),
) -> None:
    """
    Analyze memory layout and detect anomalies.
    
    Shows:
    - Memory region classification (heap, stack, libraries, etc.)
    - Register state (if available from core dump)
    - Detected anomalies and corruption risks
    
    Example:
        baldrick analyze-memory --pid 1 --detailed
    """
    pass

@app.command()
async def show_registers(
    pid: int = typer.Option(..., "--pid", "-p", help="Process snapshot ID"),
    db: Optional[str] = typer.Option(None, "--db", "-d"),
) -> None:
    """
    Show CPU register state from core dump.
    
    Displays:
    - General purpose registers (RAX, RBX, etc.)
    - Frame pointer (RBP)
    - Stack pointer (RSP)
    - Instruction pointer (RIP) - crash location
    - Flags register
    
    Example:
        baldrick show-registers --pid 1
    """
    pass
```

---

## Test Strategy

### Unit Tests (test_memory_analyzer.py)

```
TestMemoryRegionClassification:
  - test_classify_heap_region: pathname="heap" → HEAP
  - test_classify_stack_region: near RSP → STACK
  - test_classify_vdso_region: pathname="vdso" → VDSO
  - test_classify_library_region: .so file → MMAP
  - test_classify_jit_region: rwx permissions → JIT
  - test_confidence_scoring: various confidence levels

TestAnomalyDetection:
  - test_executable_heap: heap + x → anomaly
  - test_oversized_region: size > 1GB → anomaly
  - test_writable_stack: stack + w → anomaly (some systems)
  - test_suspicious_naming: unusual names → anomaly

TestCorruptionDetection:
  - test_executable_heap_corruption: code injection marker
  - test_rwx_region_corruption: unusual permissions
```

### Integration Tests (with real processes/core dumps)

```
TestMemoryAnalysisIntegration:
  - test_analyze_real_process: Load real /proc/maps, classify regions
  - test_analyze_core_dump: Load real core dump, extract registers + analyze
  - test_find_address_in_region: Query by address
  - test_get_stack_bounds: Calculate stack limits
```

---

## Implementation Order

1. Add ORM models: ProcessRegisterState, MemoryRegionAnalysis
2. Implement PT_NOTE parser in CoreDumpParser
3. Implement MemoryAnalyzer with classification heuristics
4. Enhance ProcessDatabase with analysis methods
5. Add CLI commands: analyze-memory, show-registers
6. Write comprehensive tests
7. Update documentation

---

## Success Criteria

- [ ] ProcessRegisterState table created and populated from core dumps
- [ ] PT_NOTE parsing extracts all x86-64 registers correctly
- [ ] Memory regions classified with >85% accuracy on common patterns
- [ ] Anomaly detection identifies executable heap, oversized regions
- [ ] CLI commands show readable register and memory analysis
- [ ] Test coverage >80% for analyzer module
- [ ] Performance: analyze 100 regions in <50ms

---

## Future Enhancements (Phase 3+)

1. **Advanced PT_NOTE parsing**: Float registers, AVX state (FPREGSET)
2. **Heap analysis**: Free list corruption, double-free detection
3. **Stack analysis**: Buffer overflow detection, ROP gadget search
4. **Memory diff**: Compare two core dumps to find changes
5. **Visualization**: Generate memory layout diagrams
