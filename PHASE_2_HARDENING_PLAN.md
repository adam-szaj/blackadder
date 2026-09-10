# Phase 2 Production Hardening Plan

## Scope

Polish Phase 2.1-2.3 for production deployment:
1. **Comprehensive error handling** with clear messages
2. **Input validation** at all boundaries
3. **Resource limits** to prevent exhaustion
4. **Graceful degradation** when subsystems fail
5. **Edge case handling** for malformed data
6. **Logging** for diagnostics
7. **Performance benchmarks** with targets

---

## 1. Error Handling Strategy

### Current State
- Basic try/except in some methods
- Limited error context
- Some silent failures

### Target State
- **Named exceptions** for each failure type
- **Clear error messages** with context (file, address, etc.)
- **Retry logic** where applicable
- **Fallback paths** instead of crashes
- **Logging** at WARNING/ERROR levels

### Areas to Harden
1. **File Operations**
   - Missing files → clear error, suggestion
   - Permission denied → "check file permissions"
   - Corrupt data → "file appears malformed"

2. **Database Operations**
   - Connection failures → retry, timeout
   - Query errors → validation failed, try reparsing
   - Constraint violations → duplicate entry

3. **Subprocess Execution**
   - Tool not found (objdump, readelf) → clear message
   - Tool crashes → capture stderr
   - Timeout → "binary too large or system overloaded"

4. **Memory Operations**
   - Invalid address → "address out of process range"
   - Missing mapping → "address not in any mapping"
   - Overflow risks → cap allocations

---

## 2. Input Validation

### Validate at Entry Points

**CLI Arguments**:
- PID > 0, reasonable (<2^31)
- File paths exist and are readable
- Database paths writable
- Jobs count 1-256

**Database Queries**:
- Process ID exists before analysis
- Mapping contains address
- Binary file accessible

**File Parsing**:
- File not empty
- ELF magic present
- Size reasonable (not > 4GB)

**Memory Analysis**:
- Address range valid (start < end)
- Permissions string valid (4 chars, [rwx-p])
- Size not negative

---

## 3. Resource Limits

### Prevent DOS / Resource Exhaustion

**Process Analysis**:
```python
MAX_REGIONS = 10000          # Prevent memory explosion
MAX_REGION_SIZE = 0x40000000  # 1GB per region (set threshold)
MAX_BACKTRACES = 100000       # Prevent unbounded caching
MAX_SYMBOLS_PER_BINARY = 1000000
```

**Core Dump Parsing**:
```python
MAX_CORE_DUMP_SIZE = 0x40000000  # 1GB limit
MAX_PROGRAM_HEADERS = 10000
MAX_NOTE_SIZE = 0x100000  # 1MB per note
```

**Analysis**:
```python
MAX_REGIONS_TO_ANALYZE = 5000
MAX_ANOMALIES_PER_REGION = 10
ANALYSIS_TIMEOUT = 30  # seconds
```

**Database**:
```python
MAX_CONCURRENT_QUERIES = 10
QUERY_TIMEOUT = 30  # seconds
MAX_DB_SIZE = 0x4000000000  # 16GB
```

---

## 4. Graceful Degradation

### When Subsystems Fail

**Missing Binary**:
- Can't exact match → try fuzzy match
- Can't fuzzy match → use symbol table only
- No symbols → show addresses only

**Core Dump Parse Failure**:
- Can't parse PT_NOTE → continue with memory segments
- Can't parse headers → return empty mappings
- Can't read file → clear error with suggestion

**Register Extraction Failure**:
- PT_NOTE missing → analysis without register state
- Register parsing fails → analyze without stack detection

**Memory Analysis Failure**:
- Classification fails → mark as UNKNOWN
- Anomaly detection fails → skip anomalies, continue

**Subprocess Failure**:
- objdump missing → fall back to Python ELF parsing (future)
- readelf timeout → return partial results
- Tool crashes → log error, return None gracefully

---

## 5. Edge Cases to Handle

### Parsing
- [ ] Empty files
- [ ] Truncated files (header ok, data missing)
- [ ] Malformed ELF (bad magic, corrupted headers)
- [ ] Zero-sized sections
- [ ] Negative offsets / sizes
- [ ] Circular references (unlikely but check)

### Memory Analysis
- [ ] Regions with same start/end address
- [ ] Overlapping regions (shouldn't happen but validate)
- [ ] Permission string wrong format
- [ ] Pathname with special characters
- [ ] Addresses wrapping (0xffffffff...)

### Database
- [ ] Duplicate binary IDs
- [ ] Missing foreign keys (data corruption)
- [ ] Stale connections
- [ ] Concurrent writes (SQLite limitations)

### Symbol Resolution
- [ ] Address outside all mappings
- [ ] Symbol at address 0x0
- [ ] Very large offsets (> binary size)
- [ ] Demangling failure (C++ symbols)

---

## 6. Logging Strategy

### Levels
- **DEBUG**: Entry/exit of functions, parameter values
- **INFO**: Major operations (loaded process, decoded backtrace)
- **WARNING**: Unusual conditions (missing symbol, file truncated)
- **ERROR**: Failures with recovery
- **CRITICAL**: Failures without recovery (exit)

### Key Points to Log
```python
# Function entry/exit (DEBUG)
logger.debug(f"Analyzing memory for process {process_id}")
logger.debug(f"Analysis complete: {region_count} regions, {anomaly_count} anomalies")

# Tool execution (DEBUG)
logger.debug(f"Running: {' '.join(cmd)}")
logger.debug(f"Tool output: {output[:200]}...")  # First 200 chars

# Warnings (WARNING)
logger.warning(f"Symbol not found for {binary_path}:{offset:#x}, using ???")
logger.warning(f"Core dump file truncated, parsed {segment_count} segments")

# Errors (ERROR)
logger.error(f"Failed to parse core dump: {e}")
logger.error(f"Database query failed, retrying: {e}")

# Critical (CRITICAL)
logger.critical(f"Cannot proceed without database access: {e}")
```

---

## 7. Performance Benchmarks

### Target Performance

| Operation | Data | Target | Status |
|-----------|------|--------|--------|
| Load process | 100 mappings | <100ms | ✓ |
| Fuzzy match binary | 50 candidates | <50ms | ✓ |
| Load core dump | Typical | <200ms | ✓ |
| Analyze memory | 100 regions | <50ms | ✓ |
| Decode backtrace | 100 frames | <200ms | ✓ |
| Full workflow | Typical core | <1s | ? |

### Benchmarking Code
```python
# Add to tests/test_performance.py
import time

@pytest.mark.performance
async def test_backtrace_decode_100_frames(process_db):
    start = time.time()
    frames = await process_db.decode_backtrace(pid, [0x400a1c] * 100)
    elapsed = time.time() - start
    
    assert elapsed < 0.25, f"Decoded 100 frames in {elapsed:.3f}s (target: <250ms)"
```

---

## 8. Implementation Plan

### Phase 3.1: Error Handling (2-3 hours)
1. Create custom exception hierarchy
2. Add error handling to all public methods
3. Implement retry logic for transient errors
4. Add clear error messages with context

### Phase 3.2: Input Validation (1-2 hours)
1. Validate CLI arguments
2. Validate database inputs
3. Add bounds checking
4. Reject invalid data early

### Phase 3.3: Resource Limits (1 hour)
1. Define limits in config
2. Add size/count checks
3. Implement timeouts
4. Handle graceful degradation

### Phase 3.4: Logging (1-2 hours)
1. Set up logger in each module
2. Add strategic log points
3. Include context in logs
4. Test log output

### Phase 3.5: Edge Cases & Tests (2-3 hours)
1. Add edge case tests
2. Malformed data tests
3. Resource limit tests
4. Performance benchmarks

### Phase 3.6: Documentation (1 hour)
1. Add error codes/meanings doc
2. Add troubleshooting guide
3. Update CLAUDE.md with error handling
4. Add logging configuration docs

---

## Success Criteria

- [ ] All public methods have error handling
- [ ] Invalid inputs rejected at entry points
- [ ] Resource limits enforced (max regions, size, etc.)
- [ ] Graceful degradation when subsystems fail
- [ ] 100+ edge case tests pass
- [ ] Performance benchmarks <targets
- [ ] All log levels used appropriately
- [ ] Zero uncaught exceptions in normal operation
- [ ] Clear error messages for common failures
- [ ] Troubleshooting documentation complete

---

## Files to Modify

### New Files
- `baldrick/exceptions.py` - Custom exceptions
- `baldrick/logging_config.py` - Logging setup
- `tests/test_performance.py` - Performance benchmarks
- `tests/test_edge_cases.py` - Edge case coverage
- `docs/TROUBLESHOOTING.md` - User guide
- `docs/ERROR_CODES.md` - Error reference

### Modified Files
- `baldrick/memory_analyzer.py` - Error handling, validation
- `baldrick/binutils/coredump.py` - Error handling, limits
- `baldrick/binutils/hasher.py` - Error handling
- `baldrick/binutils/matcher.py` - Error handling
- `baldrick/db/process.py` - Error handling, timeouts
- `baldrick/db/rootfs.py` - Error handling
- `baldrick/cli/main.py` - Validation, error display
- `baldrick/config.py` - Resource limits
- `baldrick/models.py` - Validation rules
- `CLAUDE.md` - Error handling guidelines

---

## Estimated Effort

- **Total time**: 8-12 hours
- **Lines added**: 400-600 (error handling, validation, logging)
- **Tests added**: 40-50 (edge cases, performance, error paths)
- **Documentation**: 500+ lines

---

## Rollout Strategy

1. **Phase 1**: Error handling (makes code more robust immediately)
2. **Phase 2**: Validation & limits (prevents bad inputs)
3. **Phase 3**: Logging (helps with debugging)
4. **Phase 4**: Tests & benchmarks (verifies everything)
5. **Phase 5**: Documentation (helps users)

Can ship after Phase 1-2 (most critical). Phases 3-5 improve observability and polish.
