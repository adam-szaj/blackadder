# Phase 4 Roadmap: Remote Service & Live GDB Support

## Overview

Phase 4 focuses on **remote debugging capabilities**: a FastAPI service backend and live GDB session support. This enables Blackadder to act as a remote debugging server for embedded systems, containers, and distributed debugging scenarios.

## Phase 4 Scope

Phase 4 is divided into two tracks:

### Track A: Remote FastAPI Service (Weeks 1-4)
### Track B: Live GDB Session Support (Weeks 3-6)

---

## Track A: Remote FastAPI Service

### Goal
Create a production-ready FastAPI service that exposes Blackadder analysis capabilities over HTTP, enabling remote clients (embedded GDB, web tools, CI/CD) to access debugging features.

### 4.1: FastAPI Service Architecture (Week 1)

**Deliverable**: Service design and data models

#### 4.1.1 API Specification
```python
# blackadder/service/api.py

from fastapi import FastAPI, HTTPException, WebSocket
from pydantic import BaseModel

app = FastAPI(
    title="Blackadder Debugging Service",
    description="Remote debugging engine for Linux binaries",
    version="1.0.0",
)

# ============================================================================
# Data Models
# ============================================================================

class AnalysisSession(BaseModel):
    """Represents a debugging session."""
    session_id: str
    pid: int
    process_name: str
    binary_path: str
    created_at: datetime
    architecture: str
    memory_size: int
    thread_count: int

class BacktraceDecodeRequest(BaseModel):
    """Request to decode backtrace."""
    addresses: list[int]
    format: str = "raw"  # "raw", "gdb", "kernel"

class BacktraceDecodeResponse(BaseModel):
    """Decoded backtrace with symbols."""
    frames: list[dict]
    decode_time_ms: float
    cache_hits: int

class MemoryAnalysisRequest(BaseModel):
    """Request memory analysis for region."""
    start_addr: int
    end_addr: int
    include_contents: bool = False

class MemoryAnalysisResponse(BaseModel):
    """Memory region analysis."""
    regions: list[dict]
    total_size: int
    anomalies: list[dict]
    analysis_time_ms: float

class RegisterState(BaseModel):
    """CPU register state."""
    architecture: str
    registers: dict[str, int | None]

class RegisterInterpretationResponse(BaseModel):
    """Interpreted register values."""
    interpretations: dict[str, dict]
    calling_convention: str
    locals: list[dict]

# ============================================================================
# REST Endpoints
# ============================================================================

@app.post("/api/v1/sessions", response_model=AnalysisSession)
async def create_session(pid: int) -> AnalysisSession:
    """
    Create a new analysis session for a process.
    
    Returns session info including architecture, memory layout, etc.
    """
    pass

@app.get("/api/v1/sessions/{session_id}", response_model=AnalysisSession)
async def get_session(session_id: str) -> AnalysisSession:
    """Get existing session info."""
    pass

@app.post("/api/v1/sessions/{session_id}/backtrace", response_model=BacktraceDecodeResponse)
async def decode_backtrace(
    session_id: str,
    request: BacktraceDecodeRequest,
) -> BacktraceDecodeResponse:
    """
    Decode backtrace for session.
    
    - Supports multiple formats (raw hex, GDB, kernel)
    - Resolves addresses to symbols
    - Returns memory type info
    """
    pass

@app.post("/api/v1/sessions/{session_id}/memory/analyze")
async def analyze_memory(
    session_id: str,
    request: MemoryAnalysisRequest,
) -> MemoryAnalysisResponse:
    """
    Analyze memory region.
    
    - Classify memory types
    - Detect anomalies
    - Show corruption patterns
    """
    pass

@app.post("/api/v1/sessions/{session_id}/registers/interpret")
async def interpret_registers(
    session_id: str,
    request: RegisterState,
) -> RegisterInterpretationResponse:
    """
    Interpret register values in context.
    
    - Detect pointers, strings, values
    - Reconstruct calling convention state
    - Find local variables
    """
    pass

@app.get("/api/v1/sessions/{session_id}/memory/map")
async def get_memory_map(session_id: str):
    """Get memory map for session."""
    pass

@app.get("/api/v1/sessions/{session_id}/binaries")
async def list_binaries(session_id: str):
    """List loaded binaries for session."""
    pass

@app.post("/api/v1/symbols/resolve")
async def resolve_symbol(binary: str, address: int):
    """Resolve address to symbol."""
    pass

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}
```

#### 4.1.2 Service Configuration
```python
# blackadder/service/config.py

class ServiceConfig(BaseSettings):
    """Configuration for remote service."""
    
    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    workers: int = Field(default_factory=lambda: os.cpu_count() or 4)
    
    # Database settings (from Phase 2)
    rootfs_db: str = "sqlite+aiosqlite:///blackadder-rootfs.db"
    process_db: str = "sqlite+aiosqlite:///blackadder-process.db"
    
    # Security
    auth_token: str | None = None  # Optional auth token
    max_sessions: int = 100
    max_session_duration_hours: int = 24
    
    # Performance
    max_subprocess_workers: int = Field(default_factory=lambda: min(32, os.cpu_count() or 4))
    max_symbol_cache_size: int = 100_000
    max_memory_analysis_size: int = 1024 * 1024 * 1024  # 1GB
    
    # Features
    enable_live_gdb: bool = True
    enable_core_dump_upload: bool = True
    enable_memory_dump: bool = False  # Security-sensitive
    
    class Config:
        env_file = ".env.service"
        env_prefix = "BLACKADDER_"
```

### 4.2: Session Management (Week 1-2)

**Deliverable**: Lifecycle management for analysis sessions

#### 4.2.1 Session Store
```python
# blackadder/service/sessions.py

class SessionManager:
    """Manage analysis sessions and their lifecycle."""
    
    def __init__(self, config: ServiceConfig):
        self.config = config
        self.sessions: dict[str, AnalysisSession] = {}
        self.cleanup_task = None
    
    async def create_session(self, pid: int) -> AnalysisSession:
        """
        Create new session for process.
        
        1. Load /proc/{pid}/maps
        2. Auto-detect architecture
        3. Initialize databases
        4. Load symbol information
        5. Return session info
        """
        session_id = uuid4()
        
        process_db = ProcessDatabase(manager, self.config)
        mappings = await process_db.load_maps_from_proc(pid)
        arch = detect_architecture_from_pid(pid)
        
        session = AnalysisSession(
            session_id=str(session_id),
            pid=pid,
            process_name=get_process_name(pid),
            binary_path=get_binary_path(pid),
            created_at=datetime.now(),
            architecture=arch.arch_variant,
            memory_size=sum(m.end_addr - m.start_addr for m in mappings),
            thread_count=get_thread_count(pid),
        )
        
        self.sessions[session_id] = session
        
        # Schedule cleanup
        asyncio.create_task(self._cleanup_session(session_id))
        
        return session
    
    async def _cleanup_session(self, session_id: str):
        """Clean up session after timeout."""
        await asyncio.sleep(self.config.max_session_duration_hours * 3600)
        await self.delete_session(session_id)
    
    async def delete_session(self, session_id: str):
        """Clean up and remove session."""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            # Close databases
            # Clean up resources
            del self.sessions[session_id]
    
    def get_session(self, session_id: str) -> AnalysisSession:
        """Get session by ID."""
        if session_id not in self.sessions:
            raise HTTPException(status_code=404, detail="Session not found")
        return self.sessions[session_id]
```

### 4.3: Service Endpoints Implementation (Week 2-3)

**Deliverable**: Fully functional REST API

#### 4.3.1 Backtrace Endpoint
```python
@app.post("/api/v1/sessions/{session_id}/backtrace")
async def decode_backtrace(
    session_id: str,
    request: BacktraceDecodeRequest,
) -> BacktraceDecodeResponse:
    """
    Decode backtrace addresses to symbols.
    
    Features:
    - Format auto-detection (raw, GDB, kernel)
    - Parallel address resolution
    - Symbol caching
    - Memory type classification
    - Performance timing
    """
    session = session_manager.get_session(session_id)
    
    start_time = time.time()
    
    # Parse request addresses
    if request.format == "auto":
        request.format = detect_backtrace_format(request.addresses)
    
    # Decode backtrace
    process_db = get_session_database(session_id)
    frames = await process_db.decode_backtrace(session.pid, request.addresses)
    
    # Add memory type info
    for frame in frames:
        region = process_db.classify_address(frame.address)
        frame.memory_type = region.type
        frame.anomalies = region.anomalies
    
    decode_time = (time.time() - start_time) * 1000
    
    return BacktraceDecodeResponse(
        frames=frames,
        decode_time_ms=decode_time,
        cache_hits=process_db.symbol_cache.hits,
    )
```

#### 4.3.2 Memory Analysis Endpoint
```python
@app.post("/api/v1/sessions/{session_id}/memory/analyze")
async def analyze_memory(
    session_id: str,
    request: MemoryAnalysisRequest,
) -> MemoryAnalysisResponse:
    """Analyze memory region for corruption and anomalies."""
    session = session_manager.get_session(session_id)
    
    analyzer = MemoryAnalyzer(self.config)
    
    # Get mappings in range
    process_db = get_session_database(session_id)
    mappings = process_db.get_mappings_in_range(
        request.start_addr, request.end_addr
    )
    
    # Analyze each region
    regions = []
    anomalies = []
    
    for mapping in mappings:
        region_type, confidence = analyzer.classify_region(
            mapping.pathname,
            mapping.start_addr,
            mapping.end_addr,
            mapping.perms,
            mapping.offset,
        )
        
        anomalies_list = analyzer.detect_anomalies(
            region_type, mapping.perms, mapping.end_addr - mapping.start_addr, mapping.pathname
        )
        
        if anomalies_list:
            anomalies.extend(anomalies_list)
        
        regions.append({
            "start": hex(mapping.start_addr),
            "end": hex(mapping.end_addr),
            "size": mapping.end_addr - mapping.start_addr,
            "type": region_type.value,
            "confidence": confidence,
            "permissions": mapping.perms,
            "path": mapping.pathname,
            "anomalies": anomalies_list,
        })
    
    return MemoryAnalysisResponse(
        regions=regions,
        total_size=sum(r["size"] for r in regions),
        anomalies=anomalies,
        analysis_time_ms=0,
    )
```

### 4.4: Authentication & Authorization (Week 3)

**Deliverable**: Security layer for remote service

#### 4.4.1 Auth Middleware
```python
# blackadder/service/auth.py

class TokenAuth:
    """Token-based authentication."""
    
    def __init__(self, token: str | None):
        self.token = token
    
    async def verify_token(self, request: Request):
        """Verify auth token in request."""
        if not self.token:
            return  # No auth required
        
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing auth token")
        
        token = auth_header[7:]  # Remove "Bearer " prefix
        if token != self.token:
            raise HTTPException(status_code=401, detail="Invalid token")

class ProcessAccessControl:
    """Limit which processes can be analyzed."""
    
    async def can_analyze_process(self, pid: int) -> bool:
        """Check if process can be analyzed."""
        # - Check if running as same user
        # - Check PID is in whitelist
        # - Check SELinux/AppArmor permissions
        pass
```

### 4.5: Deployment & Containerization (Week 4)

**Deliverable**: Production-ready deployment

#### 4.5.1 Docker Setup
```dockerfile
# Dockerfile

FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    binutils \
    gdb \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY blackadder/ ./blackadder/

# Create data directory
RUN mkdir -p /var/lib/blackadder

# Expose API port
EXPOSE 8000

# Run service
CMD ["blackadder-service", "--host", "0.0.0.0", "--port", "8000"]
```

#### 4.5.2 Docker Compose
```yaml
# docker-compose.yml

version: '3.8'

services:
  blackadder:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - blackadder-data:/var/lib/blackadder
      - /proc:/proc:ro  # Read-only access to /proc
    environment:
      - BLACKADDER_DEBUG=false
      - BLACKADDER_WORKERS=4
    restart: unless-stopped

volumes:
  blackadder-data:
```

---

## Track B: Live GDB Session Support

### Goal
Enable Blackadder to attach to live GDB sessions, providing enhanced analysis of running processes in real-time.

### 4.6: GDB Attachment Protocol (Week 3)

**Deliverable**: GDB protocol implementation

#### 4.6.1 GDB Machine Interface (MI) Client
```python
# blackadder/service/gdb_client.py

class GDBMIClient:
    """Connect to GDB via Machine Interface."""
    
    async def connect(self, gdb_port: int = 9001):
        """Connect to GDB MI socket."""
        self.reader, self.writer = await asyncio.open_connection(
            "127.0.0.1", gdb_port
        )
        self.listening_task = asyncio.create_task(self._listen_loop())
    
    async def send_command(self, cmd: str) -> dict:
        """Send MI command and get response."""
        self.writer.write(f"{cmd}\n".encode())
        await self.writer.drain()
        
        # Wait for response with timeout
        response = await asyncio.wait_for(
            self._get_response(), timeout=5.0
        )
        return response
    
    async def get_frames(self) -> list[dict]:
        """Get current backtrace from GDB."""
        response = await self.send_command("-stack-list-frames")
        return parse_frame_response(response)
    
    async def get_registers(self) -> dict:
        """Get current register state from GDB."""
        response = await self.send_command("-data-list-register-values x")
        return parse_register_response(response)
    
    async def read_memory(self, address: int, length: int) -> bytes:
        """Read memory from inferior."""
        response = await self.send_command(
            f"-data-read-memory-bytes {hex(address)} {length}"
        )
        return parse_memory_response(response)
    
    async def get_inferior_info(self) -> dict:
        """Get info about inferior process."""
        response = await self.send_command("-list-thread-groups --available")
        return parse_inferior_info(response)
    
    async def _listen_loop(self):
        """Listen for async notifications from GDB."""
        while True:
            try:
                line = await self.reader.readline()
                if not line:
                    break
                
                # Handle async notifications
                await self._handle_notification(line.decode())
            except asyncio.CancelledError:
                break
```

### 4.7: Live Process Integration (Week 4)

**Deliverable**: Real-time analysis of running processes

#### 4.7.1 Live Session Handler
```python
# blackadder/service/live_gdb.py

class LiveGDBSession:
    """Manage live GDB session with real-time analysis."""
    
    def __init__(self, gdb_mi_client: GDBMIClient, service_config: ServiceConfig):
        self.gdb = gdb_mi_client
        self.config = service_config
        self.breakpoint_callbacks: dict[int, callable] = {}
    
    async def attach_to_gdb(self, gdb_port: int = 9001):
        """Attach to running GDB instance."""
        await self.gdb.connect(gdb_port)
        
        # Register breakpoint handler
        self.gdb.on_breakpoint = self._on_breakpoint_hit
    
    async def _on_breakpoint_hit(self, frame_info: dict):
        """Handle breakpoint hit."""
        # Auto-analyze backtrace
        frames = await self.gdb.get_frames()
        registers = await self.gdb.get_registers()
        
        # Run Blackadder analysis
        analysis = await self._analyze_current_state(frames, registers)
        
        # Notify subscribers
        await self._notify_subscribers("breakpoint_hit", analysis)
    
    async def _analyze_current_state(self, frames: list, registers: dict) -> dict:
        """Analyze current state at breakpoint."""
        interpreter = RegisterInterpreter(self.arch, self.memory_layout)
        
        return {
            "backtrace_analysis": await self._decode_backtrace(frames),
            "register_interpretation": interpreter.interpret_all_registers(registers),
            "memory_context": await self._get_memory_context(frames[0]),
            "potential_issues": await self._detect_issues(frames, registers),
        }
    
    async def subscribe_to_analysis(self, callback: callable):
        """Subscribe to real-time analysis updates."""
        # When breakpoint hits, analysis is sent to callback
        pass
```

### 4.8: WebSocket Support (Week 5)

**Deliverable**: Real-time streaming via WebSocket

#### 4.8.1 WebSocket Endpoint
```python
@app.websocket("/api/v1/gdb/live")
async def gdb_live_stream(websocket: WebSocket):
    """
    WebSocket endpoint for live GDB analysis.
    
    Connection flow:
    1. Client connects via WebSocket
    2. Server attaches to local GDB instance
    3. Server streams analysis results as breakpoints hit
    4. Client receives real-time updates
    """
    await websocket.accept()
    
    try:
        # Attach to GDB
        gdb_mi = GDBMIClient()
        live_session = LiveGDBSession(gdb_mi, config)
        
        # Subscribe to analysis updates
        async def send_update(event: str, analysis: dict):
            await websocket.send_json({
                "event": event,
                "timestamp": datetime.now().isoformat(),
                "data": analysis,
            })
        
        live_session.subscribe_to_analysis(send_update)
        
        # Keep connection alive
        while True:
            msg = await websocket.receive_text()
            if msg == "disconnect":
                break
    
    finally:
        await websocket.close()
```

### 4.9: GDB Remote Protocol Bridge (Week 5-6)

**Deliverable**: GDB remote debugging protocol support

#### 4.9.1 GDB Remote Protocol Server
```python
# blackadder/service/gdb_remote.py

class GDBRemoteServer:
    """
    Implement GDB Remote Serial Protocol (RSP).
    
    Allows GDB to connect via TCP:
    gdb> target remote localhost:2331
    """
    
    async def start(self, host: str = "0.0.0.0", port: int = 2331):
        """Start GDB RSP server."""
        server = await asyncio.start_server(
            self._handle_client,
            host, port
        )
        
        async with server:
            await server.serve_forever()
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming GDB connection."""
        # Implement RSP packet parsing
        # - g: read registers
        # - G: write registers
        # - m: read memory
        # - M: write memory
        # - c: continue execution
        # - s: single step
        # - z/Z: set/clear breakpoints
        # - qXfer: transfer data (backtrace, memory, etc.)
        
        while True:
            try:
                packet = await self._read_packet(reader)
                response = await self._handle_packet(packet)
                await self._send_packet(writer, response)
            except:
                break
        
        writer.close()
```

---

## Phase 4 Deliverables Summary

| Feature | Status | Files | Tests |
|---------|--------|-------|-------|
| **FastAPI Service** | New | service/api.py | test_api.py |
| **Session Management** | New | service/sessions.py | test_sessions.py |
| **Auth & Security** | New | service/auth.py | test_auth.py |
| **GDB MI Client** | New | service/gdb_client.py | test_gdb_client.py |
| **Live GDB Integration** | New | service/live_gdb.py | test_live_gdb.py |
| **WebSocket Support** | New | service/websocket.py | test_websocket.py |
| **GDB Remote Protocol** | New | service/gdb_remote.py | test_gdb_remote.py |
| **Deployment** | New | Dockerfile, docker-compose.yml | - |
| **Service CLI** | New | cli/service.py | test_service_cli.py |

### Code Statistics (Estimated)
- **New implementation code**: ~2,500 lines
- **Test code**: ~2,000 lines
- **Documentation**: 5 comprehensive guides

### Performance Targets
- **API response time**: <100ms for typical requests
- **WebSocket latency**: <50ms for updates
- **Maximum concurrent sessions**: 100
- **Memory per session**: ~50MB

---

## Phase 4 Success Criteria

### Functional
- [ ] FastAPI service starts and serves requests
- [ ] All REST endpoints functional and tested
- [ ] Session management working (create, list, delete)
- [ ] GDB MI client connects and communicates
- [ ] Live GDB analysis working
- [ ] WebSocket real-time streaming working
- [ ] Docker deployment working

### Performance
- [ ] REST API response time <100ms
- [ ] WebSocket latency <50ms
- [ ] Support 100+ concurrent sessions
- [ ] No memory leaks in long-running sessions

### Security
- [ ] Authentication/authorization working
- [ ] Process access control enforced
- [ ] Input validation on all endpoints
- [ ] Rate limiting implemented
- [ ] No sensitive data in logs

### Quality
- [ ] 100% type safety (mypy)
- [ ] >80% test coverage
- [ ] All new code properly documented
- [ ] Integration tests passing
- [ ] Load testing passed (100+ sessions)

### Documentation
- [ ] API Reference Guide (OpenAPI/Swagger)
- [ ] Service Installation Guide
- [ ] GDB Integration Guide
- [ ] WebSocket Client Guide
- [ ] Deployment Guide
- [ ] Updated CLAUDE.md

---

## Timeline (Estimated: 6 weeks)

```
Week 1: FastAPI service architecture + Session management
Week 2: Service endpoints (backtrace, memory, registers)
Week 3: Auth/security + GDB MI client
Week 4: Live GDB integration + Deployment
Week 5: WebSocket support + GDB Remote Protocol
Week 6: Integration testing, documentation, stabilization
```

---

## Dependencies & Prerequisites

### Required
- ✅ Phase 2 completion (core analysis engine)
- ✅ Phase 3 completion (register interpretation, memory analysis)
- FastAPI 0.100+
- Pydantic 2.0+
- aiosqlite (already used)

### Optional
- GDB with MI support (for live debugging)
- Docker (for deployment)

---

## Deployment Scenarios

### Scenario 1: Local Service (Single Machine)
```bash
# Start service on localhost
blackadder-service --host 127.0.0.1 --port 8000

# Connect from GDB
gdb -ex "target remote localhost:2331"
```

### Scenario 2: Embedded Systems
```bash
# Run in Docker on development machine
docker-compose up

# GDB on embedded target connects to service
gdb (target)> target remote dev-machine:2331
```

### Scenario 3: CI/CD Pipeline
```bash
# Analyze core dumps automatically
curl -X POST http://blackadder:8000/api/v1/sessions \
  -H "Authorization: Bearer $TOKEN" \
  -d "pid=$PID"

curl -X POST http://blackadder:8000/api/v1/sessions/$SESSION_ID/analyze \
  -H "Authorization: Bearer $TOKEN"
```

---

## Future Enhancements (Phase 4+)

### Short Term
- TLS/HTTPS support
- Multi-user support with RBAC
- Persistent session storage
- Session replay/recording

### Medium Term
- Web dashboard for visualization
- Mobile app support
- Integration with debugger UIs
- Performance profiling

### Long Term
- Distributed debugging across multiple machines
- Kubernetes integration
- Multi-process debugging
- VM/container integration

---

## Transition Post Phase 4

After Phase 4 completion, Blackadder will be:
- ✅ Production-ready debugging engine (Phase 2)
- ✅ Local GDB integration with advanced analysis (Phase 3)
- ✅ Remote service with live debugging (Phase 4)

Potential future phases:
- **Phase 5**: Machine learning-based anomaly detection
- **Phase 6**: Integration with popular debuggers (VS Code, CLion, etc.)
- **Phase 7**: Distributed debugging across clusters

---

**Phase 4 Status**: 📋 **PLANNED AND READY FOR IMPLEMENTATION**
