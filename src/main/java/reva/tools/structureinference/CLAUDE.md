# CLAUDE.md - Structure Inference Package

This file provides guidance for Claude Code when working with the structure inference tools in the `reva.tools.structureinference` package.

## Package Overview

The `reva.tools.structureinference` package provides MCP tools for inferring structure layouts from memory access patterns in decompiled code. It uses Ghidra's `FillOutStructureHelper` to discover how pointer variables are accessed, then matches against existing structures and detects C++ patterns.

## Key Tools

### `infer-structure`
Analyze functions to infer structure layout from variable access patterns. Two modes:

**Single-function mode:** Analyze one function with a specific variable (or first param if not specified)
```json
{"functions": ["FUN_12345"], "variable": "local_10"}
{"functions": ["FUN_12345"]}  // Uses first param automatically
```

**Multi-function mode (class methods):** Analyze multiple functions, using first parameter of each
```json
{"functions": ["method1", "method2", "method3"]}
```
- Cannot specify `variable` with multiple functions (returns error)
- Aggregates results with confidence scores
- Each function's first parameter is analyzed (for class methods, this is the object pointer)

### `find-matching-structures`
Search existing structures matching a given offset layout

## Key Classes

### FieldInfo (FieldInfo.java)

Tracks field information discovered from memory access patterns. Aggregates multiple accesses to the same offset across functions.

**Key Features:**
- Tracks access types (STORE/LOAD) and counts
- Maintains set of accessing functions for confidence scoring
- Advanced type inference: float detection via PcodeOp, pointer detection via graph traversal
- Array detection (3+ consecutive same-size elements merged)
- Confidence scoring based on function coverage, size consistency, and access patterns

**Usage:**
```java
FieldInfo field = new FieldInfo(offset, size);
field.addAccessWithOp(AccessType.STORE, 4, functionAddress, pcodeOp);
field.performAdvancedInference();  // After all accesses recorded
String type = field.getInferredType();  // e.g., "float*", "int[4]"
Map<String, Object> json = field.toMap(totalFunctions);
```

**Static Utility:**
```java
String typeName = FieldInfo.inferTypeNameFromSize(4, false);  // "int"
String pointerType = FieldInfo.inferTypeNameFromSize(8, true);  // "void*"
```

### AccessType Enum (FieldInfo.java)

Simple enum for memory access types: `STORE`, `LOAD`.

### CppDetector

Utility for detecting whether a program is written in C++. Uses tiered detection with thread-safe caching.

**Strong indicators (any single match = C++):**
- Vtable symbols: `_ZTV`/`__ZTV` (GCC/Mach-O), `??_7`/`??_8` (MSVC)
- RTTI symbols: `_ZTI`/`__ZTI`, `_ZTS`/`__ZTS`
- C++ library imports: `msvcp*`, `libstdc++`, `libc++`

**Weak indicators (need 3+ matches):**
- General mangled symbols: `_Z`/`__Z` (GCC/Mach-O), `?...@@` (MSVC), `W?` (Watcom), `@...$q` (Borland)
- Exception handling: `__gxx_personality`, `___gxx_personality` (Mach-O)

**Exclusions (prevent false positives):**
- `__cxa_atexit`, `__cxa_finalize` - appear in C programs via glibc
- Rust symbols - use `_ZN`/`__ZN` prefix but have hash suffix pattern (`\d+h[0-9a-f]+E`)

**Two-tier caching:**
1. In-memory ConcurrentHashMap cache (fast, session-scoped)
2. Program Options (persistent, survives Ghidra restarts)

**Version tracking:** Detector has a version number. When detection logic changes, increment `DETECTOR_VERSION` to invalidate cached results and force re-detection.

**Thread-safety:** Uses ConcurrentHashMap.computeIfAbsent for atomic cache updates:
- Simple and correct - no manual synchronization needed
- Detection happens inside computeIfAbsent (guaranteed single execution per key)
- Cache cleanup when size exceeds MAX_CACHE_SIZE (simple cleanup, not LRU)

**Cache key:** Uses `program.getUniqueProgramID()` (survives saves, unique per project) plus pathname for debugging.

**Limitations:**
- Statically linked C++ binaries may rely solely on symbol detection
- Heavily stripped binaries with few symbols may not be detected

```java
// Check if program is C++ (thread-safe, cached, persistent)
boolean isCpp = CppDetector.isCppProgram(program);

// Clear in-memory cache on shutdown
CppDetector.clearCache();

// Invalidate both caches when program is modified
// (clears persistent first to prevent stale reload)
CppDetector.invalidateCache(program);
```

**Program Options stored:**
- `ReVa.CppDetector.isCpp` - boolean result
- `ReVa.CppDetector.version` - detector version for cache invalidation

**Transaction handling:** Uses standard pattern with `finally` block and `boolean success` flag for proper cleanup.

### StructureInferenceToolProvider

Main tool provider implementing both inference tools. Uses:
- `FillOutStructureHelper` - Ghidra's built-in offset discovery
- Structure matching algorithm with scoring
- C++ vtable and inheritance detection

## Critical Implementation Patterns

### Using FillOutStructureHelper

```java
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.decompiler.util.FillOutStructureHelper.OffsetPcodeOpPair;

// Create helper with program and monitor
FillOutStructureHelper helper = new FillOutStructureHelper(program, monitor);

// Process a variable to find all memory accesses
// Parameters: highVariable, function, createClassIfNeeded, useDataType, decompiler
helper.processStructure(targetVar, function, false, false, decompiler);

// Get discovered offsets
List<OffsetPcodeOpPair> stores = helper.getStorePcodeOps();
List<OffsetPcodeOpPair> loads = helper.getLoadPcodeOps();

// Each pair contains:
long offset = pair.getOffset();      // Byte offset in structure
PcodeOp op = pair.getPcodeOp();      // The Pcode operation
```

### Finding Variables by Name

```java
/**
 * Find a high-level variable by name in the decompiled function.
 * LocalSymbolMap.getSymbols() includes all symbols: parameters, locals, and globals.
 */
private HighVariable findVariableByName(HighFunction highFunction, String name) {
    LocalSymbolMap localSyms = highFunction.getLocalSymbolMap();
    Iterator<HighSymbol> iter = localSyms.getSymbols();  // Iterator, not Iterable!
    while (iter.hasNext()) {
        HighSymbol sym = iter.next();
        if (sym != null && sym.getName().equals(name)) {
            return sym.getHighVariable();
        }
    }
    return null;
}
```

Note: `LocalSymbolMap.getSymbols()` includes parameters, so no separate parameter search is needed.

### Access Size Extraction

```java
private int getAccessSize(PcodeOp op, boolean isStore) {
    if (isStore) {
        // For STORE, size is from value being stored (input 2)
        if (op.getNumInputs() >= 3) {
            Varnode stored = op.getInput(2);
            if (stored != null) {
                return stored.getSize();
            }
        }
    } else {
        // For LOAD, size is from output
        Varnode output = op.getOutput();
        if (output != null) {
            return output.getSize();
        }
    }
    return 0;
}
```

### Vtable Detection

Uses shared `VtableUtil` from `reva.util` package for vtable detection:

```java
import reva.util.VtableUtil;

private Address getVtableAddressFromStore(Program program, PcodeOp op) {
    if (op.getNumInputs() < 3) return null;

    Varnode stored = op.getInput(2);
    if (stored == null || !stored.isConstant()) return null;

    long value = stored.getOffset();

    try {
        Address addr = program.getAddressFactory()
            .getDefaultAddressSpace().getAddress(value);

        if (addr == null || !program.getMemory().contains(addr)) {
            return null;
        }

        // Use shared utility for vtable detection
        if (VtableUtil.isLikelyVtable(program, addr)) {
            return addr;
        }
        return null;
    } catch (Exception e) {
        return null;
    }
}

// VtableUtil provides:
// - isLikelyVtable(program, addr) - checks for consecutive function pointers
// - readPointer(memory, addr, pointerSize) - reads pointer from memory
// - toAddress(program, offset) - converts offset to Address
```

## Enhanced Type Inference

The system performs advanced type inference beyond simple size-based guessing:

### Float Detection
- Analyzes PcodeOps to detect FLOAT_* operations (FLOAT_ADD, FLOAT_MULT, etc.)
- If a field participates in floating-point operations, infers `float` (4 bytes) or `double` (8 bytes)

### Pointer Detection
- Detects when loaded values are used as pointers (dereferenced in subsequent LOAD/STORE)
- Follows pointer arithmetic through PTRADD, INT_ADD, INT_SUB operations
- Infers pointed-to type based on dereference size (e.g., `int*` if dereferencing 4 bytes)
- Uses recursion depth limiting (max 10) and cycle detection to prevent infinite loops

### Array Detection
- Detects 3+ consecutive accesses at sequential offsets with same size
- Merges into array fields (e.g., accesses at 0, 4, 8, 12 become `int[4]`)
- Calculates element size from total size / array length

### Field Info Output
```json
{
    "offset": 16,
    "size": 16,
    "inferredType": "float[4]",
    "isArray": true,
    "arrayLength": 4,
    "isFloatingPoint": true,
    "distinctFunctionCount": 3,
    "sizeConsistent": true,
    "accessPattern": "read-write",
    "confidence": 0.95
}
```

## Confidence Scoring

Confidence uses multi-factor scoring instead of simple access counting:

```java
// Function coverage: what proportion of analyzed functions accessed this field
double functionCoverage = distinctFunctions / (double) totalFunctions;

// Size consistency: penalty if field accessed with different sizes
double sizeConsistencyFactor = sizeConsistent ? 1.0 : 0.7;

// Access pattern: read-only fields might be inherited (slightly lower confidence)
double accessPatternFactor = isReadOnly ? 0.9 : 1.0;

// Combined confidence
confidence = functionCoverage * sizeConsistencyFactor * accessPatternFactor;
```

**Access Patterns:**
- `read-only` - Only LOAD operations (might be inherited base class member)
- `write-only` - Only STORE operations
- `read-write` - Both LOAD and STORE operations (highest confidence)

## Structure Matching Algorithm

### Match Types

- `EXACT` - All query offsets match, same field count, **and no size mismatches**
- `SUBSET` - Query offsets fully contained in structure (structure has more fields)
- `SUPERSET` - Structure fields fully contained in query (query has more offsets)
- `PARTIAL` - Some overlap but neither subset

### Enhanced Scoring Algorithm

The scoring now considers field sizes and structure size ratio:

```java
// Base offset matching score
double offsetScore = matchedCount / (double) Math.max(queryCount, structFieldCount);

// Size mismatch penalty: 10% per field where sizes differ
double sizePenalty = sizeMismatchCount * 0.1;

// Structure size ratio: prefer structures close to inferred size
double sizeRatio = min(structSize, inferredSize) / (double) max(structSize, inferredSize);

// Combined score
score = offsetScore * sizeRatio - sizePenalty;

// Apply match type bonuses
if (matchType == EXACT && sizeMismatchCount == 0) {
    score = 1.0;  // Perfect match only if sizes also match
} else if (matchType == SUBSET && sizeMismatchCount == 0) {
    score = min(1.0, score + 0.1);
}
```

### Match Response Fields
```json
{
    "name": "MyStruct",
    "matchScore": 0.85,
    "matchType": "SUBSET",
    "sizeMismatchCount": 1,
    "sizeRatioScore": 0.94,
    "matchedOffsets": [0, 8, 16],
    "unmatchedQueryOffsets": []
}
```

## Response Patterns

### Infer Structure Response (Single-Function Mode)

```json
{
    "programPath": "/program.exe",
    "analyzedFunctions": 1,
    "successfulAnalyses": 1,
    "mode": "single-function",
    "variable": "param_1",
    "inferredLayout": {
        "fields": [
            {"offset": 0, "size": 8, "inferredType": "void*", "accessCount": 5, "confidence": 1.0},
            {"offset": 8, "size": 4, "inferredType": "int", "accessCount": 3, "confidence": 1.0}
        ],
        "minSize": 32,
        "storeCount": 8,
        "loadCount": 5
    },
    "suggestedCDefinition": "struct Inferred_0x20 { ... };",
    "matchingStructures": [...],
    "cppAnalysis": {...},
    "functionDetails": [
        {"address": "0x00401000", "name": "FUN_00401000", "success": true, "variable": "param_1", "storeCount": 8, "loadCount": 5}
    ]
}
```

### Infer Structure Response (Multi-Function Mode)

```json
{
    "programPath": "/program.exe",
    "analyzedFunctions": 3,
    "successfulAnalyses": 3,
    "mode": "multi-function",
    "variable": "first parameter of each function (auto-detected)",
    "inferredLayout": {...},
    "functionDetails": [
        {"address": "0x00401000", "name": "method1", "success": true, "variable": "param_1", ...},
        {"address": "0x00401100", "name": "method2", "success": true, "variable": "param_1", ...},
        {"address": "0x00401200", "name": "method3", "success": true, "variable": "this", ...}
    ]
}
```

### Find Matching Structures Response

```json
{
    "programPath": "/program.exe",
    "queryOffsets": [0, 8, 28],
    "matchCount": 3,
    "matches": [
        {
            "name": "MyClass",
            "category": "/Classes",
            "size": 64,
            "matchScore": 0.85,
            "matchType": "SUPERSET",
            "matchedOffsets": [0, 8, 28],
            "unmatchedQueryOffsets": [],
            "structureFieldCount": 8
        }
    ]
}
```

## Testing Considerations

### Integration Tests

- Test single function analysis with known variable
- Test multi-function aggregation
- Test C++ vtable detection
- Test structure matching with various match types
- Test with both C and C++ binaries

### Test Data Requirements

- Functions with pointer arithmetic patterns (`*(ptr + offset)`)
- C++ classes with vtables
- Existing structures for matching tests
- Programs with and without C++ indicators

## Important Notes

- **Decompiler Disposal**: Always dispose `DecompInterface` in finally block
- **Iterator Pattern**: `LocalSymbolMap.getSymbols()` returns Iterator, not Iterable
- **Confidence Scoring**: Multi-factor formula using function coverage, size consistency, and access patterns (see Confidence Scoring section above)
- **Type Inference**: Uses PcodeOp analysis for float/pointer detection with recursion depth limiting (max 10) and cycle detection
- **Array Detection**: Requires 3+ consecutive same-size elements (MIN_ARRAY_ELEMENTS = 3)
- **C++ Detection**: Uses tiered detection (strong = immediate, weak = need 3+). Excludes Rust symbols and glibc C symbols. Two-tier cache: in-memory LRU + persistent Program Options. Cache key uses `program.getUniqueProgramID()`.
- **Vtable Heuristic**: At least 2 consecutive function pointers required (MIN_VTABLE_FUNCTION_POINTERS)
- **Structure Matching**: Uses field size comparison and structure size ratio in scoring (see Structure Matching section above)
- **Address Formatting**: Always use `AddressUtil.formatAddress()` for JSON output
- **Offset Validation**: Offsets must be non-negative and less than Integer.MAX_VALUE
- **Address Safety**: Use `addNoWrap()` when iterating addresses to avoid overflow
- **FieldInfo Thread Safety**: FieldInfo class uses non-thread-safe collections; not designed for concurrent access
