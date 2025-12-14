package reva.tools.structureinference;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.decompiler.util.FillOutStructureHelper.OffsetPcodeOpPair;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.ConfigManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.RevaInternalServiceRegistry;
import reva.util.VtableUtil;

/**
 * Tool provider for structure inference from memory access patterns.
 *
 * <p>Analyzes how pointer variables are accessed in decompiled code to infer
 * structure layouts. Uses Ghidra's FillOutStructureHelper to discover memory
 * access offsets, then matches against existing structures and detects C++
 * patterns like vtables and inheritance.</p>
 */
public class StructureInferenceToolProvider extends AbstractToolProvider {

    private static final int DEFAULT_DECOMPILER_TIMEOUT_SECS = 30;
    private static final int DEFAULT_MAX_RESULTS = 10;
    private static final int MAX_FUNCTIONS_TO_ANALYZE = 50;

    /** Maximum valid structure offset (prevents Long overflow issues) */
    private static final long MAX_VALID_OFFSET = Integer.MAX_VALUE;

    public StructureInferenceToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerInferStructureFromVariableTool();
        registerFindMatchingStructuresTool();
    }

    @Override
    public void cleanup() {
        // Clear the C++ detection cache to release memory
        CppDetector.clearCache();
    }

    private void registerInferStructureFromVariableTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("functions", Map.of(
            "type", "array",
            "description", "List of function addresses or names to analyze (1 or more)",
            "items", Map.of("type", "string")
        ));
        properties.put("variable", Map.of(
            "type", "string",
            "description", "Name of the variable to analyze (e.g., 'param_1', 'local_10'). " +
                "Only valid for single-function analysis. For multiple functions, first parameter of each is used automatically."
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("infer-structure")
            .title("Infer Structure")
            .description("Analyze how a pointer variable is accessed to infer its structure layout. " +
                "Two modes: (1) Single function - analyzes specified variable or first parameter. " +
                "(2) Multiple functions (class methods) - analyzes first parameter of each function " +
                "and aggregates results with confidence scores. " +
                "Automatically detects C++ patterns like vtables and suggests matching existing structures.")
            .inputSchema(createSchema(properties, List.of("programPath", "functions")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            List<String> functions = getValidatedStringList(request.arguments(), "functions");
            String variable = getOptionalString(request, "variable", null);

            // Filter out empty/whitespace-only strings
            if (functions != null) {
                functions = functions.stream()
                    .filter(f -> f != null && !f.trim().isEmpty())
                    .collect(Collectors.toList());
            }

            if (functions == null || functions.isEmpty()) {
                return createErrorResult("Parameter 'functions' is required and must contain at least one function address or name");
            }

            if (functions.size() > MAX_FUNCTIONS_TO_ANALYZE) {
                return createErrorResult("Too many functions specified (" + functions.size() +
                    "). Maximum allowed is " + MAX_FUNCTIONS_TO_ANALYZE);
            }

            // Validate: cannot specify variable with multiple functions
            boolean hasVariable = variable != null && !variable.trim().isEmpty();
            if (functions.size() > 1 && hasVariable) {
                return createErrorResult("Cannot specify 'variable' parameter with multiple functions. " +
                    "For class method analysis, the first parameter of each function is analyzed automatically.");
            }

            // Single function mode: use specified variable or auto-detect
            if (functions.size() == 1) {
                if (!hasVariable) {
                    Function func = resolveFunction(program, functions.get(0));
                    if (func == null) {
                        return createErrorResult("Cannot resolve function '" + functions.get(0) + "'");
                    }
                    variable = autoDetectVariable(func);
                    if (variable == null) {
                        return createErrorResult("Function has no parameters. Please specify 'variable' parameter. " +
                            "Available variables can be found in the decompiled code.");
                    }
                }
                // Single function with specified or auto-detected variable
                return inferStructureInternal(program, functions, variable);
            }

            // Multi-function mode: pass null to trigger per-function auto-detect
            return inferStructureInternal(program, functions, null);
        });
    }

    /**
     * Internal method that performs structure inference.
     *
     * @param program The program to analyze
     * @param functions List of function addresses/names to analyze
     * @param variable Variable name to analyze. If null, auto-detects first param for each function.
     */
    private McpSchema.CallToolResult inferStructureInternal(
            Program program,
            List<String> functions,
            String variable) {

        List<Map<String, Object>> functionResults = new ArrayList<>();
        Map<Long, FieldInfo> aggregatedFields = new HashMap<>();
        int successCount = 0;
        int storeCount = 0;
        int loadCount = 0;

        boolean isCpp = CppDetector.isCppProgram(program);
        Address detectedVtableAddress = null;
        List<Long> vtableOffsets = new ArrayList<>();

        // Track if we're in multi-function auto-detect mode
        boolean autoDetectMode = (variable == null);

        // Analyze each function
        for (String funcAddr : functions) {
            Function function = resolveFunction(program, funcAddr);
            if (function == null) {
                functionResults.add(Map.of(
                    "address", funcAddr,
                    "success", false,
                    "error", "Function not found: " + funcAddr
                ));
                continue;
            }

            // Determine variable for this function
            String varForThisFunc;
            if (autoDetectMode) {
                varForThisFunc = autoDetectVariable(function);
                if (varForThisFunc == null) {
                    Map<String, Object> errorResult = new HashMap<>();
                    errorResult.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
                    errorResult.put("name", function.getName());
                    errorResult.put("success", false);
                    errorResult.put("variable", null);
                    errorResult.put("error", "Function has no parameters to analyze");
                    functionResults.add(errorResult);
                    continue;
                }
            } else {
                varForThisFunc = variable;
            }

            try {
                FunctionAnalysisResult result = analyzeFunction(program, function, varForThisFunc);
                if (result == null) {
                    Map<String, Object> errorResult = new HashMap<>();
                    errorResult.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
                    errorResult.put("name", function.getName());
                    errorResult.put("success", false);
                    errorResult.put("variable", varForThisFunc);
                    errorResult.put("error", "Variable '" + varForThisFunc + "' not found in function or decompilation failed");
                    functionResults.add(errorResult);
                    continue;
                }

                successCount++;
                storeCount += result.stores.size();
                loadCount += result.loads.size();

                // Get function address for tracking distinct functions
                Address functionAddress = function.getEntryPoint();

                // Merge into aggregated fields
                for (OffsetPcodeOpPair pair : result.stores) {
                    long offset = pair.getOffset();

                    // Skip invalid offsets
                    if (offset < 0 || offset > MAX_VALID_OFFSET) {
                        continue;
                    }

                    int size = getAccessSize(pair.getPcodeOp(), true);
                    PcodeOp op = pair.getPcodeOp();
                    aggregatedFields.computeIfAbsent(offset, k -> new FieldInfo(offset, size))
                        .addAccessWithOp(AccessType.STORE, size, functionAddress, op);

                    // Check for vtable store at this offset
                    if (isCpp) {
                        Address vtAddr = getVtableAddressFromStore(program, op);
                        if (vtAddr != null) {
                            vtableOffsets.add(offset);
                            if (offset == 0) {
                                detectedVtableAddress = vtAddr;
                            }
                        }
                    }
                }

                for (OffsetPcodeOpPair pair : result.loads) {
                    long offset = pair.getOffset();

                    // Skip invalid offsets
                    if (offset < 0 || offset > MAX_VALID_OFFSET) {
                        continue;
                    }

                    int size = getAccessSize(pair.getPcodeOp(), false);
                    PcodeOp op = pair.getPcodeOp();
                    aggregatedFields.computeIfAbsent(offset, k -> new FieldInfo(offset, size))
                        .addAccessWithOp(AccessType.LOAD, size, functionAddress, op);
                }

                Map<String, Object> funcResult = new HashMap<>();
                funcResult.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
                funcResult.put("name", function.getName());
                funcResult.put("success", true);
                funcResult.put("variable", varForThisFunc);
                funcResult.put("storeCount", result.stores.size());
                funcResult.put("loadCount", result.loads.size());
                functionResults.add(funcResult);

            } catch (Exception e) {
                Map<String, Object> errorResult = new HashMap<>();
                errorResult.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
                errorResult.put("name", function.getName());
                errorResult.put("success", false);
                errorResult.put("variable", varForThisFunc);
                errorResult.put("error", "Analysis failed: " + e.getMessage());
                functionResults.add(errorResult);
            }
        }

        if (successCount == 0) {
            if (autoDetectMode) {
                return createErrorResult("Failed to analyze any of the " + functions.size() +
                    " specified functions. Ensure the functions have parameters and decompilation succeeds.");
            } else {
                return createErrorResult("Failed to analyze the function. Ensure the variable '" + variable +
                    "' exists in the function and decompilation succeeds.");
            }
        }

        // Perform advanced type inference on all fields
        for (FieldInfo field : aggregatedFields.values()) {
            field.performAdvancedInference();
        }

        // Detect and merge array patterns
        detectAndMergeArrays(aggregatedFields);

        // Capture for lambda
        final int finalSuccessCount = successCount;

        // Build field list sorted by offset
        List<Map<String, Object>> fields = aggregatedFields.values().stream()
            .sorted((a, b) -> Long.compare(a.offset, b.offset))
            .map(f -> f.toMap(finalSuccessCount))
            .collect(Collectors.toList());

        // Calculate min size with overflow protection
        long minSize = aggregatedFields.values().stream()
            .mapToLong(f -> {
                long endOffset = f.offset + f.size;
                if (endOffset < 0) return Long.MAX_VALUE; // Overflow
                return endOffset;
            })
            .filter(v -> v != Long.MAX_VALUE)
            .max()
            .orElse(0);

        // Find matching structures - convert offsets safely and include size info
        // Use exclusive upper bound (<) to ensure safe int conversion
        Map<Integer, Integer> offsetToSize = new HashMap<>();
        for (FieldInfo field : aggregatedFields.values()) {
            if (field.offset >= 0 && field.offset < Integer.MAX_VALUE) {
                offsetToSize.put((int) field.offset, field.size);
            }
        }
        List<Integer> offsets = new ArrayList<>(offsetToSize.keySet());

        // Pass the inferred minimum size for structure size comparison
        int inferredMinSize = minSize > Integer.MAX_VALUE ? 0 : (int) minSize;
        List<Map<String, Object>> matches = findMatchingStructuresInternal(
            program, offsetToSize, inferredMinSize, 0, 0, 0.3, DEFAULT_MAX_RESULTS);

        // Generate C definition
        String cDefinition = generateCDefinition(aggregatedFields, minSize, isCpp && detectedVtableAddress != null);

        // Build C++ analysis
        Map<String, Object> cppAnalysis = new HashMap<>();
        cppAnalysis.put("isCppProject", isCpp);
        if (isCpp) {
            cppAnalysis.put("hasVtableAtZero", detectedVtableAddress != null);
            if (detectedVtableAddress != null) {
                cppAnalysis.put("vtableAddress", AddressUtil.formatAddress(detectedVtableAddress));
            }
            if (vtableOffsets.size() > 1) {
                cppAnalysis.put("multipleInheritance", true);
                cppAnalysis.put("vtableOffsets", vtableOffsets);
            }
            // Inheritance detection placeholder - would need multiple class layouts to compare
            cppAnalysis.put("inheritanceIndicators", List.of());
        }

        // Build response
        Map<String, Object> result = new HashMap<>();
        result.put("programPath", getProgramPath(program));
        result.put("analyzedFunctions", functions.size());
        result.put("successfulAnalyses", successCount);
        if (autoDetectMode) {
            result.put("mode", "multi-function");
            result.put("variable", "first parameter of each function (auto-detected)");
        } else {
            result.put("mode", "single-function");
            result.put("variable", variable);
        }
        result.put("inferredLayout", Map.of(
            "fields", fields,
            "minSize", minSize,
            "storeCount", storeCount,
            "loadCount", loadCount
        ));
        result.put("suggestedCDefinition", cDefinition);
        result.put("matchingStructures", matches);
        result.put("cppAnalysis", cppAnalysis);
        result.put("functionDetails", functionResults);

        return createJsonResult(result);
    }

    private void registerFindMatchingStructuresTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("offsets", Map.of(
            "type", "array",
            "description", "List of byte offsets that must have fields in the structure",
            "items", Map.of("type", "integer")
        ));
        properties.put("minSize", Map.of(
            "type", "integer",
            "description", "Minimum structure size to consider (default: 0)",
            "default", 0
        ));
        properties.put("maxSize", Map.of(
            "type", "integer",
            "description", "Maximum structure size to consider, 0 = unlimited (default: 0)",
            "default", 0
        ));
        properties.put("matchThreshold", Map.of(
            "type", "number",
            "description", "Minimum match score 0.0-1.0 to include in results (default: 0.5)",
            "default", 0.5
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of results to return (default: 10)",
            "default", DEFAULT_MAX_RESULTS
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("find-matching-structures")
            .title("Find Matching Structures")
            .description("Search for existing structures that have fields at the specified offsets. " +
                "Returns structures ranked by how well they match the given offset layout. " +
                "Useful when you know field offsets from manual analysis and want to find " +
                "matching structure definitions.")
            .inputSchema(createSchema(properties, List.of("programPath", "offsets")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            List<Integer> offsets = getIntegerList(request.arguments(), "offsets");
            int minSize = getOptionalInt(request, "minSize", 0);
            int maxSize = getOptionalInt(request, "maxSize", 0);
            double matchThreshold = getOptionalDouble(request.arguments(), "matchThreshold", 0.5);
            int maxResults = getOptionalInt(request, "maxResults", DEFAULT_MAX_RESULTS);

            if (offsets.isEmpty()) {
                return createErrorResult("Parameter 'offsets' must contain at least one offset value");
            }

            // Validate offsets are non-negative
            for (Integer offset : offsets) {
                if (offset < 0) {
                    return createErrorResult("Invalid offset value: " + offset + ". Offsets must be non-negative.");
                }
            }

            // For direct tool calls, create a uniform size map (all fields are unknown size)
            Map<Integer, Integer> offsetToSize = new HashMap<>();
            for (Integer offset : offsets) {
                offsetToSize.put(offset, 0); // 0 means unknown size, no penalty
            }
            List<Map<String, Object>> matches = findMatchingStructuresInternal(
                program, offsetToSize, minSize, minSize, maxSize, matchThreshold, maxResults);

            Map<String, Object> result = Map.of(
                "programPath", getProgramPath(program),
                "queryOffsets", offsets,
                "matchCount", matches.size(),
                "matches", matches
            );

            return createJsonResult(result);
        });
    }

    private FunctionAnalysisResult analyzeFunction(Program program, Function function, String variableName) {
        DecompInterface decompiler = createConfiguredDecompiler(program);
        if (decompiler == null) {
            return null;
        }

        try {
            int timeoutSecs = getDecompilerTimeout();
            TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(timeoutSecs, TimeUnit.SECONDS);
            DecompileResults results = decompiler.decompileFunction(function, timeoutSecs, monitor);

            if (!results.decompileCompleted()) {
                return null;
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return null;
            }

            // Find the target variable
            HighVariable targetVar = findVariableByName(highFunction, variableName);
            if (targetVar == null) {
                return null;
            }

            // Use FillOutStructureHelper to analyze memory accesses
            FillOutStructureHelper helper = new FillOutStructureHelper(program, monitor);
            helper.processStructure(targetVar, function, false, false, decompiler);

            List<OffsetPcodeOpPair> stores = helper.getStorePcodeOps();
            List<OffsetPcodeOpPair> loads = helper.getLoadPcodeOps();

            return new FunctionAnalysisResult(stores, loads);

        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Find a high-level variable by name in the decompiled function.
     * LocalSymbolMap.getSymbols() includes all symbols: parameters, locals, and globals.
     */
    private HighVariable findVariableByName(HighFunction highFunction, String name) {
        LocalSymbolMap localSyms = highFunction.getLocalSymbolMap();
        Iterator<HighSymbol> iter = localSyms.getSymbols();
        while (iter.hasNext()) {
            HighSymbol sym = iter.next();
            if (sym != null && sym.getName().equals(name)) {
                return sym.getHighVariable();
            }
        }
        return null;
    }

    private int getAccessSize(PcodeOp op, boolean isStore) {
        if (isStore) {
            // For STORE, the size is from the value being stored (input 2)
            if (op.getNumInputs() >= 3) {
                Varnode stored = op.getInput(2);
                if (stored != null) {
                    return stored.getSize();
                }
            }
        } else {
            // For LOAD, the size is from the output
            Varnode output = op.getOutput();
            if (output != null) {
                return output.getSize();
            }
        }
        return 0;
    }

    /**
     * Check if a STORE operation is storing a vtable pointer.
     * Returns the vtable address if detected, null otherwise.
     */
    private Address getVtableAddressFromStore(Program program, PcodeOp op) {
        if (op.getNumInputs() < 3) {
            return null;
        }

        Varnode stored = op.getInput(2);
        if (stored == null || !stored.isConstant()) {
            return null;
        }

        long value = stored.getOffset();

        try {
            Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            if (addr == null || !program.getMemory().contains(addr)) {
                return null;
            }
            if (VtableUtil.isLikelyVtable(program, addr)) {
                return addr;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private List<Map<String, Object>> findMatchingStructuresInternal(
            Program program,
            Map<Integer, Integer> offsetToSize,
            int inferredSize,
            int minSize,
            int maxSize,
            double matchThreshold,
            int maxResults) {

        List<Map<String, Object>> matches = new ArrayList<>();

        // Iterate all data types
        Iterator<DataType> iter = program.getDataTypeManager().getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();

            if (!(dt instanceof Structure)) {
                continue;
            }

            Structure struct = (Structure) dt;
            int structSize = struct.getLength();

            // Size filtering
            if (minSize > 0 && structSize < minSize) continue;
            if (maxSize > 0 && structSize > maxSize) continue;

            // Skip built-in types
            if (dt.getSourceArchive() != null &&
                "BuiltInTypes".equals(dt.getSourceArchive().getName())) {
                continue;
            }

            // Calculate match with size information
            StructureMatch match = calculateMatch(struct, offsetToSize, inferredSize);
            if (match.score >= matchThreshold) {
                matches.add(match.toMap());
            }
        }

        // Sort by score descending
        matches.sort((a, b) -> Double.compare(
            (Double) b.get("matchScore"),
            (Double) a.get("matchScore")));

        // Limit results
        if (matches.size() > maxResults) {
            matches = matches.subList(0, maxResults);
        }

        return matches;
    }

    private StructureMatch calculateMatch(Structure struct, Map<Integer, Integer> offsetToSize, int inferredSize) {
        // Collect defined field offsets with their sizes (skip undefined/padding)
        Map<Integer, Integer> structOffsetToSize = new HashMap<>();
        for (int i = 0; i < struct.getNumComponents(); i++) {
            DataTypeComponent comp = struct.getComponent(i);
            String typeName = comp.getDataType().getName();
            if (!typeName.startsWith("undefined") && !typeName.equals("padding")) {
                structOffsetToSize.put(comp.getOffset(), comp.getLength());
            }
        }

        Set<Integer> queryOffsets = offsetToSize.keySet();
        Set<Integer> structOffsets = structOffsetToSize.keySet();

        // Calculate intersection (offset matches)
        Set<Integer> matched = new HashSet<>(queryOffsets);
        matched.retainAll(structOffsets);

        int matchedCount = matched.size();
        int queryCount = queryOffsets.size();
        int structFieldCount = structOffsets.size();

        // Count size mismatches among matched offsets
        int sizeMismatchCount = 0;
        for (Integer offset : matched) {
            int querySize = offsetToSize.get(offset);
            int structSize = structOffsetToSize.get(offset);

            // Only penalize if both sizes are known (non-zero) and different
            if (querySize > 0 && structSize > 0 && querySize != structSize) {
                sizeMismatchCount++;
            }
        }

        // Calculate structure size ratio
        int structSize = struct.getLength();
        double sizeRatio = 1.0;
        if (inferredSize > 0 && structSize > 0) {
            int minStructSize = Math.min(structSize, inferredSize);
            int maxStructSize = Math.max(structSize, inferredSize);
            sizeRatio = (double) minStructSize / maxStructSize;
        }

        // Determine match type (based on offset matching only, not sizes)
        MatchType matchType;
        if (matchedCount == queryCount && matchedCount == structFieldCount && sizeMismatchCount == 0) {
            matchType = MatchType.EXACT;
        } else if (matchedCount == queryCount) {
            matchType = MatchType.SUBSET;
        } else if (matchedCount == structFieldCount) {
            matchType = MatchType.SUPERSET;
        } else {
            matchType = MatchType.PARTIAL;
        }

        // Calculate score with enhanced algorithm
        double score;
        if (queryCount == 0 || structFieldCount == 0) {
            score = 0;
        } else {
            // Base offset matching score
            double offsetScore = (double) matchedCount / Math.max(queryCount, structFieldCount);

            // Size mismatch penalty: 10% per mismatch
            double sizePenalty = sizeMismatchCount * 0.1;

            // Combined score: offset match * size ratio - penalty
            score = offsetScore * sizeRatio - sizePenalty;

            // Apply match type bonuses
            if (matchType == MatchType.EXACT) {
                // Perfect match only if no size mismatches
                score = 1.0;
            } else if (matchType == MatchType.SUBSET && sizeMismatchCount == 0) {
                // Bonus for subset with perfect size matches
                score = Math.min(1.0, score + 0.1);
            }

            // Ensure score stays in valid range
            score = Math.max(0.0, Math.min(1.0, score));
        }

        // Unmatched offsets
        Set<Integer> unmatchedQuery = new HashSet<>(queryOffsets);
        unmatchedQuery.removeAll(matched);

        return new StructureMatch(
            struct.getName(),
            struct.getCategoryPath().getPath(),
            struct.getLength(),
            score,
            matchType,
            new ArrayList<>(matched),
            new ArrayList<>(unmatchedQuery),
            structFieldCount,
            sizeMismatchCount,
            sizeRatio
        );
    }

    /**
     * Detect array patterns and merge consecutive fields into arrays.
     * Arrays are detected when multiple accesses occur at consecutive offsets with the same size.
     */
    private void detectAndMergeArrays(Map<Long, FieldInfo> fields) {
        List<FieldInfo> sortedFields = fields.values().stream()
            .sorted((a, b) -> Long.compare(a.offset, b.offset))
            .collect(Collectors.toList());

        // Look for consecutive fields with the same size
        for (int i = 0; i < sortedFields.size(); i++) {
            FieldInfo current = sortedFields.get(i);
            if (current.isArray) {
                continue; // Already processed as array
            }

            int arrayLength = 1;
            long expectedOffset = current.offset + current.size;

            // Look ahead for consecutive fields with same size
            for (int j = i + 1; j < sortedFields.size(); j++) {
                FieldInfo next = sortedFields.get(j);

                // Check if next field is consecutive and same size
                if (next.offset == expectedOffset && next.size == current.size) {
                    arrayLength++;
                    expectedOffset = next.offset + next.size;
                } else {
                    break; // Not consecutive or different size
                }
            }

            // If we found at least 3 consecutive elements, mark as array
            if (arrayLength >= 3) {
                // Calculate total array size with overflow protection
                long totalSize = (long) current.size * arrayLength;
                if (totalSize > Integer.MAX_VALUE) {
                    // Overflow would occur - skip array merging for this field
                    continue;
                }

                current.isArray = true;
                current.arrayLength = arrayLength;

                // Update size to cover the whole array (safe cast - checked above)
                current.size = (int) totalSize;

                // Remove the merged fields
                for (int j = 1; j < arrayLength; j++) {
                    if (i + j >= sortedFields.size()) break;  // Add bounds check
                    FieldInfo toRemove = sortedFields.get(i + j);
                    fields.remove(toRemove.offset);
                }

                // Skip over the consumed elements
                i += arrayLength - 1;
            }
        }
    }

    private String generateCDefinition(Map<Long, FieldInfo> fields, long minSize, boolean hasVtable) {
        StringBuilder sb = new StringBuilder();
        sb.append("struct Inferred_0x").append(Long.toHexString(minSize)).append(" {\n");

        List<FieldInfo> sortedFields = fields.values().stream()
            .sorted((a, b) -> Long.compare(a.offset, b.offset))
            .collect(Collectors.toList());

        long currentOffset = 0;
        for (FieldInfo field : sortedFields) {
            // Add padding if needed
            if (field.offset > currentOffset) {
                long padding = field.offset - currentOffset;
                sb.append("    undefined padding_0x")
                  .append(Long.toHexString(currentOffset))
                  .append("[").append(padding).append("];\n");
            }

            // Determine field name
            boolean isVtableField = hasVtable && field.offset == 0;
            String fieldName = isVtableField ? "vtable" : "field_0x" + Long.toHexString(field.offset);

            // Use enhanced type inference
            String typeName = field.getInferredType();

            // Override for vtable field
            if (isVtableField && !field.isPointer) {
                typeName = "void*";
            }

            sb.append("    ").append(typeName).append(" ").append(fieldName).append(";\n");
            currentOffset = field.offset + field.size;
        }

        // Trailing padding
        if (currentOffset < minSize) {
            sb.append("    undefined padding_0x")
              .append(Long.toHexString(currentOffset))
              .append("[").append(minSize - currentOffset).append("];\n");
        }

        sb.append("};");
        return sb.toString();
    }

    private Function resolveFunction(Program program, String addressOrName) {
        FunctionManager funcMgr = program.getFunctionManager();

        // Try as address first
        try {
            Address addr = AddressUtil.resolveAddressOrSymbol(program, addressOrName);
            if (addr != null) {
                Function func = funcMgr.getFunctionAt(addr);
                if (func != null) {
                    return func;
                }
                // Maybe it's inside a function
                func = funcMgr.getFunctionContaining(addr);
                if (func != null) {
                    return func;
                }
            }
        } catch (Exception e) {
            // Fall through to name lookup
        }

        // Try as function name using symbol table for O(1) lookup
        for (Symbol symbol : program.getSymbolTable().getLabelOrFunctionSymbols(addressOrName, null)) {
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                Function func = funcMgr.getFunctionAt(symbol.getAddress());
                if (func != null) {
                    return func;
                }
            }
        }

        return null;
    }

    private DecompInterface createConfiguredDecompiler(Program program) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(false);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            decompiler.dispose();
            return null;
        }

        return decompiler;
    }

    private int getDecompilerTimeout() {
        ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
        return configManager != null
            ? configManager.getDecompilerTimeoutSeconds()
            : DEFAULT_DECOMPILER_TIMEOUT_SECS;
    }

    /**
     * Get the program path safely, handling null DomainFile (headless mode, in-memory programs).
     */
    private String getProgramPath(Program program) {
        DomainFile domainFile = program.getDomainFile();
        return domainFile != null ? domainFile.getPathname() : program.getName();
    }

    /**
     * Auto-detect the variable to analyze: returns the first parameter's name.
     * For class methods, this is typically the object pointer (this/self).
     *
     * @param function The function to analyze
     * @return The first parameter's name, or null if function has no parameters
     */
    private String autoDetectVariable(Function function) {
        Parameter[] params = function.getParameters();
        if (params == null || params.length == 0) {
            return null;
        }
        return params[0].getName();
    }

    private static class FunctionAnalysisResult {
        final List<OffsetPcodeOpPair> stores;
        final List<OffsetPcodeOpPair> loads;

        FunctionAnalysisResult(List<OffsetPcodeOpPair> stores, List<OffsetPcodeOpPair> loads) {
            this.stores = stores != null ? stores : List.of();
            this.loads = loads != null ? loads : List.of();
        }
    }

    private enum MatchType {
        EXACT,      // All query offsets match, same field count
        SUBSET,     // Query offsets fully contained in structure
        SUPERSET,   // Structure fields fully contained in query
        PARTIAL     // Some overlap
    }

    private static class StructureMatch {
        final String name;
        final String categoryPath;
        final int size;
        final double score;
        final MatchType matchType;
        final List<Integer> matchedOffsets;
        final List<Integer> unmatchedQueryOffsets;
        final int structureFieldCount;
        final int sizeMismatchCount;
        final double sizeRatioScore;

        StructureMatch(String name, String categoryPath, int size, double score,
                      MatchType matchType, List<Integer> matchedOffsets,
                      List<Integer> unmatchedQueryOffsets, int structureFieldCount,
                      int sizeMismatchCount, double sizeRatioScore) {
            this.name = name;
            this.categoryPath = categoryPath;
            this.size = size;
            this.score = score;
            this.matchType = matchType;
            this.matchedOffsets = matchedOffsets;
            this.unmatchedQueryOffsets = unmatchedQueryOffsets;
            this.structureFieldCount = structureFieldCount;
            this.sizeMismatchCount = sizeMismatchCount;
            this.sizeRatioScore = sizeRatioScore;
        }

        Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("name", name);
            map.put("category", categoryPath);
            map.put("size", size);
            map.put("matchScore", Math.round(score * 100) / 100.0);
            map.put("matchType", matchType.name());
            map.put("matchedOffsets", matchedOffsets);
            map.put("unmatchedQueryOffsets", unmatchedQueryOffsets);
            map.put("structureFieldCount", structureFieldCount);
            map.put("sizeMismatchCount", sizeMismatchCount);
            map.put("sizeRatioScore", Math.round(sizeRatioScore * 100) / 100.0);
            return map;
        }
    }
}
