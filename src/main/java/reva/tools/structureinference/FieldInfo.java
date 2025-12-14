/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.structureinference;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Tracks field information discovered from memory access patterns.
 * Aggregates multiple accesses to the same offset across functions.
 */
class FieldInfo {
    /** Maximum recursion depth for pointer graph traversal to prevent stack overflow */
    private static final int MAX_RECURSION_DEPTH = 10;

    final long offset;

    /** Maximum observed access size in bytes (grows but never shrinks). */
    int size;

    int storeCount = 0;
    int loadCount = 0;

    /** Set of function addresses that accessed this field */
    private final Set<Address> accessingFunctions = new HashSet<>();

    /** Set of all access sizes observed for this field */
    private final Set<Integer> observedSizes = new HashSet<>();

    /** Enhanced type detection fields */
    boolean isArray = false;
    int arrayLength = 0;
    boolean isPointer = false;
    String pointedType = null;
    boolean isFloatingPoint = false;

    /** Track PcodeOps for advanced analysis */
    private final List<PcodeOp> loadOps = new ArrayList<>();
    private final List<PcodeOp> storeOps = new ArrayList<>();

    FieldInfo(long offset, int size) {
        this.offset = offset;
        this.size = size;
        if (size > 0) {
            observedSizes.add(size);
        }
    }

    /**
     * Record an access to this field.
     * Size grows to accommodate larger access widths but never shrinks.
     *
     * @param type Access type (STORE or LOAD)
     * @param accessSize Size of this access in bytes
     * @param functionAddress Address of the function performing the access
     */
    void addAccess(AccessType type, int accessSize, Address functionAddress) {
        if (accessSize > this.size) {
            this.size = accessSize;
        }
        if (accessSize > 0) {
            observedSizes.add(accessSize);
        }
        if (functionAddress != null) {
            accessingFunctions.add(functionAddress);
        }
        if (type == AccessType.STORE) {
            storeCount++;
        } else {
            loadCount++;
        }
    }

    /**
     * Record an access with the associated PcodeOp for advanced analysis.
     *
     * @param type Access type (STORE or LOAD)
     * @param accessSize Size of this access in bytes
     * @param functionAddress Address of the function performing the access
     * @param op The PcodeOp performing this access
     */
    void addAccessWithOp(AccessType type, int accessSize, Address functionAddress, PcodeOp op) {
        addAccess(type, accessSize, functionAddress);
        if (op != null) {
            if (type == AccessType.STORE) {
                storeOps.add(op);
            } else {
                loadOps.add(op);
            }
        }
    }

    /**
     * Perform advanced type inference based on collected PcodeOps.
     * This should be called after all accesses have been recorded.
     * After inference, the PcodeOp lists are cleared to free memory.
     */
    void performAdvancedInference() {
        // Check for floating point operations
        detectFloatingPoint();

        // Check for pointer usage patterns
        detectPointer();

        // Clear PcodeOp lists after inference - they hold references to HighFunction
        // and program state that are no longer needed and could cause memory pressure
        loadOps.clear();
        storeOps.clear();
    }

    /**
     * Detect if this field participates in floating-point operations.
     */
    private void detectFloatingPoint() {
        // Check all load operations to see if their output is used in FLOAT_* operations
        for (PcodeOp loadOp : loadOps) {
            Varnode output = loadOp.getOutput();
            if (output != null) {
                // Check descendants (uses) of this varnode
                Iterator<PcodeOp> uses = output.getDescendants();
                while (uses.hasNext()) {
                    PcodeOp use = uses.next();
                    if (isFloatOperation(use.getOpcode())) {
                        isFloatingPoint = true;
                        return;
                    }
                }
            }
        }

        // Check all store operations to see if the stored value comes from FLOAT_* operations
        for (PcodeOp storeOp : storeOps) {
            if (storeOp.getNumInputs() >= 3) {
                Varnode storedValue = storeOp.getInput(2);
                if (storedValue != null) {
                    PcodeOp def = storedValue.getDef();
                    if (def != null && isFloatOperation(def.getOpcode())) {
                        isFloatingPoint = true;
                        return;
                    }
                }
            }
        }
    }

    /**
     * Detect if this field is used as a pointer (dereferenced).
     */
    private void detectPointer() {
        // Check all load operations to see if their output is used in LOAD/STORE with PTRADD
        for (PcodeOp loadOp : loadOps) {
            Varnode output = loadOp.getOutput();
            if (output != null) {
                // Check if this loaded value is used as a pointer
                if (isUsedAsPointer(output, new HashSet<>(), 0)) {
                    isPointer = true;
                    // Try to determine what type it points to
                    pointedType = inferPointedType(output, new HashSet<>(), 0);
                    return;
                }
            }
        }
    }

    /**
     * Check if a varnode is used as a pointer (in LOAD, STORE, or after PTRADD).
     *
     * @param vn The varnode to check
     * @param visited Set of already visited varnodes to prevent cycles
     * @param depth Current recursion depth
     * @return true if the varnode is used as a pointer
     */
    private boolean isUsedAsPointer(Varnode vn, Set<Varnode> visited, int depth) {
        // Prevent infinite recursion
        if (depth > MAX_RECURSION_DEPTH || visited.contains(vn)) {
            return false;
        }
        visited.add(vn);

        Iterator<PcodeOp> uses = vn.getDescendants();
        while (uses.hasNext()) {
            PcodeOp use = uses.next();
            int opcode = use.getOpcode();

            // Direct use as address in LOAD/STORE
            if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
                // Input 1 is the address for LOAD/STORE
                if (use.getNumInputs() >= 2 && use.getInput(1) == vn) {
                    return true;
                }
            }

            // Use in PTRADD (pointer arithmetic)
            if (opcode == PcodeOp.PTRADD) {
                // Output of PTRADD might be used as pointer
                Varnode ptraddOutput = use.getOutput();
                if (ptraddOutput != null && isUsedAsPointer(ptraddOutput, visited, depth + 1)) {
                    return true;
                }
            }

            // Use in INT_ADD/INT_SUB for pointer arithmetic
            if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB) {
                Varnode arithOutput = use.getOutput();
                if (arithOutput != null && isUsedAsPointer(arithOutput, visited, depth + 1)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Infer the type that a pointer points to based on dereference size.
     *
     * @param pointer The pointer varnode
     * @param visited Set of already visited varnodes to prevent cycles
     * @param depth Current recursion depth
     * @return The inferred type name, or null if unable to infer
     */
    private String inferPointedType(Varnode pointer, Set<Varnode> visited, int depth) {
        // Prevent infinite recursion
        if (depth > MAX_RECURSION_DEPTH || visited.contains(pointer)) {
            return null;
        }
        visited.add(pointer);

        Iterator<PcodeOp> uses = pointer.getDescendants();
        while (uses.hasNext()) {
            PcodeOp use = uses.next();
            int opcode = use.getOpcode();

            // Check LOAD operations using this pointer
            if (opcode == PcodeOp.LOAD && use.getNumInputs() >= 2 && use.getInput(1) == pointer) {
                Varnode output = use.getOutput();
                if (output != null) {
                    int derefSize = output.getSize();
                    return inferTypeNameFromSize(derefSize, false);
                }
            }

            // Check STORE operations using this pointer
            if (opcode == PcodeOp.STORE && use.getNumInputs() >= 3 && use.getInput(1) == pointer) {
                Varnode storedValue = use.getInput(2);
                if (storedValue != null) {
                    int derefSize = storedValue.getSize();
                    return inferTypeNameFromSize(derefSize, false);
                }
            }

            // Recurse through pointer arithmetic
            if (opcode == PcodeOp.PTRADD || opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB) {
                Varnode output = use.getOutput();
                if (output != null) {
                    String type = inferPointedType(output, visited, depth + 1);
                    if (type != null) {
                        return type;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Check if a PcodeOp opcode represents a floating-point operation.
     */
    private boolean isFloatOperation(int opcode) {
        switch (opcode) {
            case PcodeOp.FLOAT_ADD:
            case PcodeOp.FLOAT_SUB:
            case PcodeOp.FLOAT_MULT:
            case PcodeOp.FLOAT_DIV:
            case PcodeOp.FLOAT_NEG:
            case PcodeOp.FLOAT_ABS:
            case PcodeOp.FLOAT_SQRT:
            case PcodeOp.FLOAT_CEIL:
            case PcodeOp.FLOAT_FLOOR:
            case PcodeOp.FLOAT_ROUND:
            case PcodeOp.FLOAT_NAN:
            case PcodeOp.FLOAT_EQUAL:
            case PcodeOp.FLOAT_NOTEQUAL:
            case PcodeOp.FLOAT_LESS:
            case PcodeOp.FLOAT_LESSEQUAL:
            case PcodeOp.FLOAT_INT2FLOAT:
            case PcodeOp.FLOAT_FLOAT2FLOAT:
            case PcodeOp.FLOAT_TRUNC:
                return true;
            default:
                return false;
        }
    }

    /**
     * Infer a C type name from field size.
     */
    static String inferTypeNameFromSize(int size, boolean isPointer) {
        if (isPointer) {
            return "void*";
        }

        switch (size) {
            case 1: return "byte";
            case 2: return "short";
            case 4: return "int";
            case 8: return "longlong";
            default: return "undefined" + size;
        }
    }

    /**
     * Get the inferred type string for this field.
     */
    String getInferredType() {
        // Array takes precedence
        if (isArray && arrayLength > 0) {
            // Calculate actual element size (size was mutated to total array size)
            int elementSize = size / arrayLength;
            String baseType;
            if (isFloatingPoint) {
                baseType = (elementSize == 4) ? "float" : (elementSize == 8) ? "double" : "float" + (elementSize * 8);
            } else if (isPointer) {
                baseType = (pointedType != null) ? pointedType + "*" : "void*";
            } else {
                baseType = inferTypeNameFromSize(elementSize, false);
            }
            return baseType + "[" + arrayLength + "]";
        }

        // Pointer types
        if (isPointer) {
            if (pointedType != null) {
                return pointedType + "*";
            }
            return "void*";
        }

        // Floating point types
        if (isFloatingPoint) {
            return (size == 4) ? "float" : (size == 8) ? "double" : "float" + (size * 8);
        }

        // Default size-based inference
        return inferTypeNameFromSize(size, false);
    }

    /**
     * Calculate confidence score based on:
     * - Function coverage: How many distinct functions accessed this field
     * - Size consistency: Whether all accesses use the same size
     * - Access pattern: Read-only fields might be inherited (slightly lower confidence)
     *
     * @param totalFunctions Total number of functions analyzed
     * @return Confidence score between 0.0 and 1.0
     */
    private double calculateConfidence(int totalFunctions) {
        if (totalFunctions == 0) {
            return 1.0;
        }

        // Function coverage: distinctFunctions / totalFunctions
        int distinctFunctionCount = accessingFunctions.size();
        double functionCoverage = distinctFunctionCount / (double) totalFunctions;

        // Size consistency: all accesses use the same size?
        boolean sizeConsistent = observedSizes.size() <= 1;
        double sizeConsistencyFactor = sizeConsistent ? 1.0 : 0.7;

        // Access pattern: read-only fields might be inherited base class members
        // (slightly lower confidence)
        boolean isReadOnly = (storeCount == 0 && loadCount > 0);
        double accessPatternFactor = isReadOnly ? 0.9 : 1.0;

        // Combined confidence
        double confidence = functionCoverage * sizeConsistencyFactor * accessPatternFactor;

        // Cap at 1.0
        return Math.min(1.0, confidence);
    }

    /**
     * Determine access pattern string for display.
     */
    private String getAccessPattern() {
        if (storeCount > 0 && loadCount > 0) {
            return "read-write";
        } else if (storeCount > 0) {
            return "write-only";
        } else if (loadCount > 0) {
            return "read-only";
        }
        return "none";
    }

    Map<String, Object> toMap(int totalFunctions) {
        int totalAccesses = storeCount + loadCount;
        double confidence = calculateConfidence(totalFunctions);

        Map<String, Object> map = new HashMap<>();
        map.put("offset", offset);
        map.put("size", size);
        map.put("inferredType", getInferredType());
        map.put("accessCount", totalAccesses);
        map.put("storeCount", storeCount);
        map.put("loadCount", loadCount);
        map.put("distinctFunctionCount", accessingFunctions.size());
        map.put("sizeConsistent", observedSizes.size() <= 1);
        map.put("accessPattern", getAccessPattern());
        map.put("confidence", Math.round(confidence * 100) / 100.0);

        // Add enhanced type information
        if (isArray) {
            map.put("isArray", true);
            map.put("arrayLength", arrayLength);
        }
        if (isPointer) {
            map.put("isPointer", true);
            if (pointedType != null) {
                map.put("pointedType", pointedType);
            }
        }
        if (isFloatingPoint) {
            map.put("isFloatingPoint", true);
        }

        return map;
    }
}

/**
 * Type of memory access for structure field tracking.
 */
enum AccessType {
    STORE, LOAD
}
