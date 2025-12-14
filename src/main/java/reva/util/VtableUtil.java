package reva.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Utility class for vtable (virtual function table) detection and analysis.
 * Provides shared functionality used by multiple tool providers.
 */
public final class VtableUtil {

    /** Number of entries to probe when checking if an address is a vtable */
    public static final int VTABLE_PROBE_ENTRIES = 5;

    /** Minimum function pointers required to consider an address a vtable (must be <= VTABLE_PROBE_ENTRIES) */
    public static final int MIN_VTABLE_FUNCTION_POINTERS = 2;

    private VtableUtil() {
        // Utility class - prevent instantiation
    }

    /**
     * Check if an address likely points to a vtable by checking for consecutive function pointers.
     *
     * @param program The program to analyze
     * @param addr The address to check
     * @return true if the address appears to be a vtable (has at least MIN_VTABLE_FUNCTION_POINTERS consecutive function pointers)
     */
    public static boolean isLikelyVtable(Program program, Address addr) {
        if (program == null || addr == null) {
            return false;
        }

        int pointerSize = program.getDefaultPointerSize();
        Memory memory = program.getMemory();
        FunctionManager funcMgr = program.getFunctionManager();

        int functionPointers = 0;

        for (int i = 0; i < VTABLE_PROBE_ENTRIES; i++) {
            try {
                Address checkAddr = addr.addNoWrap((long) i * pointerSize);

                if (!memory.contains(checkAddr)) {
                    break;
                }

                long pointerValue = readPointer(memory, checkAddr, pointerSize);
                Address targetAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(pointerValue);

                if (targetAddr != null && funcMgr.getFunctionAt(targetAddr) != null) {
                    functionPointers++;
                }
            } catch (AddressOverflowException e) {
                break; // Reached end of address space
            } catch (MemoryAccessException e) {
                break; // Memory not readable
            } catch (Exception e) {
                break; // Other error
            }
        }

        return functionPointers >= MIN_VTABLE_FUNCTION_POINTERS;
    }

    /**
     * Read a pointer value from memory.
     *
     * @param memory The program memory
     * @param addr The address to read from
     * @param pointerSize The size of pointers (4 or 8 bytes)
     * @return The pointer value
     * @throws MemoryAccessException if the memory cannot be read
     */
    public static long readPointer(Memory memory, Address addr, int pointerSize) throws MemoryAccessException {
        if (pointerSize == 8) {
            return memory.getLong(addr);
        } else {
            return memory.getInt(addr) & 0xFFFFFFFFL;
        }
    }

    /**
     * Convert a raw pointer value to an Address in the default address space.
     *
     * @param program The program
     * @param offset The raw pointer value
     * @return The Address object
     */
    public static Address toAddress(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
}
