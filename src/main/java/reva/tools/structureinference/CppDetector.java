package reva.tools.structureinference;

import ghidra.framework.model.DomainFile;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Detects whether a program is written in C++. Uses tiered detection: strong indicators
 * (vtables, RTTI, C++ libraries) confirm immediately, weak indicators (mangled symbols)
 * require 3+ matches. Excludes Rust symbols and glibc C symbols. Two-tier caching
 * (in-memory LRU + Program Options) with version-based invalidation. Thread-safe.
 * See CLAUDE.md for detailed algorithm documentation.
 */
public class CppDetector {

    /**
     * Detector version. Increment when detection logic changes to invalidate
     * cached results and force re-detection with new logic.
     */
    private static final int DETECTOR_VERSION = 1;

    /** Maximum symbols to scan before stopping */
    private static final int MAX_SYMBOLS_TO_CHECK = 2000;

    /** Maximum cache entries (LRU eviction beyond this) */
    private static final int MAX_CACHE_SIZE = 100;

    /**
     * Weak indicator count required to confirm C++.
     * Set to 3 to balance:
     * - False positives: A C program with 1-2 coincidental _Z symbols won't trigger
     * - False negatives: Small C++ programs with few exported symbols still detected
     * Based on empirical testing with common binaries.
     */
    private static final int WEAK_INDICATOR_THRESHOLD = 3;

    /** Options category for ReVa settings */
    private static final String OPTIONS_CATEGORY = "ReVa";

    /** Key for cached C++ detection result */
    private static final String KEY_IS_CPP = "CppDetector.isCpp";

    /** Key for detector version (for cache invalidation on logic changes) */
    private static final String KEY_VERSION = "CppDetector.version";

    /**
     * Strong C++ indicators. These are highly specific to C++ and
     * don't appear in C, Rust, or other languages.
     */
    private static final List<String> STRONG_PREFIXES = Arrays.asList(
        "_ZTV",     // GCC/Clang vtable
        "_ZTI",     // GCC/Clang typeinfo structure
        "_ZTS",     // GCC/Clang typeinfo name string
        "__ZTV",    // Mach-O vtable (double underscore)
        "__ZTI",    // Mach-O typeinfo structure
        "__ZTS",    // Mach-O typeinfo name string
        "??_7",     // MSVC vftable
        "??_8"      // MSVC vbtable
    );

    /**
     * C++ standard library names. Presence of these confirms C++.
     */
    private static final List<String> CPP_LIBRARY_NAMES = Arrays.asList(
        "msvcp",        // MSVC C++ runtime
        "libstdc++",    // GCC C++ standard library
        "libc++",       // LLVM/Clang C++ standard library
        "libc++abi",    // LLVM C++ ABI library
        "libcxxabi"     // Alternative C++ ABI library name
    );

    /**
     * Weak C++ indicator prefixes. These can appear in other contexts
     * (Rust uses _Z, small C++ programs may have few symbols).
     * Includes both standard and Mach-O (double underscore) variants.
     */
    private static final List<String> WEAK_PREFIXES = Arrays.asList(
        "_Z",                   // GCC/Clang mangling (also used by Rust)
        "__Z",                  // Mach-O variant (double underscore)
        "??_",                  // MSVC special symbols
        "W?",                   // Watcom C++ mangling
        "__gxx_personality",    // GCC exception personality
        "___gxx_personality"    // Mach-O exception personality (triple underscore)
    );

    /**
     * Symbols to ignore. These appear in C programs via glibc.
     * Using Set for O(1) lookup.
     */
    private static final Set<String> IGNORED_SYMBOLS = Set.of(
        "__cxa_atexit",
        "__cxa_finalize"
    );

    /**
     * Pattern to identify Rust symbols (legacy Itanium ABI).
     * Rust symbols: _ZN...{length}h{hash}E or __ZN... (Mach-O)
     * Example: _ZN3std2io5stdio6_print17h835f773f2f89a502E
     *
     * Pattern breakdown:
     * - ^_?_ZN = optional leading underscore (Mach-O) followed by _ZN
     * - .* = path components
     * - \d+h = length prefix before 'h' marker
     * - [0-9a-f]+ = hex hash (typically 16 chars)
     * - E$ = closing E at end
     */
    private static final Pattern RUST_SYMBOL_PATTERN =
        Pattern.compile("^_?_ZN.*\\d+h[0-9a-f]+E$");

    /**
     * Thread-safe in-memory cache using ConcurrentHashMap.
     * Cache is bounded by periodic cleanup when size exceeds MAX_CACHE_SIZE.
     * No LRU eviction - simple size-based cleanup (adequate for session-scoped cache).
     */
    private static final ConcurrentHashMap<String, Boolean> cache = new ConcurrentHashMap<>();

    /**
     * Check if a program is written in C++.
     *
     * <p>Uses two-tier caching:</p>
     * <ol>
     *   <li>In-memory ConcurrentHashMap cache (fast, session-scoped)</li>
     *   <li>Program Options (persistent, survives Ghidra restarts)</li>
     *   <li>Full detection (only if not cached anywhere)</li>
     * </ol>
     *
     * <p>Thread-safe: Uses ConcurrentHashMap.computeIfAbsent for atomic cache updates.</p>
     *
     * @param program The program to analyze
     * @return true if the program appears to be C++
     */
    public static boolean isCppProgram(Program program) {
        if (program == null) {
            return false;
        }

        String cacheKey = buildCacheKey(program);

        // Use computeIfAbsent for atomic cache lookup and population
        return cache.computeIfAbsent(cacheKey, key -> {
            // Tier 2: Check Program Options (persistent cache)
            Boolean persisted = loadFromProgramOptions(program);
            if (persisted != null) {
                return persisted;
            }

            // Tier 3: Full detection
            boolean result = detectCpp(program);

            // Persist for future sessions (best effort)
            saveToProgramOptions(program, result);

            // Periodic cache cleanup if too large
            if (cache.size() > MAX_CACHE_SIZE) {
                // Remove roughly half the entries (simple cleanup, not LRU)
                int toRemove = cache.size() / 2;
                cache.keySet().stream().limit(toRemove).forEach(cache::remove);
            }

            return result;
        });
    }

    /**
     * Clear the in-memory detection cache. Call during plugin shutdown.
     * Does not clear persistent Program Options (those are per-program).
     */
    public static void clearCache() {
        cache.clear();
    }

    /**
     * Invalidate cache for a specific program.
     * Clears both persistent Program Options and in-memory cache.
     * Call when program symbols are modified.
     *
     * <p>Note: Clears persistent cache first to prevent stale data from being
     * reloaded by a concurrent call before in-memory cache is cleared.</p>
     *
     * @param program The program to invalidate
     */
    public static void invalidateCache(Program program) {
        if (program == null) {
            return;
        }

        // Clear persistent first to prevent stale reload
        clearProgramOptions(program);

        // Then clear in-memory cache
        cache.remove(buildCacheKey(program));
    }

    /**
     * Load cached result from Program Options.
     *
     * @param program The program to load from
     * @return The cached result, or null if not cached or version mismatch
     */
    private static Boolean loadFromProgramOptions(Program program) {
        try {
            if (program.isClosed()) {
                return null;
            }

            Options options = program.getOptions(OPTIONS_CATEGORY);

            // Check if we have cached data
            if (!options.contains(KEY_IS_CPP)) {
                return null;
            }

            // Check version - re-detect if detector logic has changed
            int version = options.getInt(KEY_VERSION, 0);
            if (version != DETECTOR_VERSION) {
                Msg.debug(CppDetector.class,
                    "C++ detection cache invalidated for " + program.getName() +
                    ": version mismatch (cached=" + version + ", current=" + DETECTOR_VERSION + ")");
                return null;
            }

            return options.getBoolean(KEY_IS_CPP, false);
        } catch (Exception e) {
            // If anything goes wrong, return null to trigger re-detection
            Msg.debug(CppDetector.class,
                "Failed to load C++ detection from Program Options: " + e.getMessage());
            return null;
        }
    }

    /**
     * Save detection result to Program Options for persistence.
     * Best effort - failures are logged but don't affect the caller.
     *
     * @param program The program to save to
     * @param isCpp The detection result
     */
    private static void saveToProgramOptions(Program program, boolean isCpp) {
        if (!canWriteToProgram(program)) {
            return;
        }

        int transactionId = -1;
        boolean success = false;
        try {
            transactionId = program.startTransaction("ReVa: Cache C++ detection");
            Options options = program.getOptions(OPTIONS_CATEGORY);
            options.setBoolean(KEY_IS_CPP, isCpp);
            options.setInt(KEY_VERSION, DETECTOR_VERSION);
            success = true;
        } catch (Exception e) {
            Msg.warn(CppDetector.class,
                "Failed to persist C++ detection result: " + e.getMessage());
        } finally {
            if (transactionId != -1) {
                program.endTransaction(transactionId, success);
            }
        }
    }

    /**
     * Clear cached result from Program Options.
     * Best effort - failures are logged but don't affect the caller.
     *
     * @param program The program to clear
     */
    private static void clearProgramOptions(Program program) {
        if (!canWriteToProgram(program)) {
            return;
        }

        int transactionId = -1;
        boolean success = false;
        try {
            transactionId = program.startTransaction("ReVa: Clear C++ detection cache");
            Options options = program.getOptions(OPTIONS_CATEGORY);

            if (options.contains(KEY_IS_CPP)) {
                options.removeOption(KEY_IS_CPP);
            }
            if (options.contains(KEY_VERSION)) {
                options.removeOption(KEY_VERSION);
            }
            success = true;
        } catch (Exception e) {
            Msg.warn(CppDetector.class,
                "Failed to clear C++ detection cache: " + e.getMessage());
        } finally {
            if (transactionId != -1) {
                program.endTransaction(transactionId, success);
            }
        }
    }

    private static boolean canWriteToProgram(Program program) {
        try {
            if (program.isClosed()) return false;
            DomainFile df = program.getDomainFile();
            return df == null || !df.isReadOnly();
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean detectCpp(Program program) {
        // Fast path: C++ library imports
        if (hasCppLibrary(program)) {
            return true;
        }

        // Analyze symbols
        return analyzeSymbols(program);
    }

    private static boolean hasCppLibrary(Program program) {
        ExternalManager extMgr = program.getExternalManager();
        if (extMgr == null) {
            return false;
        }

        String[] libNames = extMgr.getExternalLibraryNames();
        if (libNames == null) {
            return false;
        }

        for (String lib : libNames) {
            if (isCppLibraryName(lib)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a library name indicates C++ usage.
     *
     * @param libraryName The library name to check (may be null)
     * @return true if this is a C++ library
     */
    private static boolean isCppLibraryName(String libraryName) {
        if (libraryName == null) {
            return false;
        }
        String lower = libraryName.toLowerCase();
        for (String cppLib : CPP_LIBRARY_NAMES) {
            if (lower.contains(cppLib)) {
                return true;
            }
        }
        return false;
    }

    private static boolean analyzeSymbols(Program program) {
        SymbolTable symbolTable = program.getSymbolTable();
        if (symbolTable == null) {
            return false;
        }

        SymbolIterator iter = symbolTable.getAllSymbols(true);

        int weakCount = 0;
        int checked = 0;

        while (iter.hasNext() && checked < MAX_SYMBOLS_TO_CHECK) {
            checked++;

            Symbol symbol = iter.next();
            if (symbol == null) {
                continue;
            }

            String name = symbol.getName();
            if (name == null || name.isEmpty()) {
                continue;
            }

            // Skip false positive sources
            if (shouldIgnore(name)) {
                continue;
            }

            // Strong indicator = immediate confirmation
            if (isStrongIndicator(name)) {
                return true;
            }

            // Weak indicator = count toward threshold
            if (isWeakIndicator(name)) {
                weakCount++;
                if (weakCount >= WEAK_INDICATOR_THRESHOLD) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean shouldIgnore(String name) {
        return IGNORED_SYMBOLS.contains(name) || isRustSymbol(name);
    }

    private static boolean isRustSymbol(String name) {
        // Quick rejection before expensive regex
        // Check both standard and Mach-O prefixes
        if (!name.startsWith("_ZN") && !name.startsWith("__ZN")) {
            return false;
        }
        return RUST_SYMBOL_PATTERN.matcher(name).matches();
    }

    private static boolean isStrongIndicator(String name) {
        return matchesAnyPrefix(name, STRONG_PREFIXES);
    }

    private static boolean isWeakIndicator(String name) {
        // Check standard weak prefixes (includes Mach-O variants)
        if (matchesAnyPrefix(name, WEAK_PREFIXES)) {
            return true;
        }

        // MSVC mangled functions: ?name@@... (regular), ??0@@... (ctor), ??1@@... (dtor)
        // Note: ??_* symbols (vftable, RTTI, etc.) are already in WEAK_PREFIXES
        // Edge case: extern "C" functions may also match, but ?...@@ is very likely C++
        if (isMsvcMangled(name)) {
            return true;
        }

        // Borland/Embarcadero: @Class@Method$q...
        if (isBorlandMangled(name)) {
            return true;
        }

        return false;
    }

    private static boolean matchesAnyPrefix(String name, List<String> prefixes) {
        for (String prefix : prefixes) {
            if (name.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isMsvcMangled(String name) {
        // Pattern: ?name@@... or ??0Class@@... (constructor), ??1Class@@... (destructor)
        // Exclude ??_ which is already in WEAK_PREFIXES (avoids double counting)
        return name.startsWith("?")
            && name.contains("@@")
            && !name.startsWith("??_");
    }

    private static boolean isBorlandMangled(String name) {
        // Pattern: @ClassName@MethodName$q...
        return name.startsWith("@") && name.contains("$q");
    }

    /**
     * Build a cache key that uniquely identifies a program.
     *
     * Uses the program's unique ID (which survives saves) plus the pathname
     * for debugging clarity.
     */
    private static String buildCacheKey(Program program) {
        StringBuilder key = new StringBuilder();

        // Unique program ID (primary identifier, survives saves)
        long uniqueId = program.getUniqueProgramID();
        key.append(uniqueId);
        key.append('|');

        // Path for debugging clarity (secondary)
        DomainFile domainFile = program.getDomainFile();
        key.append(domainFile != null ? domainFile.getPathname() : program.getName());

        return key.toString();
    }
}
