# ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Makefile for ReVa structure inference test binary
#
# Builds a single comprehensive test binary for integration testing
# of structure inference tools (infer-structure, find-matching-structures)
#
# BUILD REQUIREMENTS:
#   - Linux/macOS (not Windows - uses bash and make)
#   - g++ (GNU C++ compiler)
#   - make (GNU Make)
#
# If you're on Windows, either:
#   1. Use WSL (Windows Subsystem for Linux)
#   2. Use MinGW/MSYS2 with bash and g++
#   3. Skip integration tests: gradle build -x integrationTest
#
# KEY DESIGN: Each method accesses only a SUBSET of fields.
# Multi-function analysis is REQUIRED to discover complete structure layouts.

CXX = g++

# Use -O0 to disable all optimizations for maximum predictability in tests.
# This ensures field accesses are preserved exactly as written in the source.
# -fno-omit-frame-pointer helps with stack analysis
# -fno-inline prevents inlining that could merge field accesses (redundant with -O0 but explicit)
CXXFLAGS = -O0 -fno-omit-frame-pointer -fno-inline -Wall

# Output directory (parent of src/)
OUTDIR = ..

.PHONY: all clean info

all: $(OUTDIR)/structure_test

$(OUTDIR)/structure_test: structure_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(OUTDIR)/structure_test

rebuild: clean all

# Show expected layouts (documentation)
info:
	@echo "Structure Test Binary - Multi-Function Inference Test"
	@echo ""
	@echo "KEY: Each method accesses ONLY specific fields."
	@echo "     Multi-function analysis REQUIRED for complete layouts."
	@echo ""
	@echo "=== INHERITANCE HIERARCHY ==="
	@echo ""
	@echo "class GameObject (base, 24 bytes):"
	@echo "  offset 0:  vptr (8 bytes)"
	@echo "  offset 8:  int id (4 bytes) - ONLY by getId/setId"
	@echo "  offset 12: float x (4 bytes) - ONLY by position methods"
	@echo "  offset 16: float y (4 bytes) - ONLY by position methods"
	@echo "  offset 20: float z (4 bytes) - ONLY by position methods"
	@echo ""
	@echo "class Character : GameObject (56 bytes):"
	@echo "  offset 0-23: GameObject base"
	@echo "  offset 24: int health (4 bytes) - ONLY by health methods"
	@echo "  offset 28: int mana (4 bytes) - ONLY by mana methods"
	@echo "  offset 32: char* name (8 bytes) - ONLY by name methods"
	@echo "  offset 40: float stats[4] (16 bytes) - ONLY by stat methods"
	@echo ""
	@echo "class Enemy : GameObject (40 bytes):"
	@echo "  offset 0-23: GameObject base"
	@echo "  offset 24: int damage (4 bytes) - ONLY by damage methods"
	@echo "  offset 28: int armor (4 bytes) - ONLY by armor methods"
	@echo "  offset 32: Character* target (8 bytes) - ONLY by target methods"
	@echo ""
	@echo "=== CONFUSING SIMILAR STRUCTURES (NOT RELATED) ==="
	@echo ""
	@echo "class Projectile (UNRELATED, 40 bytes) - SAME offsets as GameObject:"
	@echo "  offset 0:  vptr (8 bytes)"
	@echo "  offset 8:  int projectileId (4 bytes) - SAME as GameObject::id"
	@echo "  offset 12: float posX (4 bytes) - SAME as GameObject::x"
	@echo "  offset 16: float posY (4 bytes) - SAME as GameObject::y"
	@echo "  offset 20: float posZ (4 bytes) - SAME as GameObject::z"
	@echo "  offset 24: float velocityX (4 bytes) - UNIQUE to Projectile"
	@echo "  offset 28: float velocityY (4 bytes) - UNIQUE to Projectile"
	@echo "  offset 32: float velocityZ (4 bytes) - UNIQUE to Projectile"
	@echo "  offset 36: int damage (4 bytes) - UNIQUE to Projectile"
	@echo ""
	@echo "struct SimpleCoords (NO VTABLE, 16 bytes) - DIFFERENT offsets:"
	@echo "  offset 0:  int id (4 bytes) - NOT 8 like classes with vtable"
	@echo "  offset 4:  float x (4 bytes) - NOT 12 like classes with vtable"
	@echo "  offset 8:  float y (4 bytes) - NOT 16 like classes with vtable"
	@echo "  offset 12: float z (4 bytes) - NOT 20 like classes with vtable"
	@echo ""
	@echo "=== TEST SCENARIOS ==="
	@echo "  1. setId alone -> only offset 8"
	@echo "  2. setPosition alone -> only offsets 12,16,20"
	@echo "  3. setId + setPosition -> complete GameObject"
	@echo "  4. Character health methods -> only offset 24"
	@echo "  5. All Character methods -> complete Character layout"
	@echo "  6. setProjectileId vs setId -> SAME offset 8 (confusing!)"
	@echo "  7. setVelocity -> offsets 24,28,32 (distinguishes from GameObject)"
	@echo "  8. setSimpleCoordsId -> offset 0 (proves no vtable)"
