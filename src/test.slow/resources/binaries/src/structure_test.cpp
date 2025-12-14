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
 *
 * structure_test.cpp - Test program for multi-function structure inference
 *
 * KEY DESIGN: Each method only accesses a SUBSET of fields.
 * This means you MUST analyze multiple functions together to get the
 * complete structure layout. Single-function analysis will only reveal
 * partial information.
 *
 * EXPECTED LAYOUTS (64-bit Linux, g++ default ABI):
 *
 * class GameObject (base class with vtable):
 *   offset 0:  vptr (8 bytes) - vtable pointer
 *   offset 8:  int id (4 bytes) - ONLY accessed by getId/setId
 *   offset 12: float x (4 bytes) - ONLY accessed by position methods
 *   offset 16: float y (4 bytes) - ONLY accessed by position methods
 *   offset 20: float z (4 bytes) - ONLY accessed by position methods
 *   Total: 24 bytes
 *
 * class Character (extends GameObject):
 *   offset 0-23: GameObject base
 *   offset 24: int health (4 bytes) - ONLY accessed by health methods
 *   offset 28: int mana (4 bytes) - ONLY accessed by mana methods
 *   offset 32: char* name (8 bytes) - ONLY accessed by name methods
 *   offset 40: float stats[4] (16 bytes) - ONLY accessed by stat methods
 *   Total: 56 bytes
 *
 * MULTI-FUNCTION TEST SCENARIOS:
 *
 * 1. Single function (setId) -> only sees offset 8 (id)
 * 2. Single function (setPosition) -> only sees offsets 12,16,20 (x,y,z)
 * 3. Multiple functions (setId + setPosition) -> sees full GameObject layout
 * 4. Character methods individually -> each sees only one field
 * 5. All Character methods together -> sees complete derived class layout
 */

#include <cstdio>
#include <cstring>

/*
 * ============================================================================
 * GameObject - Base class with vtable
 * Each method accesses ONLY specific fields
 * ============================================================================
 */
class GameObject {
protected:
    int id;         /* offset 8 - ONLY accessed by getId/setId */
    float x;        /* offset 12 - ONLY accessed by position methods */
    float y;        /* offset 16 - ONLY accessed by position methods */
    float z;        /* offset 20 - ONLY accessed by position methods */

public:
    GameObject() : id(0), x(0.0f), y(0.0f), z(0.0f) {}
    virtual ~GameObject() {}

    /* ===== ID methods - ONLY access 'id' field ===== */

    void setId(int newId) {
        id = newId;
    }

    int getId() {
        return id;
    }

    /* ===== Position methods - ONLY access x,y,z fields ===== */

    void setPosition(float px, float py, float pz) {
        x = px;
        y = py;
        z = pz;
    }

    float getX() { return x; }
    float getY() { return y; }
    float getZ() { return z; }

    /* Move modifies position with float operations */
    void move(float dx, float dy, float dz) {
        x += dx;
        y += dy;
        z += dz;
    }

    /* Virtual method for polymorphism - creates vtable */
    virtual void update() {
        /* Base implementation does nothing special */
    }

    virtual void print() {
        printf("GameObject[%d] at (%.1f, %.1f, %.1f)\n", id, x, y, z);
    }
};

/*
 * ============================================================================
 * Character - Derived class with additional fields
 * Each method accesses ONLY specific fields from Character
 * Multi-function analysis needed to see complete layout
 * ============================================================================
 */
class Character : public GameObject {
private:
    int health;         /* offset 24 - ONLY accessed by health methods */
    int mana;           /* offset 28 - ONLY accessed by mana methods */
    char* name;         /* offset 32 - ONLY accessed by name methods */
    float stats[4];     /* offset 40 - ONLY accessed by stat methods */
                        /* stats: [0]=strength, [1]=defense, [2]=agility, [3]=luck */

public:
    Character() : GameObject(), health(100), mana(50), name(nullptr) {
        stats[0] = 10.0f;
        stats[1] = 10.0f;
        stats[2] = 10.0f;
        stats[3] = 10.0f;
    }

    virtual ~Character() {}

    /* ===== Health methods - ONLY access 'health' field ===== */

    void setHealth(int h) {
        health = h;
    }

    int getHealth() {
        return health;
    }

    void takeDamage(int damage) {
        health -= damage;
        if (health < 0) health = 0;
    }

    void heal(int amount) {
        health += amount;
        if (health > 100) health = 100;
    }

    bool isAlive() {
        return health > 0;
    }

    /* ===== Mana methods - ONLY access 'mana' field ===== */

    void setMana(int m) {
        mana = m;
    }

    int getMana() {
        return mana;
    }

    void useMana(int amount) {
        mana -= amount;
        if (mana < 0) mana = 0;
    }

    void restoreMana(int amount) {
        mana += amount;
        if (mana > 100) mana = 100;
    }

    bool hasMana(int required) {
        return mana >= required;
    }

    /* ===== Name methods - ONLY access 'name' field (pointer) ===== */

    void setName(const char* newName) {
        name = const_cast<char*>(newName);
    }

    const char* getName() {
        return name;
    }

    /* Dereferences the name pointer - tests pointer detection */
    char getFirstLetter() {
        if (name != nullptr && name[0] != '\0') {
            return name[0];
        }
        return '?';
    }

    int getNameLength() {
        if (name == nullptr) return 0;
        int len = 0;
        while (name[len] != '\0') len++;
        return len;
    }

    /* ===== Stat methods - ONLY access 'stats' array ===== */

    void setStat(int index, float value) {
        if (index >= 0 && index < 4) {
            stats[index] = value;
        }
    }

    float getStat(int index) {
        if (index >= 0 && index < 4) {
            return stats[index];
        }
        return 0.0f;
    }

    /* Accesses all stats - should detect as float array */
    float getTotalStats() {
        return stats[0] + stats[1] + stats[2] + stats[3];
    }

    /* Float multiply on stats - triggers FLOAT_MULT detection */
    void boostStats(float multiplier) {
        stats[0] *= multiplier;
        stats[1] *= multiplier;
        stats[2] *= multiplier;
        stats[3] *= multiplier;
    }

    void setAllStats(float strength, float defense, float agility, float luck) {
        stats[0] = strength;
        stats[1] = defense;
        stats[2] = agility;
        stats[3] = luck;
    }

    /* ===== Override methods - access fields from BOTH base and derived ===== */

    void update() override {
        /* This method accesses fields from both classes */
        /* Base class fields */
        x += 0.1f;
        y += 0.1f;

        /* Derived class fields */
        if (health < 100) {
            health += 1;  /* Slow regeneration */
        }
        if (mana < 50) {
            mana += 1;
        }
    }

    void print() override {
        printf("Character '%s' [%d] at (%.1f,%.1f,%.1f) HP:%d MP:%d\n",
               name ? name : "unnamed", id, x, y, z, health, mana);
    }
};

/*
 * ============================================================================
 * Enemy - Another derived class to test inheritance detection
 * ============================================================================
 */
class Enemy : public GameObject {
private:
    int damage;         /* offset 24 - attack damage */
    int armor;          /* offset 28 - damage reduction */
    Character* target;  /* offset 32 - pointer to target (tests pointer to class) */

public:
    Enemy() : GameObject(), damage(10), armor(5), target(nullptr) {}
    virtual ~Enemy() {}

    /* ===== Damage methods - ONLY access 'damage' field ===== */

    void setDamage(int d) {
        damage = d;
    }

    int getDamage() {
        return damage;
    }

    /* ===== Armor methods - ONLY access 'armor' field ===== */

    void setArmor(int a) {
        armor = a;
    }

    int getArmor() {
        return armor;
    }

    int getEffectiveDamage() {
        return damage - armor;  /* Uses both, but simple calculation */
    }

    /* ===== Target methods - ONLY access 'target' pointer ===== */

    void setTarget(Character* t) {
        target = t;
    }

    Character* getTarget() {
        return target;
    }

    /* Dereferences target pointer - tests pointer chain detection */
    void attackTarget() {
        if (target != nullptr) {
            target->takeDamage(damage);
        }
    }

    /* Accesses target's health through pointer */
    bool isTargetAlive() {
        if (target != nullptr) {
            return target->isAlive();
        }
        return false;
    }

    void update() override {
        /* Move toward position 0,0,0 */
        if (x > 0) x -= 0.5f;
        if (y > 0) y -= 0.5f;
        if (z > 0) z -= 0.5f;
    }

    void print() override {
        printf("Enemy[%d] at (%.1f,%.1f,%.1f) DMG:%d ARM:%d\n",
               id, x, y, z, damage, armor);
    }
};

/*
 * ============================================================================
 * Projectile - UNRELATED class with SIMILAR layout to GameObject
 *
 * This tests whether our tools can distinguish similar but unrelated structures.
 * Has vtable like GameObject, has id/x/y/z at SAME offsets (8/12/16/20).
 * BUT also has unique velocity fields at 24/28/32 that GameObject doesn't have.
 *
 * EXPECTED LAYOUT (64-bit Linux):
 *   offset 0:  vptr (8 bytes) - vtable pointer
 *   offset 8:  int projectileId (4 bytes) - SAME offset as GameObject::id
 *   offset 12: float posX (4 bytes) - SAME offset as GameObject::x
 *   offset 16: float posY (4 bytes) - SAME offset as GameObject::y
 *   offset 20: float posZ (4 bytes) - SAME offset as GameObject::z
 *   offset 24: float velocityX (4 bytes) - UNIQUE to Projectile
 *   offset 28: float velocityY (4 bytes) - UNIQUE to Projectile
 *   offset 32: float velocityZ (4 bytes) - UNIQUE to Projectile
 *   offset 36: int damage (4 bytes) - UNIQUE to Projectile
 *   Total: 40 bytes
 *
 * KEY: Analyzing setProjectileId gives SAME result as setId (offset 8)
 *      But analyzing setVelocity gives DIFFERENT offsets (24,28,32)
 * ============================================================================
 */
class Projectile {
private:
    int projectileId;    /* offset 8 - SAME offset as GameObject::id */
    float posX;          /* offset 12 - SAME offset as GameObject::x */
    float posY;          /* offset 16 - SAME offset as GameObject::y */
    float posZ;          /* offset 20 - SAME offset as GameObject::z */
    float velocityX;     /* offset 24 - UNIQUE to Projectile */
    float velocityY;     /* offset 28 - UNIQUE to Projectile */
    float velocityZ;     /* offset 32 - UNIQUE to Projectile */
    int damage;          /* offset 36 - UNIQUE to Projectile */

public:
    Projectile() : projectileId(0), posX(0), posY(0), posZ(0),
                   velocityX(0), velocityY(0), velocityZ(0), damage(0) {}
    virtual ~Projectile() {}

    /* ===== ID methods - ONLY access projectileId at offset 8 ===== */
    /* Same offset as GameObject::id - tests if tools can distinguish */

    void setProjectileId(int id) {
        projectileId = id;
    }

    int getProjectileId() {
        return projectileId;
    }

    /* ===== Position methods - ONLY access posX/Y/Z at offsets 12/16/20 ===== */
    /* Same offsets as GameObject::x/y/z */

    void setProjectilePosition(float x, float y, float z) {
        posX = x;
        posY = y;
        posZ = z;
    }

    float getPosX() { return posX; }
    float getPosY() { return posY; }
    float getPosZ() { return posZ; }

    /* ===== Velocity methods - ONLY access velocityX/Y/Z at offsets 24/28/32 ===== */
    /* These offsets are UNIQUE to Projectile - GameObject doesn't have them */

    void setVelocity(float vx, float vy, float vz) {
        velocityX = vx;
        velocityY = vy;
        velocityZ = vz;
    }

    float getVelocityX() { return velocityX; }
    float getVelocityY() { return velocityY; }
    float getVelocityZ() { return velocityZ; }

    /* ===== Damage methods - ONLY access damage at offset 36 ===== */

    void setProjectileDamage(int d) {
        damage = d;
    }

    int getProjectileDamage() {
        return damage;
    }

    /* Virtual method - creates vtable */
    virtual void update() {
        posX += velocityX;
        posY += velocityY;
        posZ += velocityZ;
    }

    virtual void print() {
        printf("Projectile[%d] at (%.1f,%.1f,%.1f) vel (%.1f,%.1f,%.1f) dmg:%d\n",
               projectileId, posX, posY, posZ, velocityX, velocityY, velocityZ, damage);
    }
};

/*
 * ============================================================================
 * SimpleCoords - Plain C struct with NO VTABLE
 *
 * This tests whether our tools correctly handle structs without vtables.
 * Has same field TYPES as GameObject (int id, float x/y/z) but at DIFFERENT offsets
 * because there's no vtable pointer.
 *
 * EXPECTED LAYOUT (64-bit Linux):
 *   offset 0:  int id (4 bytes) - DIFFERENT from GameObject (which has id at 8)
 *   offset 4:  float x (4 bytes) - DIFFERENT from GameObject (which has x at 12)
 *   offset 8:  float y (4 bytes) - DIFFERENT from GameObject (which has y at 16)
 *   offset 12: float z (4 bytes) - DIFFERENT from GameObject (which has z at 20)
 *   Total: 16 bytes
 *
 * KEY: Analyzing setSimpleCoordsId finds offset 0 (NOT 8 like classes with vtable)
 * ============================================================================
 */
struct SimpleCoords {
    int id;          /* offset 0 - NOT 8 like classes with vtable */
    float x;         /* offset 4 - NOT 12 like classes with vtable */
    float y;         /* offset 8 - NOT 16 like classes with vtable */
    float z;         /* offset 12 - NOT 20 like classes with vtable */
};

/* Standalone functions for SimpleCoords - tests struct field inference */

void setSimpleCoordsId(SimpleCoords* s, int newId) {
    s->id = newId;
}

int getSimpleCoordsId(SimpleCoords* s) {
    return s->id;
}

void setSimpleCoordsPosition(SimpleCoords* s, float px, float py, float pz) {
    s->x = px;
    s->y = py;
    s->z = pz;
}

float getSimpleCoordsX(SimpleCoords* s) { return s->x; }
float getSimpleCoordsY(SimpleCoords* s) { return s->y; }
float getSimpleCoordsZ(SimpleCoords* s) { return s->z; }

/*
 * ============================================================================
 * Standalone functions for testing non-method inference
 * ============================================================================
 */

/* Only accesses GameObject position fields */
void moveGameObject(GameObject* obj, float dx, float dy, float dz) {
    obj->move(dx, dy, dz);
}

/* Only accesses Character health */
void damageCharacter(Character* c, int amount) {
    c->takeDamage(amount);
}

/* Only accesses Character mana */
void drainMana(Character* c, int amount) {
    c->useMana(amount);
}

/* Only accesses Character stats */
void buffCharacter(Character* c, float multiplier) {
    c->boostStats(multiplier);
}

/* Accesses Enemy target pointer chain */
void commandAttack(Enemy* e) {
    e->attackTarget();
}

/*
 * ============================================================================
 * Main - exercises all methods to prevent optimization
 * ============================================================================
 */
int main() {
    /* Test GameObject */
    GameObject obj;
    obj.setId(1);
    obj.setPosition(10.0f, 20.0f, 30.0f);
    obj.move(1.0f, 2.0f, 3.0f);
    obj.update();
    obj.print();
    printf("GameObject ID: %d, X: %.1f\n", obj.getId(), obj.getX());

    /* Test Character */
    Character hero;
    hero.setId(100);
    hero.setPosition(0.0f, 0.0f, 0.0f);
    hero.setName("Hero");
    hero.setHealth(100);
    hero.setMana(50);
    hero.setAllStats(15.0f, 12.0f, 18.0f, 8.0f);

    printf("Character '%s' first letter: %c\n", hero.getName(), hero.getFirstLetter());
    printf("Name length: %d\n", hero.getNameLength());
    printf("Total stats: %.1f\n", hero.getTotalStats());

    hero.takeDamage(30);
    hero.heal(10);
    hero.useMana(20);
    hero.restoreMana(5);
    hero.boostStats(1.5f);

    printf("Health: %d, Mana: %d, Alive: %s\n",
           hero.getHealth(), hero.getMana(), hero.isAlive() ? "yes" : "no");
    printf("Has 30 mana: %s\n", hero.hasMana(30) ? "yes" : "no");

    hero.update();
    hero.print();

    /* Test Enemy */
    Enemy enemy;
    enemy.setId(200);
    enemy.setPosition(50.0f, 50.0f, 0.0f);
    enemy.setDamage(25);
    enemy.setArmor(10);
    enemy.setTarget(&hero);

    printf("Enemy effective damage: %d\n", enemy.getEffectiveDamage());
    printf("Target alive before attack: %s\n", enemy.isTargetAlive() ? "yes" : "no");

    enemy.attackTarget();
    printf("Hero health after attack: %d\n", hero.getHealth());

    enemy.update();
    enemy.print();

    /* Test standalone functions */
    moveGameObject(&obj, 5.0f, 5.0f, 5.0f);
    damageCharacter(&hero, 10);
    drainMana(&hero, 10);
    buffCharacter(&hero, 1.1f);
    commandAttack(&enemy);

    printf("Final hero state:\n");
    hero.print();

    /* Test Projectile - unrelated class with similar layout to GameObject */
    Projectile bullet;
    bullet.setProjectileId(999);
    bullet.setProjectilePosition(0.0f, 0.0f, 0.0f);
    bullet.setVelocity(1.0f, 0.5f, 0.0f);
    bullet.setProjectileDamage(50);
    bullet.update();
    bullet.print();
    printf("Projectile ID: %d, PosX: %.1f, VelX: %.1f, Damage: %d\n",
           bullet.getProjectileId(), bullet.getPosX(), bullet.getVelocityX(),
           bullet.getProjectileDamage());

    /* Test SimpleCoords - plain struct with no vtable */
    SimpleCoords coords;
    setSimpleCoordsId(&coords, 42);
    setSimpleCoordsPosition(&coords, 100.0f, 200.0f, 300.0f);
    printf("SimpleCoords ID: %d, X: %.1f, Y: %.1f, Z: %.1f\n",
           getSimpleCoordsId(&coords), getSimpleCoordsX(&coords),
           getSimpleCoordsY(&coords), getSimpleCoordsZ(&coords));

    return 0;
}
