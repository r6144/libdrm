#include <boost/utility.hpp>
#include <boost/ptr_container/ptr_set.hpp>
#include <cassert>
#include <iostream>
#include <stdint.h>
#include <sys/mman.h>
#include "mmap_manager.h"

// FIXME: Should have used sysconf(_SC_PAGE_SIZE)
#define PAGE_SHIFT 12
#define PAGE_SIZE (1U << PAGE_SHIFT)
#define PAGE_OFFSET_MASK (PAGE_SIZE - 1)

/* NOTE: We expect that a bom as well as all buffer objects in it will only be accessed by a single
   thread (note that each OpenGL context is only allowed to be accessed from a single thread as
   well).  However, other threads might call mmap unexpectedly, and we must take this into
   account. */
namespace mmap_manager_cpp {

inline bool is_whole_pages(uintptr_t size) {
    return (size & PAGE_OFFSET_MASK) == 0;
}

inline uintptr_t round_up_to_whole_pages(uintptr_t size) {
    uintptr_t rounded_size = (size + (PAGE_SIZE - 1)) & ~PAGE_OFFSET_MASK;
    assert(rounded_size >= size);
    return rounded_size;
}

class FreeBlock: boost::noncopyable {
public:
    explicit FreeBlock(uintptr_t size);
    FreeBlock(uintptr_t addr, uintptr_t size);
    ~FreeBlock();
    uintptr_t size() { return m_size; }
    uintptr_t steal(uintptr_t ssize);

    struct size_lt {
	// Blocks having the same size but different addresses must be able to coexist, so they
	// cannot compare equal (i.e. neither is less than the other).
	bool operator()(const FreeBlock &b1, const FreeBlock &b2) {
	    return (b1.m_size < b2.m_size
		    || (b1.m_size == b2.m_size && b1.m_addr < b2.m_addr));
	}
    };
private:
    uintptr_t m_addr, m_size;
}

FreeBlock::FreeBlock(uintptr_t size): m_size(size) {
    assert(is_whole_pages(size));
    void *result = mmap(0, size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert(result != MAP_FAILED);
    /* FIXME: Should really throw an exception and catch it in some kind of C wrapper in case an X
       client asks for some unreasonably large mapping, as we should not crash the X server in this
       case.  (But if the mapping nearly exhausts the X server's address space, it would fail in
       later allocations anyway.) */
    m_addr = static_cast<uintptr_t>(result);
}

/* NOTE: MAP_FIXED mmap()'s usually follow munmap() at the same address.  They risk a race with
   another thread mmap'ing the same address in the meantime, so failure is always possible. */
FreeBlock::FreeBlock(uintptr_t addr, uintptr_t size): m_addr(addr), m_size(size) {
    assert(is_whole_pages(size));
    void *result = mmap(static_cast<void *>(addr), size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    assert(result == static_cast<void *>(addr)); // FIXME: might fail due to a race
}


FreeBlock::~FreeBlock() {
    int result = munmap((void *) m_addr, m_size);
    assert(result == 0);
}

uintptr_t FreeBlock::steal(uintptr_t ssize) {
    assert(is_whole_pages(ssize)); assert(ssize <= m_size);
    ret = m_addr;
    int result = munmap((void *) m_addr, ssize); assert(result == 0);
    m_addr += ssize; m_size -= ssize;
    return ret;
    // NOTE: The caller should deallocate this FreeBlock if its size becomes zero
}

// Owns the FreeBlocks
/* FIXME: Does not yet combine adjacent free blocks.  This should not worsen worst-case address-space consumption too much, though. */
/* FIXME: Does not yet keep track of used blocks, either.  Actual mapping/unmapping is performed by
 * the caller, which is not very good encapsulation. */
class MMapManager: boost::noncopyable {
public:
    MMapManager();
    uintptr_t get_map_addr(uintptr_t size);
    void free_map_addr(uintptr_t addr, uintptr_t size);
private:
    boost::ptr_set<FreeBlock, FreeBlock::size_lt> m_free_blks;
    uintptr_t m_next_alloc_size;
    static const max_alloc_size = 256 * 1024 * 1024;
};

MMapManager::MMapManager(): m_next_alloc_size(16 * PAGE_SIZE) {}

uintptr_t MMapManager::get_map_addr(uintptr_t size) {
    
}

void MMapManager::free_map_addr(uintptr_t addr, uintptr_t size) {
    
} // end of namespace mmap_manager_cpp



using namespace mmap_manager_cpp;

void *new_mmap_manager(void)
{
    return new MMapManager;
}

void free_mmap_manager(void *pman)
{
    delete static_cast<MMapManager *>(pman);
}
