#include <boost/utility.hpp>
#include <boost/ptr_container/ptr_set.hpp>
#include <boost/format.hpp>
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

inline bool is_whole_pages(size_t size) {
    return (size & PAGE_OFFSET_MASK) == 0;
}

inline size_t round_up_to_whole_pages(size_t size) {
    size_t rounded_size = (size + (PAGE_SIZE - 1)) & ~PAGE_OFFSET_MASK;
    assert(rounded_size >= size);
    return rounded_size;
}

class FreeBlock: boost::noncopyable {
public:
    explicit FreeBlock(size_t size);
    FreeBlock(uintptr_t addr, size_t size);
    ~FreeBlock();
    size_t size() { return m_size; }
    uintptr_t steal(size_t ssize);

    struct size_lt {
	// Blocks having the same size but different addresses must be able to coexist, so they
	// cannot compare equal (i.e. neither is less than the other).
	bool operator()(const FreeBlock &b1, const FreeBlock &b2) {
	    return (b1.m_size < b2.m_size
		    || (b1.m_size == b2.m_size && b1.m_addr < b2.m_addr));
	}
    };
private:
    uintptr_t m_addr;
    size_t m_size;
}

FreeBlock::FreeBlock(size_t size): m_size(size) {
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
   another thread mmap'ing the same address in the meantime, so failure is always possible.
   Upon failure, m_size will be zero. */
FreeBlock::FreeBlock(uintptr_t addr, size_t size): m_addr(addr), m_size(size) {
    assert(is_whole_pages(size));
    void *result = mmap(static_cast<void *>(addr), size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (result == MAP_FAILED) {
	std::cerr << boost::format("Failed to create FreeBlock at addr=0x%x, size=%u; race?\n") % addr % size;
	m_size = 0;
    } else assert(result == static_cast<void *>(addr));
}


FreeBlock::~FreeBlock() {
    if (m_size != 0) {
	int result = munmap((void *) m_addr, m_size);
	assert(result == 0);
    }
}

uintptr_t FreeBlock::steal(size_t ssize) {
    assert(is_whole_pages(ssize)); assert(ssize <= m_size);
    ret = m_addr;
    int result = munmap((void *) m_addr, ssize); assert(result == 0);
    m_addr += ssize; m_size -= ssize;
    return ret;
    // NOTE: The caller should deallocate this FreeBlock if its size becomes zero
}

/* Owns the FreeBlocks, and will thus unmap them upon freeing.  The mapped blocks are owned by the caller of map/unmap, though. */
class MMapManager: boost::noncopyable {
public:
    MMapManager();
    void *map(size_t len, int prot, int flags, int fd, off_t offset);
    void unmap(void *addr, size_t len);
private:
    boost::ptr_set<FreeBlock, FreeBlock::size_lt> m_free_blks;
    size_t m_last_alloc_size;
    static const size_t max_alloc_size = 256 * 1024 * 1024;
    void *find_free_addr(size_t size);
    void *try_map_from_blocks(size_t size, int prot, int flags, int fd, off_t offset);
};

MMapManager::MMapManager(): m_last_alloc_size(0) {}

/* Returns MAP_FAILED upon failure */
void *MMapManager::find_free_addr(size_t size) {
    // FIXME
}

/* If we fail due to any reason, return MAP_FAILED */
void *MMapManager::try_map_from_blocks(size_t size, int prot, int flags, int fd, off_t offset) {
    void *addr = find_free_addr(size);
    if (addr == MAP_FAILED) {
	if (size > max_alloc_size) return MAP_FAILED;
	size_t alloc_size = m_last_alloc_size;
	alloc_size = std::max(alloc_size, 16 * PAGE_SIZE);
	while (alloc_size < size && alloc_size < max_alloc_size) alloc_size <<= 1;
	assert(size <= alloc_size);
	m_free_blks.insert(new FreeBlock(alloc_size));
	m_last_alloc_size = alloc_size;
	addr = find_free_addr(size);
    }
    assert(addr != MAP_FAILED);
    void *result = mmap(addr, size, prot, flags | MAP_FIXED, fd, offset);
    if (result == MAP_FAILED)
	std::cerr << boost::format("Fixed mmap failed in try_map_from_blocks (addr=0x%x, size=%u); race?\n") % addr % size;
    return result;
}

void *MMapManager::map(size_t len, int prot, int flags, int fd, off_t offset) {
    size_t size = round_up_to_whole_pages(len);
    void *result = try_map_from_blocks(size, prot, flags, fd, offset);
    if (result == MAP_FAILED) {
	/* The mapping is so large that the number of such mappings is unlikely to be too many.  We thus allocate directly. */
	std::clog << boost::format("Direct allocation of size %u\n") % size;
	result = mmap(0, size, prot, flags, fd, offset);
    }
    return result;
}

/* FIXME: Does not yet keep track of the mappings */
void MMapManager::unmap(void *addr, size_t len) {
    size_t size = round_up_to_whole_pages(len);
    m_free_blks.insert(new FreeBlock(addr, len));
    // FIXME: check for zero-sized blocks
    // FIXME: combine adjacent free blocks by calling mremap()
}
    
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
