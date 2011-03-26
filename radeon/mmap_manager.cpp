#include "mmap_manager.h"
#include <boost/utility.hpp>

class MMapManager: boost::noncopyable {
    
};

void *new_mmap_manager(void)
{
    return new MMapManager;
}

void free_mmap_manager(void *pman)
{
    delete static_cast<MMapManager *>(pman);
}
