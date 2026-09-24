//! Module responsible for everything related to memory management. It handles memory allocations,
//! slab allocations, page table management and virtual memory allocations.

use applevisor as av;
use applevisor::Mappable;
use bitfield::bitfield;

use std::cell::RefCell;
use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::hyperpom::error::*;
use crate::hyperpom::exceptions::*;
use crate::hyperpom::utils::*;

// -----------------------------------------------------------------------------------------------
// Macros
// -----------------------------------------------------------------------------------------------

/// Rounds up an address to the next multiple of [`applevisor::PAGE_SIZE`].
#[cfg(test)]
macro_rules! round_phys_page {
    ( $addr: expr ) => {
        (($addr as u64) + (av::PAGE_SIZE as u64 - 1)) & !(av::PAGE_SIZE as u64 - 1)
    };
}

/// Truncates an address to a multiple of [`applevisor::PAGE_SIZE`].
#[cfg(test)]
macro_rules! align_phys_page {
    ( $addr: expr ) => {
        $addr & !(av::PAGE_SIZE as u64 - 1)
    };
}

/// Rounds up an address to the next multiple of [`VIRT_PAGE_SIZE`].
#[cfg(test)]
macro_rules! round_virt_page {
    ( $addr: expr ) => {
        (($addr as u64) + (VIRT_PAGE_SIZE as u64 - 1)) & !(VIRT_PAGE_SIZE as u64 - 1)
    };
}

/// Truncates an address to a multiple of [`VIRT_PAGE_SIZE`].
macro_rules! align_virt_page {
    ( $addr: expr ) => {
        $addr & !(VIRT_PAGE_SIZE as u64 - 1)
    };
}

// -----------------------------------------------------------------------------------------------
// Guest Physical Memory Allocator - Physical Memory
// -----------------------------------------------------------------------------------------------

/// Represents a guest physical memory range backed by a [`applevisor::Mapping`].
///
/// It can only be created when guest physical memory is allocated through a [`PhysMemAllocator`]
/// instance. When a mapping is created, it is not directly mapped and an explicit call to
/// `PhysMem::map` needs to be made. However, in most cases this will be transparent for the user
/// since it's handled directly by [`PhysMemAllocator`].
///
/// # Example
///
/// ```ignore
/// use applevisor as av;
/// use applevisor::Mappable;
/// use hyperpom::memory::PhysMem;
///
/// // First we create an hypervisor virtual machine instance to allow memory management in the
/// // guest (there's only one per process).
/// let vm = applevisor::VirtualMachine::new().unwrap();
///
/// // We allocate a physical memory page of size 0x10000 (the page size on Apple Silicon systems).
/// let mut physmem = PhysMem::new(0x10000).unwrap();
///
/// // We can map our page at an arbitrary address.
/// println!("host_addr = {:#x}", physmem.get_host_addr() as u64);
/// physmem.map(0x100000, av::MemPerms::RWX).unwrap();
///
/// // We can change the protections that will be used by the hypervisor to allow or
/// // prevent access to a memory range from the guest.
/// physmem.protect(av::MemPerms::R).unwrap();
///
/// // Values can be written to it...
/// physmem.write(0x12340000, &[0, 1, 2, 3]).unwrap();
///
/// // ... and read from it.
/// let mut data = [0; 4];
/// physmem.read(0x12340000, &mut data).unwrap();
/// assert_eq!(data, [0, 1, 2, 3]);
/// ```ignore
#[derive(Clone, Debug, PartialEq)]
pub struct PhysMem {
    /// A reference to the allocator that allocated the object. Only used when we drop the object.
    allocator: Option<PhysMemAllocator>,
    /// The underlying [`applevisor::Mapping`].
    mem: av::Mapping,
    /// Determines if the mapping has been freed or not. Without this, there is a weird interaction
    /// where two references to a `PhysMem` would call [`PhysMemAllocator::_free_inner`] at the
    /// same time and panic the program.
    is_free: bool,
}

impl PhysMem {
    /// Creates a new physical memory range of size `size`.
    pub fn new(size: usize) -> Result<Self> {
        Ok(Self {
            allocator: None,
            mem: av::Mapping::new(size)?,
            is_free: false,
        })
    }

    /// Creates a new physical memory range of size `size` attached to a [`PhysMemAllocator`].
    /// Unless the design of your program requires it, you should not instanciate this object
    /// directly and let [`PhysMemAllocator`] handle it.
    pub fn with_pma(allocator: PhysMemAllocator, size: usize) -> Result<Self> {
        Ok(Self {
            allocator: Some(allocator),
            mem: av::Mapping::new(size)?,
            is_free: false,
        })
    }

    /// Maps a physical memory range at address `guest_addr` and with permissions `perms`.
    #[inline]
    pub fn map(&mut self, guest_addr: u64, perms: av::MemPerms) -> av::Result<()> {
        self.mem.map(guest_addr, perms)
    }

    /// Unmaps a physical memory range.
    #[inline]
    pub fn unmap(&mut self) -> av::Result<()> {
        self.mem.unmap()
    }

    /// Changes the permissions of a physical memory range used by a guest VM (i.e. reading and
    /// writing from the host won't be affected by these permissions).
    #[inline]
    pub fn protect(&mut self, perms: av::MemPerms) -> av::Result<()> {
        self.mem.protect(perms)
    }

    /// Reads bytes at address `guest_addr`. The size of `data` determines the number of bytes
    /// read.
    #[inline]
    pub fn read(&self, guest_addr: u64, data: &mut [u8]) -> av::Result<usize> {
        self.mem.read(guest_addr, data)
    }

    /// Writes the content of `data` into the guest at address `guest_addr`.
    #[inline]
    pub fn write(&mut self, guest_addr: u64, data: &[u8]) -> av::Result<usize> {
        self.mem.write(guest_addr, data)
    }

    /// Returns the pointer to the host allocation corresponding to this physical memory range.
    #[inline]
    pub fn get_host_addr(&self) -> *const u8 {
        self.mem.get_host_addr()
    }

    /// Returns the guest address corresponding to this physical memory range.
    #[inline]
    pub fn get_guest_addr(&self) -> Option<u64> {
        self.mem.get_guest_addr()
    }

    /// Returns the size of this physical memory range.
    #[inline]
    pub fn get_size(&self) -> usize {
        self.mem.get_size()
    }
}

impl std::ops::Drop for PhysMem {
    fn drop(&mut self) {
        if !self.is_free {
            PhysMemAllocator::_free_inner(self).expect("could not free physmem during drop");
        }
    }
}

// -----------------------------------------------------------------------------------------------
// Guest Physical Memory Allocator - Buddy Allocator
// -----------------------------------------------------------------------------------------------

/// Inner structure for [`PhysMemAllocator`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct PhysMemAllocatorInner {
    /// The address space size.
    mem_size: usize,
    /// Allocation pools. There are `max_order - min_order` pools, each containing free chunks
    /// addresses grouped by their corresponding order.
    pools: Vec<Vec<u64>>,
    /// HashMap keeping track of allocations and their size.
    allocs: HashMap<u64, usize>,
}

impl PhysMemAllocatorInner {
    /// Returns the order of an allocation using its size.
    fn get_order(&self, size: usize) -> Result<usize> {
        if size < av::PAGE_SIZE || size > self.mem_size {
            Err(MemoryError::InvalidSize(size))?
        } else {
            Ok(log2(size) - log2(av::PAGE_SIZE))
        }
    }

    /// Returns the address of a chunk's buddy.
    fn get_buddy(&self, addr: u64, size: usize) -> Option<u64> {
        if size >= self.mem_size {
            return None;
        }
        if addr % (size as u64 * 2) == 0 {
            Some(addr + size as u64)
        } else {
            Some(addr - size as u64)
        }
    }
}

/// Physical memory allocator based on the Buddy System algorithm.
///
/// # Role of the Guest Physical Memory Allocator in the Fuzzer
///
/// The Apple hypervisor provides methods to its guest VM to manage a physical address space.
/// By mapping memory in the hypervisor we effectively create physical memory ranges that can be
/// accessed by the different guests. Just like a regular operating system, a single contiguous
/// range of physical pages can be used to create multiple isolated virtual address spaces, one
/// for each guest (or fuzzing [`Executor`](crate::core::Executor) in our case).
///
/// But in order to adapt to the specific needs of each guest and allocate physical pages
/// efficiently we need a way to manage these physical memory ranges. This is where this allocator
/// comes into play. Its goal is to carve out chunks of the physical address space and then merge
/// them back once they are no longer needed. In our case, the algorithm chosen to achieve this
/// is the Buddy System.
///
/// # Algorithm Overview
///
/// The allocator starts out with a single chunk of size `mem_size`, which is the maximum amount of
/// memory that can be allocated. `mem_size` needs to be expressed as a power of two and has to be
/// larger than `0x10000`, the page size on Apple Silicon systems.
///
/// We will take the example of a chunk of size 256KB.
///
/// ```text
///             256KB
/// ```ignore
///
/// The buddy allocator then divides this chunk, and the subsequent ones, into two until it fines
/// the smallest chunk large enough to contain the requested allocation. For example, if we want
/// an allocation of size 50KB. We first divide 256KB by two and get two chunks of size 128KB. Then
/// we divide one of these 128KB chunks by two, to get two 64KB chunks. Repeating this process
/// would yield 32KB which are smaller than 50KB, so we return a 64KB chunk.
///
/// ```text
///             256KB
///           /       \
///       128KB       128KB
///      /    \
///    64KB  64KB
///    ^^^^
///     |
///     +--> allocated chunk returned
/// ```ignore
///
/// The buddy allocator takes its name from the fact that all chunks (expect for the initial one)
/// have a buddy, the other half of the chunk they were split from.
///
/// ```text
///             256KB
///           /       \
///       128KB       128KB
///         |           |
///         +-----------+----> buddies
///      /    \
///    64KB  64KB
///     |      |
///     +------+----> buddies
/// ```ignore
///
/// This is useful when a chunk is freed and needs to be merged back by the buddy allocator. The
/// allocator checks if the buddy of a chunk is allocated, and if it's not the case, it merges them
/// back together to create a bigger chunk.
///
/// ```text
///             256KB                     256KB
///           /       \                 /       \                   256KB
///       128KB       128KB   -->   128KB       128KB   -->       /       \         -->  256KB
///           \                    /    \                     128KB       128KB
///          64KB                64KB  64KB
///                              ^^^^
///                               |
///                               +--> freed chunk to merge
/// ```
///
/// This algorithm offers good performances when allocating and deallocating memory. It is simple
/// and there are tons of real-world implementations, such as in the Linux kernel, that can be
/// used as examples to refine the implementation and/or enhance performances.
///
/// It falls short when considering external fragmentation (e.g. allocating 32KB when 17KB are
/// requested). Hopefully, we can assume most of the fuzzed programs won't allocate a majority of
/// memory chunks that would maximize fragmentation.
///
/// # Example
///
/// ```ignore
/// use applevisor as av;
/// use hyperpom::memory::PhysMemAllocator;
///
/// // First we create an hypervisor virtual machine instance to allow memory management in the
/// // guest (there's only one per process).
/// let vm = applevisor::VirtualMachine::new().unwrap();
///
/// // We create a new physical memory allocator over an address range of size 0x1000_0000.
/// let mut pma = PhysMemAllocator::new(0x1000_0000).unwrap();
///
/// // We allocate a physical memory range spanning over 3 physical pages.
/// let physmem = pma.alloc(0x30000, av::MemPerms::RWX).unwrap();
///
/// // We can either free it explicitly or simply wait for it to drop.
/// pma.free(physmem).unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct PhysMemAllocator {
    inner: Arc<Mutex<PhysMemAllocatorInner>>,
}

impl PhysMemAllocator {
    /// Instanciates a buddy allocator over an address space of size `mem_size`. The size needs to
    /// be expressed as a power of two and has to be larger than [`applevisor::PAGE_SIZE`].
    pub fn new(mem_size: usize) -> Result<Self> {
        // Makes sure `mem_size` is large enough and a power of two.
        if mem_size < av::PAGE_SIZE || mem_size & (mem_size - 1) != 0 {
            return Err(MemoryError::InvalidSize(mem_size))?;
        }
        // Creates an uninitialized buddy allocator.
        let mut ba = PhysMemAllocatorInner {
            mem_size,
            pools: vec![],
            allocs: HashMap::new(),
        };
        // Allocates the pools of free chunks.
        let nb_pools = 1 + ba.get_order(mem_size)?;
        ba.pools = vec![vec![]; nb_pools];
        // Puts an initial chunk of size `mem_size` at address 0 into the highest-order pool.
        ba.pools.last_mut().unwrap().push(0);
        // Returns the initialized allocator wrapped in a lock.
        Ok(Self {
            inner: Arc::new(Mutex::new(ba)),
        })
    }

    /// Uses the buddy allocator to create a [`PhysMem`] object of size `size` mapped with the
    /// permissions `perms`.
    pub fn alloc(&mut self, size: usize, perms: av::MemPerms) -> Result<PhysMem> {
        // Gets the lock on the allocator
        let mut inner = self.inner.lock().unwrap();
        // The allocation size needs to be page aligned.
        if size & (av::PAGE_SIZE - 1) != 0 {
            return Err(MemoryError::UnalignedSize(size))?;
        }
        // Computes the order of the current allocation to know in which pool it should be.
        let alloc_order = inner.get_order(size)?;
        // Starting from the pool of index `order`, it looks for the first pool of higher order
        // that contains at least one free chunk and returns its index.
        // Returns an OOM error if it can't find one.
        let mut free_order = alloc_order
            + inner
                .pools
                .iter()
                .skip(alloc_order)
                .position(|x| !x.is_empty())
                .ok_or(MemoryError::OutOfMemory)?;
        // Gets the free chunk we will make an allocation from.
        let alloc_addr = inner.pools[free_order].pop().unwrap();
        // Computes the chunk's size.
        let mut alloc_size = 1 << (free_order + log2(av::PAGE_SIZE) - 1);
        // Iterates over the pool of free chunks in reverse.
        while free_order > alloc_order {
            free_order -= 1;
            // Computes the address of the current chunk's buddy.
            let buddy_addr = alloc_addr + alloc_size;
            // Pushes it into the corresponding pool.
            inner.pools[free_order].push(buddy_addr);
            // Halves the size and reiterates the process.
            alloc_size >>= 1;
        }
        // Adds the chunk and its size to the HashMap in order to track current allocations.
        inner.allocs.insert(alloc_addr, size);
        // Creates a guest mapping that corresponds to the allocation and maps it.
        let mut mapping = PhysMem::with_pma(self.clone(), size)?;
        mapping.map(alloc_addr, perms)?;

        Ok(mapping)
    }

    /// Explicit free of a [`PhysMem`] object allocated through the buddy allocator
    /// (`PhysMem`s can also be freed by letting them go out of scope/dropping them).
    pub fn free(&self, mut mem: PhysMem) -> Result<()> {
        Self::_free_inner(&mut mem)
    }

    /// The inner function that unmaps a [`PhysMem`] object from the guest and merges back the
    /// corresponding physical memory chunk with the other freed chunks.
    fn _free_inner(mem: &mut PhysMem) -> Result<()> {
        // Return early if `mem` is not associated to a PhysMemAllocator.
        if mem.allocator.is_none() {
            return Ok(());
        }
        // It's safe to unwrap the allocator since we've checked above that it's not None.
        let allocator = mem.allocator.as_ref().unwrap();
        // Gets the lock on the allocator.
        let mut inner = allocator.inner.lock().unwrap();
        let mut chunk_addr = mem.get_guest_addr().unwrap();
        // Whether the mapping actually exists or not, we set `is_free` to true so that
        // `free_inner` is not called again - which would panic the program - when `mem` is
        // dropped.
        mem.is_free = true;
        // Unmaps the guest mapping.
        mem.mem.unmap()?;
        // Removes our chunk from the HashMap tracking allocations since we want to free it.
        if let Some(mut chunk_size) = inner.allocs.remove(&chunk_addr) {
            let mut order = inner.get_order(chunk_size)?;
            // This loop finds the chunk's buddy, merge them if it's free and reiterates the
            // process with the resulting merged chunk.
            while let Some(buddy_addr) = inner.get_buddy(chunk_addr, chunk_size) {
                // Checks if the buddy is not allocated.
                if inner.allocs.get(&buddy_addr).is_none() {
                    // Removes it from the free list.
                    if let Some(pos) = inner.pools[order].iter().position(|x| *x == buddy_addr) {
                        inner.pools[order].remove(pos);
                    } else {
                        break;
                    }
                    // Merges the chunk and its buddy into a new one of size `chunk_size*2` and at
                    // address `min(chunk_addr, buddy_addr)`.
                    chunk_size *= 2;
                    chunk_addr = std::cmp::min(chunk_addr, buddy_addr);
                    order += 1;
                } else {
                    break;
                }
            }
            inner.pools[order].push(chunk_addr);
        } else {
            return Err(MemoryError::UnallocatedMemoryAccess(chunk_addr))?;
        }
        Ok(())
    }
}

impl fmt::Display for PhysMemAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        writeln!(f)?;
        writeln!(f, "+-------+-------+")?;
        writeln!(f, "| Order | Count |")?;
        writeln!(f, "+-------+-------+")?;
        for (i, pool) in inner.pools.iter().enumerate() {
            writeln!(f, "| {:5} | {:5} |", i, pool.len())?;
        }
        writeln!(f, "+-------+-------+")
    }
}

impl PartialEq for PhysMemAllocator {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

// -----------------------------------------------------------------------------------------------
// Guest Physical Memory Allocator - Slab Allocator
// -----------------------------------------------------------------------------------------------

/// Slab allocator for allocations smaller than [`applevisor::PAGE_SIZE`].
///
/// # Role of the Slab Allocator in the Fuzzer.
///
/// On Apple Silicon, the size of a physical memory page is 64KB (or 0x10000 bytes). However,
/// a majority of targets still use a 4KB (or 0x1000 bytes) granule for physical memory pages.
/// Directly using a physical page from the hypervisor would be way too inefficient as it would
/// create a lot of unused space. A slab allocator solves this problem by servicing multiple 4KB
/// pages from a single 64KB hypervisor page, which can then be used the guest VMs transparently.
///
/// Note: this fuzzer only supports 4KB pages for the moment (but support for other granules
/// could be added relatively easily).
///
/// # Algorithm Overview
///
/// A slab is a contiguous space in memory from which are allocated objects of a specific size
/// (usually also the same type of objects). As hinted above, in our case the slabs are the 64KB
/// pages and the objects the 4KB ones, but the implementation can handle other sizes as well.
///
/// In this implementation slabs are represented by the structure [`Slab`] and objects by the
/// structure [`SlabObject`].
///
/// ```text
///                                       64KB
/// <------------------------------------------------------------------------------->
/// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
/// |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
/// |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
/// |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
/// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
///           <---->
///            4KB
/// ```
///
/// A slab starts as empty, it's just one hypervisor physical page with no 4KB page allocated from
/// it yet.
///
/// When an allocation is requested, the allocator checks if there are partial slabs available.
/// These are slabs that still have some space left to service 4KB pages.
///
///  * If a partial slab is available, a pointer to the 4KB chunk is returned.
///    * If there is no space left after the allocation, the corresponding slab is marked as full.
///  * Otherwise, if no partial slab is available, a new one is created.
///
/// When a page is freed, the allocator checks from which slab it initially came from.
///
/// * If the initial slab is full, the corresponding 4KB chunk is marked as free and the slab is
///   put in the partial slabs list.
/// * If the 4KB page was the last chunk used in the initial slab, then the 64KB as a whole is
///   reclaimed and unmapped from the hypervisor.
///
/// # Example
///
/// ```ignore
/// use applevisor as av;
/// use hyperpom::memory::{PhysMemAllocator, SlabAllocator};
///
/// // First we create an hypervisor virtual machine instance to allow memory management in the
/// // guest (there's only one per process).
/// let vm = applevisor::VirtualMachine::new().unwrap();
///
/// // We create a new physical memory allocator over an address range of size 0x1000_0000.
/// let mut pma = PhysMemAllocator::new(0x1000_0000).unwrap();
///
/// // We create a new slab allocator for objects of size 0x1000.
/// let mut slab_allocator = SlabAllocator::new(pma, 0x1000).unwrap();
///
/// // And we can now create and free slab objects of size 0x1000.
/// let object = slab_allocator.alloc().unwrap();
/// slab_allocator.free(object).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct SlabAllocator {
    /// Physical memory allocator from which slabs are allocated.
    pma: PhysMemAllocator,
    /// Size of the objects stored in this slab.
    object_size: usize,
    /// Numbers of objects per slab.
    objects_per_slab: usize,
    /// List of full slabs.
    full: VecDeque<SlabReference>,
    /// List of partial slabs.
    partial: VecDeque<SlabReference>,
}

impl SlabAllocator {
    /// Creates a new slab allocator containing objects of size `object_size`.
    pub fn new(pma: PhysMemAllocator, object_size: usize) -> Result<Self> {
        // Checks if the object would fit in a page.
        if object_size > av::PAGE_SIZE {
            return Err(MemoryError::InvalidSize(object_size))?;
        }
        Ok(SlabAllocator {
            pma,
            object_size,
            objects_per_slab: av::PAGE_SIZE / object_size,
            full: VecDeque::new(),
            partial: VecDeque::new(),
        })
    }

    /// Allocates a [`SlabObject`].
    pub fn alloc(&mut self) -> Result<SlabObject> {
        // Creates a new slab if there are no partial slabs available.
        if self.partial.is_empty() {
            // TODO: maybe pass perms as func args.
            let mem = self.pma.alloc(av::PAGE_SIZE, av::MemPerms::RWX)?;
            let slab = SlabReference::new(mem, self.object_size, self.objects_per_slab);
            self.partial.push_back(slab);
        }
        // At this point, we know there's at least one partial slab, so it's safe to just iterate
        // and take a reference to the first one encountered.
        let slab = self
            .partial
            .iter_mut()
            .next()
            .ok_or(MemoryError::CorruptedSlab)?;
        // We allocate an objects from the partial slab we found.
        let object = slab.alloc().ok_or(MemoryError::CorruptedSlab)?;
        // If after the allocation, the slab is full, then it's put in the list referencing the
        // other full slabs.
        if slab.is_full() {
            let slab = self.partial.pop_front().unwrap();
            self.full.push_back(slab);
        }
        Ok(object)
    }

    /// Frees a [`SlabObject`].
    pub fn free(&mut self, mut object: SlabObject) -> Result<()> {
        // Retrieves the slab this object was allocated from.
        let parent = object.parent.take();
        let mut slab = parent.ok_or(MemoryError::CorruptedSlab)?;
        // Checks if the slab is full before freeing the object. This tells us if we need to
        // move out the corresponding slab from the full slabs list and put it into the partial
        // slabs one.
        let is_full_slab = slab.is_full();
        // The object is freed.
        slab.free(object);
        // If the slab was full before we freed, then transfer it to the partial slabs list.
        if is_full_slab {
            let full_slab_pos = self
                .full
                .iter()
                .position(|x| *x == slab)
                .ok_or(MemoryError::CorruptedSlab)?;
            let full_slab = self.full.remove(full_slab_pos).unwrap();
            self.partial.push_front(full_slab);
        }
        // If the slab is now empty, remove it from the partial list (the underlying physical page
        // is unmapped once drop is called).
        if slab.is_empty() {
            let empty_slab_pos = self
                .partial
                .iter()
                .position(|x| *x == slab)
                .ok_or(MemoryError::CorruptedSlab)?;
            let _ = self.partial.remove(empty_slab_pos).unwrap();
        }
        Ok(())
    }
}

/// Represents a slab from which object of a given size can be allocated.
///
/// See [`SlabAllocator`] for more information on slabs.
#[derive(Clone, Debug, PartialEq)]
pub struct Slab {
    /// The underlying hypervisor physical memory page.
    mem: PhysMem,
    /// Number of objects stored in this slab.
    objects_per_slab: usize,
    /// The list of free [`SlabObject`]s that can be allocated from this slab.
    freelist: Vec<SlabObject>,
}

/// A reference to a slab.
///
/// When an object is allocated, it gets a `SlabReference` to the slab it belongs to. This
/// reference is deleted when the object is freed. Thus, when all objects from a slab are freed,
/// it's automatically deleted and unmapped from the hypervisor.
///
/// See [`SlabAllocator`] for more information on slabs.
#[derive(Clone, Debug, PartialEq)]
pub struct SlabReference(Rc<RefCell<Slab>>);

impl SlabReference {
    /// Creates a new slab backed by the `mem` allocation.
    pub fn new(mem: PhysMem, object_size: usize, objects_per_slab: usize) -> Self {
        let mut freelist = vec![];
        // Initializes the freelist by dividing the physical memory page into smaller chunks and
        // creating slab objects with each a pointer to their respective chunk.
        for i in (0..objects_per_slab).rev() {
            // SAFETY: `mem` is mapped and we made sure that it is large enough to contain
            //         `object_size * objects_per_slab` bytes. And since all objects have a
            //         reference to the slab, it won't get freed unless all slab objects are also
            //         freed.
            let object = SlabObject {
                host_addr: unsafe { mem.get_host_addr().add(i * object_size) as *const u8 },
                guest_addr: mem.get_guest_addr().unwrap() + (i * object_size) as u64,
                object_size,
                parent: None,
            };
            freelist.push(object);
        }
        Self(Rc::new(RefCell::new(Slab {
            mem,
            objects_per_slab,
            freelist,
        })))
    }

    /// Returns whether our slab is full or not.
    pub fn is_full(&self) -> bool {
        self.0.borrow().freelist.is_empty()
    }

    /// Returns whether our slab is empty or not.
    pub fn is_empty(&self) -> bool {
        self.0.borrow().freelist.len() == self.0.borrow().objects_per_slab
    }

    /// Allocates a new object from the current slab. Returns `None` if the slab is full.
    pub fn alloc(&mut self) -> Option<SlabObject> {
        if let Some(mut object) = self.0.borrow_mut().freelist.pop() {
            object.parent = Some(self.clone());
            // Objects are zeroed-out when allocated.
            // SAFETY: we can safely write `object_size` bytes into the object, since we
            //         know it's part of a an allocation that exists at least as long as the
            //         current object and with a fixed sized.
            unsafe { std::ptr::write_bytes(object.host_addr as *mut u8, 0, object.object_size) };
            Some(object)
        } else {
            None
        }
    }

    /// Frees an object by removing the reference to the slab it belongs to and adding it back to
    /// the freelist.
    pub fn free(&mut self, mut object: SlabObject) {
        let _ = object.parent.take();
        self.0.borrow_mut().freelist.push(object);
    }
}

/// A slab object.
///
/// See [`SlabAllocator`] for more information on slabs.
#[derive(Clone, Debug, PartialEq)]
pub struct SlabObject {
    /// The pointer in the host address space referencing the object's data.
    host_addr: *const u8,
    /// The pointer in the guest address space referencing the object's data.
    guest_addr: u64,
    /// The object size.
    object_size: usize,
    /// The reference to the slab it belongs to when the object is allocated.
    parent: Option<SlabReference>,
}

impl fmt::Display for SlabObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Slab object @Host {:#x} - @Guest {:#x}",
            self.host_addr as u64, self.guest_addr
        )?;
        // SAFETY: We made sure when initializing the slab, that all objects can be of size
        //         `object_size` and the underlying physical memory page is still there because
        //         we currently have at least one object that points to it.
        let data: &[u8] = unsafe { std::slice::from_raw_parts(self.host_addr, self.object_size) };
        let mut rhx = rhexdump::Rhexdump::default();
        rhx.display_duplicate_lines(false);
        write!(f, "{}", rhx.hexdump_offset(data, self.host_addr as u32))
    }
}

// -----------------------------------------------------------------------------------------------
// Guest Page Tables
// -----------------------------------------------------------------------------------------------

/// Page size in virtual address spaces.
pub const VIRT_PAGE_SIZE: usize = 0x1000;

/// Number of entries in a page table.
pub const PAGE_TABLE_NB_ENTRIES: usize = 0x200;

/// Page table size.
pub const PAGE_TABLE_SIZE: usize = PAGE_TABLE_NB_ENTRIES * std::mem::size_of::<u64>();

bitfield! {
    /// Level 0, 1 and 2 page table descriptor.
    ///
    ///  - **NS Table**: specifies the Security state for subsequent levels of lookup
    ///  - **AP Table**: access permissions limit for subsequent levels of lookup
    ///  - **UXN Table**: XN limit for subsequent levels of lookup
    ///  - **PXN Table**: PXN limit for subsequent levels of lookup
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hyperpom::memory::TableDescriptor;
    ///
    /// // Creates a descriptor for a table at address `0x1234000`.
    /// let descriptor = TableDescriptor::new(0x1234000);
    /// ```ignore
    #[derive(Copy, Clone, Eq, Hash, PartialEq)]
    pub struct TableDescriptor(u64);
    impl Debug;
    get_valid, set_valid: 0;
    get_type, set_type: 1;
    get_addr, set_addr: 47, 12;
    get_pxntable, set_pxntable: 59;
    get_uxntable, set_uxntable: 60;
    get_aptable, set_aptable: 62, 61;
    get_nstable, set_nstable: 63;
}

impl TableDescriptor {
    /// Create a new table descriptor for levels 0, 1 and 2.
    ///
    /// Apart from the address field, all descriptors store the following permissions:
    ///
    ///  - **NS Table**: `true`, everything should be non-secure;
    ///  - **AP Table**: `0b00`, no limitations regarding access permissions;
    ///  - **UXN Table**: `false`, no limitations regarding user execution permissions;
    ///  - **PXN Table**: `false`, no limitations regarding privileged execution permissions.
    pub fn new(addr: u64) -> Self {
        let mut descriptor = TableDescriptor(0);
        descriptor.set_valid(true);
        descriptor.set_type(true);
        // Sets the next descriptor's address
        descriptor.set_addr(addr >> 12);
        // Disables PXN table bit
        descriptor.set_pxntable(false);
        // Disables UXN table bit
        descriptor.set_uxntable(false);
        // No effect on access permissions in subsequent levels of lookup
        descriptor.set_aptable(0b00);
        // Disables NS table bit
        descriptor.set_nstable(true);
        descriptor
    }
}

bitfield! {
    /// Level 3 page table descriptor.
    ///
    /// - **UXN:** Unprivileged execute-never field
    /// - **PXN:** Privilege execute-never field
    /// - **Contiguous:** A hint bit indicating that the translation table entry is one of a
    ///     contiguous set of entries
    /// - **DBM:** Dirty Bit Modifier
    /// - **nG:** Not Global Bit
    /// - **AF:** Access flag
    /// - **SH:** Shareability field
    /// - **AP:** Data Access Permissions bits
    /// - **NS:** Non-Secure bit
    /// - **AttrIndx:** Stage 1 memory attributes index field
    ///
    /// # Example
    ///
    /// ```ignore
    /// use applevisor as av;
    /// use hyperpom::memory::PageDescriptor;
    ///
    /// // Creates a descriptor for a physical page at address `0x1234000` with RWX permissions.
    /// let descriptor = PageDescriptor::new(0x1234000, av::MemPerms::RWX, false);
    ///
    /// // It's also possible to create privileged mappings restricted to EL1. This is necessary
    /// // to create EL1 mappings that do not trigger PAN.
    /// let descriptor = PageDescriptor::new(0x1235000, av::MemPerms::RWX, true);
    /// ```
    #[derive(Copy, Clone, Eq, Hash, PartialEq)]
    pub struct PageDescriptor(u64);
    impl Debug;
    get_valid, set_valid: 0;
    get_type, set_type: 1;
    get_attrindx, set_attrindx: 4, 2;
    get_ns, set_ns: 5;
    get_ap, set_ap: 7, 6;
    get_sh, set_sh: 9, 8;
    get_af, set_af: 10;
    get_ng, set_ng: 11;
    get_addr, set_addr: 47, 12;
    get_dbm, set_dbm: 51;
    get_contiguous, set_contiguous: 52;
    get_pxn, set_pxn: 53;
    get_uxn, set_uxn: 54;
}

impl PageDescriptor {
    /// Create a new table descriptor for levels 0, 1 and 2.
    ///
    /// Other than the address, the AP flags and the UXN flag, all descriptors store the following
    /// permissions:
    ///
    ///  - **PXN:** `true`, EL1 can always execute code mapped at EL0;
    ///  - **nG:** `false`, ASIDs are not currently used;
    ///  - **AF:** `true`, otherwise nothing works for some reason;
    ///  - **SH:** `0b11`, we want the page to be *Inner Shareable*.
    ///  - **NS:** `true`, all pages are non-secure;
    ///  - **AttrIndx:** `0b000`, we use the same memory attributes for all pages as configured
    ///         by the register `MAIR_EL1` set in [`VirtMemAllocator::init`].
    pub fn new(addr: u64, perms: av::MemPerms, privileged: bool) -> Self {
        let mut descriptor = PageDescriptor(0xffff_ffff);
        descriptor.set_valid(true);
        descriptor.set_type(true);
        descriptor.set_attrindx(0b000);
        descriptor.set_ns(true);
        descriptor.set_ap(match privileged {
            true => 0b00,
            false => match perms {
                av::MemPerms::None | av::MemPerms::W | av::MemPerms::X | av::MemPerms::WX => 0b00,
                av::MemPerms::R | av::MemPerms::RX => 0b11,
                av::MemPerms::RW | av::MemPerms::RWX => 0b01,
            },
        });
        descriptor.set_sh(0b11);
        descriptor.set_af(true);
        descriptor.set_ng(false);
        // Sets the page descriptor's address
        descriptor.set_addr(addr >> 12);
        descriptor.set_pxn(false);
        descriptor.set_uxn(
            privileged
                | match perms {
                    av::MemPerms::None | av::MemPerms::W | av::MemPerms::R | av::MemPerms::RW => {
                        true
                    }
                    av::MemPerms::X | av::MemPerms::WX | av::MemPerms::RX | av::MemPerms::RWX => {
                        false
                    }
                },
        );
        descriptor
    }

}

/// Represents a *Page Global Directory*.
///
/// See [`PageTableManager`] for more information.
#[derive(Clone, Debug)]
pub struct PageGlobalDirectory {
    /// The slab object pointing to memory that contains the raw descriptors.
    entries: SlabObject,
    /// A hashmap mapping the descriptor's index to the corresponding PUD object.
    /// It's a more convenient way to handle page table components rather than manually parsing and
    /// changing descriptors in memory.
    objects: HashMap<usize, PageUpperDirectory>,
}

impl PageGlobalDirectory {
    /// Creates a new PGD.
    pub fn new(entries: SlabObject) -> Self {
        Self {
            entries,
            objects: HashMap::new(),
        }
    }
}

/// Represents a *Page Upper Directory*.
///
/// See [`PageTableManager`] for more information.
#[derive(Clone, Debug)]
pub struct PageUpperDirectory {
    /// Descriptor storing the information and permissions of the current PUD.
    descriptor: TableDescriptor,
    /// The slab object pointing to memory that contains the raw descriptors.
    entries: SlabObject,
    /// A hashmap mapping the descriptor's index to the corresponding PMD object.
    /// It's a more convenient way to handle page table components rather than manually parsing and
    /// changing descriptors in memory.
    objects: HashMap<usize, PageMiddleDirectory>,
}

impl PageUpperDirectory {
    /// Creates a new PUD.
    pub fn new(entries: SlabObject) -> Self {
        Self {
            descriptor: TableDescriptor::new(entries.guest_addr as u64),
            entries,
            objects: HashMap::new(),
        }
    }
}

/// Represents a *Page Middle Directory*.
///
/// See [`PageTableManager`] for more information.
#[derive(Clone, Debug)]
pub struct PageMiddleDirectory {
    /// Descriptor storing the information and permissions of the current PMD.
    descriptor: TableDescriptor,
    /// The slab object pointing to memory that contains the raw descriptors.
    entries: SlabObject,
    /// A hashmap mapping the descriptor's index to the corresponding PT object.
    /// It's a more convenient way to handle page table components rather than manually parsing and
    /// changing descriptors in memory.
    objects: HashMap<usize, PageTable>,
}

impl PageMiddleDirectory {
    /// Creates a new PMD.
    pub fn new(entries: SlabObject) -> Self {
        Self {
            descriptor: TableDescriptor::new(entries.guest_addr as u64),
            entries,
            objects: HashMap::new(),
        }
    }
}

/// Represents a *Page Table*.
///
/// See [`PageTableManager`] for more information.
#[derive(Clone, Debug)]
pub struct PageTable {
    /// Descriptor storing the information and permissions of the current PT.
    descriptor: TableDescriptor,
    /// The slab object pointing to memory that contains the raw descriptors.
    entries: SlabObject,
    /// How many of its descriptors are valid, to free it once none are.
    used: usize,
}

impl PageTable {
    /// Creates a new PT.
    pub fn new(entries: SlabObject) -> Self {
        Self {
            descriptor: TableDescriptor::new(entries.guest_addr as u64),
            entries,
            used: 0,
        }
    }

    fn entry(&self, idx: usize) -> u64 {
        // SAFETY: the entries are mapped as long as the table exists, and `idx` is below
        //         PAGE_TABLE_NB_ENTRIES.
        unsafe { std::ptr::read(self.entries.host_addr.add(idx * 8) as *const u64) }
    }

    /// Returns whether it removed or replaced a valid descriptor, which the TLBs may hold.
    fn set_entry(&mut self, idx: usize, desc: u64) -> bool {
        let old = self.entry(idx);
        match (old != 0, desc != 0) {
            (false, true) => self.used += 1,
            (true, false) => self.used -= 1,
            _ => {}
        }
        // SAFETY: as for `entry`.
        unsafe { std::ptr::write(self.entries.host_addr.add(idx * 8) as *mut u64, desc) };
        old != 0 && old != desc
    }
}

/// Implements the paging model that allows mapping virtual addresses to physical ones.
///
/// # Role of the Page Table Manager in the Fuzzer
///
/// Using unique virtual address spaces for each guests gives us a better control over memory
/// accessible to them and also prevents inadvertent accesses to each other's memory while fuzzing
/// (e.g. an OOB that goes undetected because the access was on a page allocated for another guest).
/// But to create this virtual address space, we must use translation tables that map virtual
/// addresses to physical ones.
///
/// # Page Tables Implementation
///
/// ## Addressable Virtual Memory
///
/// When we're fuzzing a userland application, even though we're only testing non-privileged code,
/// there are still some privileged operations that need to take place: cache maintenance,
/// exceptions handling, etc. Handling these operations requires to have dedicated code available
/// at fixed addresses in memory and we need to make sure that they don't collide with the
/// program's address ranges.
///
/// To solve this problem, based on the assumption that most userland binaries expect to be mapped
/// at lower addresses, this fuzzer splits a guest address space into two virtual address ranges.
///
///  * The lower address range for non-privileged mappings. It is translated using `TTBR0_EL1` and
///    spans from `0x0000_0000_0000_0000` to `0x0000_ffff_ffff_ffff` by setting `TCR_EL1.T0SZ`
///    to 16.
///  * The upper address range for privileged mappings. It is translated using `TTBR1_EL1` and
///    spans from `0xffff_0000_0000_0000` to `0xffff_ffff_ffff_ffff` by setting `TCR_EL1.T1SZ`
///    to 16.
///
/// ```text
///  0xffff_ffff_ffff_ffff  +---------------------+
///                         |                     |
///                         |      TTBR1_EL1      |
///                         |       REGION        |
///                         |                     |
///  0xffff_0000_0000_0000  +---------------------+  ----> TCR_EL1.T1SZ == 16
///                         |  /////////////////  |
///                         |  /////////////////  |
///                         |  /////////////////  |
///                         |                     |
///                         |  ACCESSES GENERATE  |
///                         |  TRANSLATION FAULT  |
///                         |                     |
///                         |  /////////////////  |
///                         |  /////////////////  |
///                         |  /////////////////  |
///  0x0000_ffff_ffff_ffff  +---------------------+  ----> TCR_EL1.T0SZ == 16
///                         |                     |
///                         |      TTBR0_EL1      |
///                         |       REGION        |
///                         |                     |
///  0x0000_0000_0000_0000  +---------------------+
///
/// ```ignore
///
/// **Note:** While it's possible to have privileged mappings in lower addresses and non-privileged
///           in higher ones, keep in mind that some addresses in the upper virtual address range
///           are reserved by the fuzzer. If you wish to map addresses in the upper VA, make sure
///           they don't overlap or alter existing mappings.
///
/// ## Paging Model
///
/// We'll use two separate page tables for each region: one referenced by `TTBR0_EL1` and the other
/// by `TTBR1_EL1`. But before we move on to the actual implementation, we need to determine the
/// number of page table levels necessary based on our requirements. In the rest of this section,
/// we'll explain the reasoning for the region covered by `TTBR0_EL1`, but the same applies to its
/// counterpart.
///
/// One of our requirements is to have regions with a total size of addressable memory of
/// `0x0001_0000_0000_0000` bytes, which means that a virtual address in these regions is 48-bit
/// long. The second requirement is that the granule size is 4KB.
///
/// With a 4KB granule size, the last 12 bits of the address are directly used as an offset into
/// the corresponding physical page and they don't need to be taken into account during the
/// translation process. But we still need to determine how to split the remaining 36 bits.
///
/// Since the granule size is 4KB, page tables are also 4KB long. And because the descriptors we
/// store in these tables are 8-byte long, this means that we can store at most 512 descriptors.
/// Therefore there are 9 address bits resolved in one level of lookup. If you need more convicing,
/// you can take the example of the last level of a page table lookup starting at address 0. The
/// 512 descriptors it contains spans from the page corresponding to address 0 to the one
/// corresponding to address 0x1ff000, with 0x1ff being 9-bit long.
///
/// All in all, if one level of lookup resolves 9 bits and we need to resolve 36 of them, it means
/// that our page table should have 4 levels.
///
/// ```text
/// Input Address -> 48 bits
///     +--> Level 0: bits [47:39]
///         +--> Level 1: bits [38:30]
///             +--> Level 2: bits [29:21]
///                 +--> Level 3: bits [20:12]
///                     +--> Page offset: bits [11:0]
/// ```ignore
///
/// To address these four levels in the fuzzer, we shamelessly stole Linux's naming convention:
///
/// * [`PageGlobalDirectory`] at level 0;
/// * [`PageUpperDirectory`] at level 1;
/// * [`PageMiddleDirectory`] at level 2;
/// * [`PageTable`] at level 3;
///
/// In each of these structures, there is a [`SlabObject`] that points to the physical memory
/// region that contains the descriptors used during memory translation as well as a hashmap
/// to get a convenient mapping between the descriptor's index and the object it corresponds to
/// (e.g. in a page upper directory, the hashmap stores a mapping with page middle directories).
/// We now need to figure out how to fill these objects to actually map a virtual address.
///
/// ## Mapping a Virtual Address
///
/// If we want to map, for example, a memory page at address 0xdead_beef_c000, we first extract the
/// indices into the page table levels from the input virtual address:
///
/// ```text
/// Input Address -> 0xdead_beef_cafe
///     +--> Level 0: bits [47:39] = (0xdead_beef_cafe >> 39) & 0x1ff = 0x1bd
///         +--> Level 1: bits [38:30] = (0xdead_beef_cafe >> 30) & 0x1ff = 0xb6
///             +--> Level 2: bits [29:21] = (0xdead_beef_cafe >> 21) & 0x1ff = 0x1f7
///                 +--> Level 3: bits [20:12] = (0xdead_beef_cafe >> 12) & 0x1ff = 0xfc
/// ```ignore
///
/// Then, we check if the entries exists in the corresponding levels, starting with the page
/// global directory:
///
///  * if an entry exists in [`PageGlobalDirectory`]'s hashmap for index `0x1bd`, we get the
///    the corresponding [`PageUpperDirectory`] entry and continue.
///  * otherwise, it the entry doesn't exist yet, we create a new `PageUpperDirectory` object, add
///    the PUD descriptor in the physical memory page of the `PageGlobalDirectory` at index `0x1bd`
///    and insert the PUD object into the PGD's hashmap.
///
/// We repeat this process for the [`PageUpperDirectory`] and [`PageMiddleDirectory`].
///
/// When we reach the [`PageTable`] level, there should be no entry at index `0xfc`, otherwise
/// we return a [`MemoryError::AlreadyMapped`] error. We can now create a [`Page`] object, add it
/// to the [`PageTable`]'s hashmap as well as its descriptor into the PT's memory page.
///
/// ```text
///       +-----------+
///       | TTBR0_EL1 |
///       +-----------+
///             |
///             |
///             v
/// +-----------------------+
/// | Page Global Directory |
/// +-----------------------+
///     |
///     +--> Index 0x000: [...]
///     •
///     •
///     •                 +----------------------+
///     +--> Index 0x1bd: | Page Upper Directory |
///     •                 +----------------------+
///                           |
///                           +--> Index 0x000: [...]
///                           •
///                           •
///                           •                 +-----------------------+
///                           +--> Index 0x0b6: | Page Middle Directory |
///                           •                 +-----------------------+
///                                                 |
///                                                 +--> Index 0x000: [...]
///                                                 •
///                                                 •
///                                                 •                 +------------+
///                                                 +--> Index 0x1f7: | Page Table |
///                                                 •                 +------------+
///                                                                       |
///                                                                       +--> Index 0x000: [...]
///                                                                       •
///                                                                       •
///                                                                       •
///                                                                       +--> Index 0x0fc: Page
///                                                                       •
/// ```ignore
///
/// The MMU can now use our page tables to resolve the physical page that corresponds to the
/// the virtual address `0xdead_beef_c000`.
///
/// At this stage, even if we need a bit more abstraction to create a real virtual memory allocator
/// that maps memory, performs read/writes operations, etc., most of the heavy lifting is done
/// by the `PageTableManager`.
///
/// You can refer to [`VirtMemAllocator`] for more information about the virtual memory allocator
/// used by the fuzzer.

#[derive(Clone, Debug)]
pub struct PageTableManager {
    pub(crate) slab: SlabAllocator,
    pub(crate) pgd: PageGlobalDirectory,
    /// What's mapped, by virtual start address: non-overlapping, and coalesced where adjacent
    /// ones agree.
    regions: BTreeMap<u64, Region>,
    /// The pages backing [`Backing::Slab`] regions, by virtual address.
    slab_pages: BTreeMap<u64, SlabObject>,
    one_to_one_last: u64,
    /// Guest physical ranges below `one_to_one_last` free for reuse, as start -> size.
    free_one_to_one: BTreeMap<u64, u64>,
    /// 1:1 ranges, keyed by guest physical start address. Lazy ones' stage-2 mappings are
    /// deferred until first access.
    one_to_one: BTreeMap<u64, OneToOne>,
    /// Guest physical addresses of 1:1 host pages currently write-protected in the VM (see
    /// [`Self::write_protect_1to1`]).
    write_protected: BTreeSet<u64>,
    /// Whether lazily mapped pages start out write-protected.
    write_protecting: bool,
    /// Whether descriptors have been removed or replaced since the TLBs were last invalidated.
    tlb_stale: bool,
}

/// Granularity at which lazily mapped 1:1 ranges are faulted in.
const LAZY_ONE_TO_ONE_CHUNK: u64 = 0x10_0000;
const HOST_PAGE_SIZE: u64 = 0x4000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LazyPage {
    Pending,
    Mapped,
    Unmapped,
}

/// Tracked per host page, since the guest may unmap parts of a range, and parts of a lazy range
/// before (or after) they are faulted in.
#[derive(Clone, Debug)]
struct OneToOne {
    host_addr: u64,
    pages: Vec<LazyPage>,
}

/// A virtually contiguous range mapped with the same permissions and backing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Region {
    size: u64,
    perms: av::MemPerms,
    privileged: bool,
    backing: Backing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backing {
    /// Host memory at the same address, at guest physical addresses from `paddr` on.
    OneToOne { paddr: u64 },
    /// Pages from the slab allocator, one per virtual page (see
    /// [`PageTableManager::slab_pages`]).
    Slab,
}

impl Region {
    /// This region's part from `offset` bytes in, `size` bytes long.
    fn slice(&self, offset: u64, size: u64) -> Self {
        let backing = match self.backing {
            Backing::OneToOne { paddr } => Backing::OneToOne {
                paddr: paddr + offset,
            },
            Backing::Slab => Backing::Slab,
        };
        Self {
            size,
            backing,
            ..*self
        }
    }

    /// Whether `next`, starting right after this region, can be merged into it.
    fn continues_into(&self, next: &Region) -> bool {
        let backing_continues = match (self.backing, next.backing) {
            (Backing::OneToOne { paddr }, Backing::OneToOne { paddr: next_paddr }) => {
                paddr + self.size == next_paddr
            }
            (Backing::Slab, Backing::Slab) => true,
            _ => false,
        };
        backing_continues && self.perms == next.perms && self.privileged == next.privileged
    }
}

/// Sets the VM's permissions on a 1:1 range, which is always readable and executable.
fn hv_protect(guest_paddr: u64, size: usize, writable: bool) -> Result<()> {
    let perms = if writable {
        av::MemPerms::RWX
    } else {
        av::MemPerms::RX
    };
    let ret = unsafe {
        applevisor_sys::hv_vm_protect(
            guest_paddr,
            size,
            Into::<applevisor_sys::hv_memory_flags_t>::into(perms),
        )
    };
    match ret {
        x if x == applevisor_sys::hv_error_t::HV_SUCCESS as i32 => Ok(()),
        code => Err(av::HypervisorError::from(code))?,
    }
}

// Expanded from hv_unsafe_call in applevisor
fn hv_map_1to1(host_addr: u64, guest_paddr: u64, size: usize) -> Result<()> {
    let ret = unsafe {
        applevisor_sys::hv_vm_map(
            host_addr as _,
            guest_paddr,
            size,
            Into::<applevisor_sys::hv_memory_flags_t>::into(av::MemPerms::RWX),
        )
    };
    match ret {
        x if x == applevisor_sys::hv_error_t::HV_SUCCESS as i32 => Ok(()),
        code => Err(av::HypervisorError::from(code))?,
    }
}

impl PageTableManager {
    /// Creates a new page table manager using `pma` as the physical memory page provider.
    pub fn new(pma: PhysMemAllocator) -> Result<Self> {
        let mut slab = SlabAllocator::new(pma, PAGE_TABLE_SIZE)?;
        let pgd = PageGlobalDirectory::new(slab.alloc()?);
        Ok(Self {
            slab,
            pgd,
            regions: BTreeMap::new(),
            slab_pages: BTreeMap::new(),
            one_to_one_last: 0x1_0000_0000,
            free_one_to_one: BTreeMap::new(),
            one_to_one: BTreeMap::new(),
            write_protected: BTreeSet::new(),
            write_protecting: false,
            tlb_stale: false,
        })
    }

    /// Maps the virtual address range of size `size` and starting at virtual address `addr` with
    /// permissions `perms`, backed by pages from the slab allocator. `privileged` determines if the
    /// mapping should be privileged or not (i.e. whether or not instructions running at EL0 can
    /// access it).
    pub fn map(
        &mut self,
        addr: u64,
        size: usize,
        perms: av::MemPerms,
        privileged: bool,
    ) -> Result<()> {
        let end = Self::virt_range(addr, size)?;
        if let Some(mapped) = self.regions_overlapping(addr, end).next() {
            return Err(MemoryError::AlreadyMapped(mapped.0.max(addr)))?;
        }
        for page_addr in (addr..end).step_by(VIRT_PAGE_SIZE) {
            let page = self.slab.alloc()?;
            let desc = PageDescriptor::new(page.guest_addr, perms, privileged);
            self.fill_ptes(page_addr, page_addr + VIRT_PAGE_SIZE as u64, |_| {
                desc.0
            })?;
            self.slab_pages.insert(page_addr, page);
        }
        self.insert_region(
            addr,
            Region {
                size: end - addr,
                perms,
                privileged,
                backing: Backing::Slab,
            },
        );
        Ok(())
    }

    /// Map the given address in the hypervisor's virtual address space into the same address in
    /// the virtual machine's address space.
    ///
    /// The host pages must not be ones SPTM has typed executable (`XNU_USER_EXEC`): handing
    /// those to `hv_vm_map` panics the kernel (`VIOLATION_ILLEGAL_MAPPING_TYPE`) rather than
    /// returning an error. That includes pages of a private, not-yet-written file mapping that
    /// share physical memory with an executable mapping of the same file anywhere on the system
    /// (e.g. the dyld shared cache). Use [`Self::map_1to1_lazy`] for those, which forces private
    /// copies as the guest touches them.
    pub fn map_1to1(
        &mut self,
        addr: u64,
        size: usize,
        perms: av::MemPerms,
        privileged: bool,
    ) -> Result<()> {
        self.retire_1to1(addr, size as u64)?;
        let guest_paddr = self.map_1to1_tables(addr, size, perms, privileged)?;
        hv_map_1to1(addr, guest_paddr, size)?;
        let pages = (size as u64).div_ceil(HOST_PAGE_SIZE) as usize;
        self.one_to_one.insert(
            guest_paddr,
            OneToOne {
                host_addr: addr,
                pages: vec![LazyPage::Mapped; pages],
            },
        );
        Ok(())
    }

    /// Like [`Self::map_1to1`], but the backing host memory is only mapped into the VM (in
    /// [`LAZY_ONE_TO_ONE_CHUNK`] pieces) when the guest first touches it; see
    /// [`Self::fault_in_lazy_1to1`]. The host range must be writable.
    pub fn map_1to1_lazy(
        &mut self,
        addr: u64,
        size: usize,
        perms: av::MemPerms,
        privileged: bool,
    ) -> Result<()> {
        if size as u64 % HOST_PAGE_SIZE != 0 {
            return Err(MemoryError::UnalignedSize(size))?;
        }
        self.retire_1to1(addr, size as u64)?;
        let guest_paddr = self.map_1to1_tables(addr, size, perms, privileged)?;
        self.one_to_one.insert(
            guest_paddr,
            OneToOne {
                host_addr: addr,
                pages: vec![LazyPage::Pending; size / HOST_PAGE_SIZE as usize],
            },
        );
        Ok(())
    }

    /// Takes the 1:1 pages backing host memory `addr..addr + size` out of the VM, before it's
    /// mapped again (e.g. the guest mapping over it), which points the page tables elsewhere.
    fn retire_1to1(&mut self, addr: u64, size: u64) -> Result<()> {
        let end = addr.saturating_add(size);
        let mut retired = BTreeSet::new();
        for (&range_paddr, range) in self.one_to_one.iter_mut() {
            let range_end = range.host_addr + range.pages.len() as u64 * HOST_PAGE_SIZE;
            if range.host_addr >= end || range_end <= addr {
                continue;
            }
            retired.insert(range_paddr);
            let first = (addr.max(range.host_addr) - range.host_addr) / HOST_PAGE_SIZE;
            let last = (end.min(range_end) - range.host_addr).div_ceil(HOST_PAGE_SIZE);
            for page in first..last {
                let state = std::mem::replace(&mut range.pages[page as usize], LazyPage::Unmapped);
                let paddr = range_paddr + page * HOST_PAGE_SIZE;
                self.write_protected.remove(&paddr);
                if state == LazyPage::Mapped {
                    let ret =
                        unsafe { applevisor_sys::hv_vm_unmap(paddr, HOST_PAGE_SIZE as usize) };
                    if ret != applevisor_sys::hv_error_t::HV_SUCCESS as i32 {
                        Err(av::HypervisorError::from(ret))?;
                    }
                }
            }
        }
        self.free_unmapped_1to1(retired);
        Ok(())
    }

    /// Guest physical space for a 1:1 range of `size` bytes, reusing that of ranges since
    /// unmapped. The VM's physical address space is small next to what a guest can map and unmap
    /// over time.
    fn allocate_one_to_one_paddr(&mut self, size: u64) -> u64 {
        let size = size.div_ceil(HOST_PAGE_SIZE) * HOST_PAGE_SIZE;
        let fit = self
            .free_one_to_one
            .iter()
            .find(|(_, &free)| free >= size)
            .map(|(&start, &free)| (start, free));
        let Some((start, free)) = fit else {
            let paddr = self.one_to_one_last;
            self.one_to_one_last += size;
            return paddr;
        };
        self.free_one_to_one.remove(&start);
        if free > size {
            self.free_one_to_one.insert(start + size, free - size);
        }
        start
    }

    /// Drops those of the 1:1 ranges starting at guest physical addresses `ranges` that are now
    /// entirely unmapped, freeing their guest physical space.
    fn free_unmapped_1to1(&mut self, ranges: BTreeSet<u64>) {
        for mut start in ranges {
            let Some(range) = self.one_to_one.get(&start) else {
                continue;
            };
            if range.pages.iter().any(|&page| page != LazyPage::Unmapped) {
                continue;
            }
            let mut size = range.pages.len() as u64 * HOST_PAGE_SIZE;
            self.one_to_one.remove(&start);
            if let Some((&before, &before_size)) = self.free_one_to_one.range(..start).next_back() {
                if before + before_size == start {
                    self.free_one_to_one.remove(&before);
                    start = before;
                    size += before_size;
                }
            }
            if let Some(after_size) = self.free_one_to_one.remove(&(start + size)) {
                size += after_size;
            }
            self.free_one_to_one.insert(start, size);
        }
    }

    /// Maps the chunk of a lazy 1:1 range containing guest physical address `paddr` into the VM.
    /// Returns `false` if `paddr` isn't in a lazy range, or its chunk was already mapped (so the
    /// fault is not ours to handle).
    pub fn fault_in_lazy_1to1(&mut self, paddr: u64) -> Result<bool> {
        let Some((range_paddr, range, page)) = self.lazy_page(paddr) else {
            return Ok(false);
        };
        if range.pages[page] != LazyPage::Pending {
            return Ok(false);
        }

        let pages_per_chunk = (LAZY_ONE_TO_ONE_CHUNK / HOST_PAGE_SIZE) as usize;
        let chunk_start = page / pages_per_chunk * pages_per_chunk;
        let chunk_end = (chunk_start + pages_per_chunk).min(range.pages.len());
        let mut mapped_runs = Vec::new();
        let mut page = chunk_start;
        while page < chunk_end {
            if range.pages[page] != LazyPage::Pending {
                page += 1;
                continue;
            }
            let run_start = page;
            while page < chunk_end && range.pages[page] == LazyPage::Pending {
                // Lazy ranges are meant for private file mappings whose pages may still be
                // shared with (and typed executable by) other mappings of the same file, which
                // the kernel refuses to map into a VM. Writing each page forces a copy-on-write
                // into a fresh private page.
                unsafe {
                    let ptr = (range.host_addr + page as u64 * HOST_PAGE_SIZE) as *mut u8;
                    std::ptr::write_volatile(ptr, std::ptr::read_volatile(ptr));
                }
                range.pages[page] = LazyPage::Mapped;
                page += 1;
            }
            let run_offset = run_start as u64 * HOST_PAGE_SIZE;
            let run_size = (page - run_start) * HOST_PAGE_SIZE as usize;
            hv_map_1to1(range.host_addr + run_offset, range_paddr + run_offset, run_size)?;
            mapped_runs.push((range_paddr + run_offset, run_size));
        }
        if self.write_protecting {
            for (paddr, size) in mapped_runs {
                hv_protect(paddr, size, false)?;
                for page_paddr in (paddr..paddr + size as u64).step_by(HOST_PAGE_SIZE as usize) {
                    self.write_protected.insert(page_paddr);
                }
            }
        }
        Ok(true)
    }

    /// Write-protects every 1:1 host page mapped into the VM, and those lazily mapped from now
    /// on, until [`Self::stop_write_protecting_1to1`]. A guest write to one then faults (see
    /// [`Self::take_write_fault`]).
    pub fn write_protect_1to1(&mut self) -> Result<()> {
        self.write_protecting = true;
        for (&range_paddr, range) in &self.one_to_one {
            let mut page = 0;
            while page < range.pages.len() {
                let needs_protecting = |p: usize| {
                    range.pages[p] == LazyPage::Mapped
                        && !self
                            .write_protected
                            .contains(&(range_paddr + p as u64 * HOST_PAGE_SIZE))
                };
                if !needs_protecting(page) {
                    page += 1;
                    continue;
                }
                let run_start = page;
                while page < range.pages.len() && needs_protecting(page) {
                    page += 1;
                }
                hv_protect(
                    range_paddr + run_start as u64 * HOST_PAGE_SIZE,
                    (page - run_start) * HOST_PAGE_SIZE as usize,
                    false,
                )?;
                for p in run_start..page {
                    self.write_protected
                        .insert(range_paddr + p as u64 * HOST_PAGE_SIZE);
                }
            }
        }
        Ok(())
    }

    /// Makes every 1:1 host page writable again, and stops write-protecting new ones.
    pub fn stop_write_protecting_1to1(&mut self) -> Result<()> {
        self.write_protecting = false;
        for paddr in std::mem::take(&mut self.write_protected) {
            hv_protect(paddr, HOST_PAGE_SIZE as usize, true)?;
        }
        Ok(())
    }

    /// Handles a stage-2 fault at guest physical address `paddr` if it's a write to a page
    /// [`Self::write_protect_1to1`] protected: makes the page writable, returning its host
    /// address.
    pub fn take_write_fault(&mut self, paddr: u64) -> Result<Option<u64>> {
        let page_paddr = paddr & !(HOST_PAGE_SIZE - 1);
        if !self.write_protected.remove(&page_paddr) {
            return Ok(None);
        }
        hv_protect(page_paddr, HOST_PAGE_SIZE as usize, true)?;
        let (range_paddr, range) = self
            .one_to_one
            .range(..=page_paddr)
            .next_back()
            .expect("protected pages are in 1:1 ranges");
        Ok(Some(range.host_addr + (page_paddr - range_paddr)))
    }

    /// The host pages of every 1:1 mapping, whether or not (lazily) mapped into the VM yet.
    #[cfg(test)]
    pub(crate) fn mapped_one_to_one_host_pages(&self) -> Vec<u64> {
        self.one_to_one
            .values()
            .flat_map(|range| {
                range
                    .pages
                    .iter()
                    .enumerate()
                    .filter(|(_, state)| **state != LazyPage::Unmapped)
                    .map(|(page, _)| range.host_addr + page as u64 * HOST_PAGE_SIZE)
            })
            .collect()
    }

    /// The host pages backing the 1:1 mappings in the virtual range `addr..addr + size`.
    pub fn one_to_one_host_pages(&self, addr: u64, size: usize) -> Vec<u64> {
        let end = addr.saturating_add(size as u64);
        let mut pages = Vec::new();
        let mut page_addr = addr & !(HOST_PAGE_SIZE - 1);
        while page_addr < end {
            let is_one_to_one = self.region_at(page_addr).is_some_and(|(_, region)| {
                matches!(region.backing, Backing::OneToOne { .. })
            });
            if is_one_to_one {
                pages.push(page_addr);
            }
            page_addr += HOST_PAGE_SIZE;
        }
        pages
    }

    /// Finds the lazy range and host page index containing guest physical address `paddr`.
    fn lazy_page(&mut self, paddr: u64) -> Option<(u64, &mut OneToOne, usize)> {
        let (&range_paddr, range) = self.one_to_one.range_mut(..=paddr).next_back()?;
        let page = ((paddr - range_paddr) / HOST_PAGE_SIZE) as usize;
        (page < range.pages.len()).then_some((range_paddr, range, page))
    }

    /// Removes a 1:1 range from the page tables and the VM. Pages in the range that aren't
    /// mapped, or aren't 1:1 mappings, are skipped.
    pub fn unmap_1to1(&mut self, addr: u64, size: usize) -> Result<()> {
        if addr & (HOST_PAGE_SIZE - 1) != 0 {
            return Err(MemoryError::UnalignedAddress(addr))?;
        }
        let end = addr
            .checked_add(size as u64)
            .ok_or(MemoryError::Overflow(addr, size))?;
        let removed = self.remove_regions(addr, end, |region| {
            matches!(region.backing, Backing::OneToOne { .. })
        })?;
        let mut host_page_paddrs = BTreeSet::new();
        for (_, region) in removed {
            let Backing::OneToOne { paddr } = region.backing else {
                unreachable!("only 1:1 regions were removed");
            };
            let first = paddr & !(HOST_PAGE_SIZE - 1);
            host_page_paddrs.extend((first..paddr + region.size).step_by(HOST_PAGE_SIZE as usize));
        }

        let mut ranges = BTreeSet::new();
        for paddr in host_page_paddrs {
            let was_mapped = match self.lazy_page(paddr) {
                Some((range_paddr, range, page)) => {
                    ranges.insert(range_paddr);
                    let state = std::mem::replace(&mut range.pages[page], LazyPage::Unmapped);
                    state == LazyPage::Mapped
                }
                None => true,
            };
            self.write_protected.remove(&paddr);
            if was_mapped {
                let ret = unsafe { applevisor_sys::hv_vm_unmap(paddr, HOST_PAGE_SIZE as usize) };
                if ret != applevisor_sys::hv_error_t::HV_SUCCESS as i32 {
                    Err(av::HypervisorError::from(ret))?;
                }
            }
        }
        self.free_unmapped_1to1(ranges);
        Ok(())
    }

    /// Assigns guest physical addresses to a 1:1 range and adds it to the page tables, without
    /// creating the stage-2 mapping. Returns the range's guest physical address. Whatever was
    /// mapped there before is replaced.
    fn map_1to1_tables(
        &mut self,
        addr: u64,
        size: usize,
        perms: av::MemPerms,
        privileged: bool,
    ) -> Result<u64> {
        let end = Self::virt_range(addr, size)?;
        self.remove_regions(addr, end, |_| true)?;
        let paddr = self.allocate_one_to_one_paddr(size as u64);
        self.fill_ptes(addr, end, |page_addr| {
            PageDescriptor::new(paddr + (page_addr - addr), perms, privileged).0
        })?;
        self.insert_region(
            addr,
            Region {
                size: end - addr,
                perms,
                privileged,
                backing: Backing::OneToOne { paddr },
            },
        );
        Ok(paddr)
    }

    /// Unmaps the virtual address range of size `size` and starting at address `addr`.
    pub fn unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        let end = Self::virt_range(addr, size)?;
        self.remove_regions(addr, end, |_| true)?;
        Ok(())
    }

    /// Checks `addr..addr + size` is page-aligned, returning its end.
    fn virt_range(addr: u64, size: usize) -> Result<u64> {
        if addr & (VIRT_PAGE_SIZE as u64 - 1) != 0 {
            return Err(MemoryError::UnalignedAddress(addr))?;
        }
        if size & (VIRT_PAGE_SIZE - 1) != 0 {
            return Err(MemoryError::UnalignedSize(size))?;
        }
        Ok(addr
            .checked_add(size as u64)
            .ok_or(MemoryError::Overflow(addr, size))?)
    }

    /// The region containing virtual address `addr`, and where it starts.
    fn region_at(&self, addr: u64) -> Option<(u64, &Region)> {
        let (&start, region) = self.regions.range(..=addr).next_back()?;
        (addr < start + region.size).then_some((start, region))
    }

    /// The regions overlapping `start..end`, and where they start.
    fn regions_overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, Region)> + '_ {
        let first = self.region_at(start).map_or(start, |(region_start, _)| region_start);
        self.regions
            .range(first..end)
            .map(|(&region_start, region)| (region_start, *region))
    }

    /// Adds a region, merging it with its neighbors where they agree.
    fn insert_region(&mut self, mut start: u64, mut region: Region) {
        if let Some((&before, previous)) = self.regions.range(..start).next_back() {
            if before + previous.size == start && previous.continues_into(&region) {
                region = Region {
                    size: previous.size + region.size,
                    ..*previous
                };
                self.regions.remove(&before);
                start = before;
            }
        }
        let end = start + region.size;
        if let Some(next) = self.regions.get(&end).copied() {
            if region.continues_into(&next) {
                region.size += next.size;
                self.regions.remove(&end);
            }
        }
        self.regions.insert(start, region);
    }

    /// Unmaps the parts of the regions in `start..end` that `which` selects: splits them off,
    /// clears their descriptors, and frees their slab pages. Returns the parts removed.
    fn remove_regions(
        &mut self,
        start: u64,
        end: u64,
        which: impl Fn(&Region) -> bool,
    ) -> Result<Vec<(u64, Region)>> {
        let overlapping: Vec<(u64, Region)> = self
            .regions_overlapping(start, end)
            .filter(|(_, region)| which(region))
            .collect();
        let mut removed = Vec::new();
        for (region_start, region) in overlapping {
            let region_end = region_start + region.size;
            let cut_start = region_start.max(start);
            let cut_end = region_end.min(end);
            self.regions.remove(&region_start);
            if region_start < cut_start {
                self.regions
                    .insert(region_start, region.slice(0, cut_start - region_start));
            }
            if cut_end < region_end {
                self.regions.insert(
                    cut_end,
                    region.slice(cut_end - region_start, region_end - cut_end),
                );
            }
            self.clear_ptes(cut_start, cut_end)?;
            if region.backing == Backing::Slab {
                for page_addr in (cut_start..cut_end).step_by(VIRT_PAGE_SIZE) {
                    if let Some(page) = self.slab_pages.remove(&page_addr) {
                        self.slab.free(page)?;
                    }
                }
            }
            removed.push((
                cut_start,
                region.slice(cut_start - region_start, cut_end - cut_start),
            ));
        }
        Ok(removed)
    }

    /// Sets the descriptors of the pages in `start..end` to `desc(page address)`, adding page
    /// tables as needed.
    fn fill_ptes(&mut self, start: u64, end: u64, desc: impl Fn(u64) -> u64) -> Result<()> {
        let mut addr = start;
        while addr < end {
            let table_end = (addr | ((1 << 21) - 1)).saturating_add(1);
            let pt = self.page_table_mut(addr)?;
            let mut stale = false;
            while addr < end.min(table_end) {
                stale |= pt.set_entry((addr >> 12 & 0x1ff) as usize, desc(addr));
                addr += VIRT_PAGE_SIZE as u64;
            }
            self.tlb_stale |= stale;
        }
        Ok(())
    }

    /// The page table covering virtual address `addr`, added (with its parents) if needed.
    fn page_table_mut(&mut self, addr: u64) -> Result<&mut PageTable> {
        let pud_idx = (addr >> 39 & 0x1ff) as usize;
        if let Entry::Vacant(e) = self.pgd.objects.entry(pud_idx) {
            let pud = PageUpperDirectory::new(self.slab.alloc()?);
            Self::add_entry(pud.descriptor.0, pud_idx, &mut self.pgd.entries)?;
            e.insert(pud);
        }
        let pud = self.pgd.objects.get_mut(&pud_idx).unwrap();
        let pmd_idx = (addr >> 30 & 0x1ff) as usize;
        if let Entry::Vacant(e) = pud.objects.entry(pmd_idx) {
            let pmd = PageMiddleDirectory::new(self.slab.alloc()?);
            Self::add_entry(pmd.descriptor.0, pmd_idx, &mut pud.entries)?;
            e.insert(pmd);
        }
        let pmd = pud.objects.get_mut(&pmd_idx).unwrap();
        let pt_idx = (addr >> 21 & 0x1ff) as usize;
        if let Entry::Vacant(e) = pmd.objects.entry(pt_idx) {
            let pt = PageTable::new(self.slab.alloc()?);
            Self::add_entry(pt.descriptor.0, pt_idx, &mut pmd.entries)?;
            e.insert(pt);
        }
        Ok(pmd.objects.get_mut(&pt_idx).unwrap())
    }

    /// The page table covering virtual address `addr`, if there is one.
    fn page_table(&self, addr: u64) -> Option<&PageTable> {
        self.pgd
            .objects
            .get(&((addr >> 39 & 0x1ff) as usize))?
            .objects
            .get(&((addr >> 30 & 0x1ff) as usize))?
            .objects
            .get(&((addr >> 21 & 0x1ff) as usize))
    }

    /// Clears the descriptors of the pages in `start..end`, freeing page tables left empty.
    fn clear_ptes(&mut self, start: u64, end: u64) -> Result<()> {
        let mut addr = start;
        while addr < end {
            let table_end = (addr | ((1 << 21) - 1)).saturating_add(1);
            let pud_idx = (addr >> 39 & 0x1ff) as usize;
            let pmd_idx = (addr >> 30 & 0x1ff) as usize;
            let pt_idx = (addr >> 21 & 0x1ff) as usize;
            let Some(pud) = self.pgd.objects.get_mut(&pud_idx) else {
                addr = table_end;
                continue;
            };
            let Some(pmd) = pud.objects.get_mut(&pmd_idx) else {
                addr = table_end;
                continue;
            };
            let Some(pt) = pmd.objects.get_mut(&pt_idx) else {
                addr = table_end;
                continue;
            };
            while addr < end.min(table_end) {
                self.tlb_stale |= pt.set_entry((addr >> 12 & 0x1ff) as usize, 0);
                addr += VIRT_PAGE_SIZE as u64;
            }
            if pt.used == 0 {
                Self::del_entry(pt_idx, &mut pmd.entries)?;
                let pt = pmd.objects.remove(&pt_idx).unwrap();
                self.slab.free(pt.entries)?;
            }
            if pmd.objects.is_empty() {
                Self::del_entry(pmd_idx, &mut pud.entries)?;
                let pmd = pud.objects.remove(&pmd_idx).unwrap();
                self.slab.free(pmd.entries)?;
            }
            if pud.objects.is_empty() {
                Self::del_entry(pud_idx, &mut self.pgd.entries)?;
                let pud = self.pgd.objects.remove(&pud_idx).unwrap();
                self.slab.free(pud.entries)?;
            }
        }
        Ok(())
    }

    /// The descriptor virtual address `addr`'s page should have, and the page's host address.
    fn page(&self, addr: u64) -> Result<(PageDescriptor, *const u8)> {
        let page_addr = align_virt_page!(addr);
        let (start, region) = self
            .region_at(page_addr)
            .ok_or(MemoryError::UnallocatedMemoryAccess(addr))?;
        let (paddr, host_addr) = match region.backing {
            Backing::OneToOne { paddr } => (paddr + (page_addr - start), page_addr as *const u8),
            Backing::Slab => {
                let page = &self.slab_pages[&page_addr];
                (page.guest_addr, page.host_addr)
            }
        };
        Ok((
            PageDescriptor::new(paddr, region.perms, region.privileged),
            host_addr,
        ))
    }

    /// The host address backing virtual address `addr`.
    pub fn host_addr(&self, addr: u64) -> Result<*const u8> {
        let (_, host_page) = self.page(addr)?;
        // SAFETY: the offset is within the page.
        Ok(unsafe { host_page.add((addr & (VIRT_PAGE_SIZE as u64 - 1)) as usize) })
    }

    /// Adds a descriptor `desc` at index `idx` into the [`SlabObject`] `ents` that corresponds to
    /// a page table level.
    #[inline]
    fn add_entry(desc: u64, idx: usize, ents: &mut SlabObject) -> Result<()> {
        if idx > PAGE_TABLE_NB_ENTRIES {
            return Err(MemoryError::InvalidIndex(idx))?;
        }
        // SAFETY: we know that `host_addr` is mapped as long as the `ents` exists and we made sure
        //         that `idx` is not out of bounds.
        unsafe {
            std::ptr::write(ents.host_addr.add(idx * 8) as *mut u64, desc);
        };
        Ok(())
    }

    /// Removes the descriptor at index `idx` from the [`SlabObject`] `ents` that corresponds to
    /// a page table level.
    #[inline]
    pub fn del_entry(idx: usize, ents: &mut SlabObject) -> Result<()> {
        Self::add_entry(0, idx, ents)
    }
}

// -----------------------------------------------------------------------------------------------
// Guest Virtual Memory Allocator
// -----------------------------------------------------------------------------------------------

/// Virtual memory allocator.
///
/// # Role of the Virtual Memory Allocator in the Fuzzer
///
/// [`PhysMemAllocator`] and [`PageTableManager`] provides the necessary building blocks to create
/// multiple independant virtual address spaces over a shared physical one.
///
/// The role of this allocator is to provide an abstraction over [`PageTableManager`], to easily
/// allocate and access virtual memory inside a guest VM, but also to initialize the different
/// ARM system registers used for memory management (e.g. `TTBR0_EL1/TTBR1_EL1`, `SCTRL_EL1`,
/// `MAIR_EL1`, etc.). It also provides fuzzing specific function, such as the ability to restore
/// a virtual address space from a snapshot.
///
/// Each fuzzing [`Executor`](crate::core::Executor) has at least one instance of this allocator to
/// manage its virtual memory ranges.
///
/// # Example
///
/// ```ignore
/// use applevisor as av;
/// use hyperpom::memory::{PhysMemAllocator, VirtMemAllocator};
///
/// // First we create an hypervisor virtual machine instance to allow memory management in the
/// // guest (there's only one per process).
/// let vm = applevisor::VirtualMachine::new().unwrap();
///
/// // We create a new physical memory allocator over an address range of size 0x1000_0000.
/// let mut pma = PhysMemAllocator::new(0x1000_0000).unwrap();
///
/// // We create a new virtual memory allocator using `pma` as the physical page provider.
/// let mut vma = VirtMemAllocator::new(pma).unwrap();
///
/// // We can now map a virtual memory range starting at address `0x1234_0000`.
/// vma.map(0x1234_0000, 0x1000, av::MemPerms::RWX).unwrap();
///
/// // We can clone the virtual address space.
/// let vma_snapshot = vma.clone();
///
/// // We can write to it.
/// vma.write_qword(0x0000_0000_1000_0000, 0xdead_beef_dead_beef).unwrap();
///
/// // We can read from it.
/// assert_eq!(vma.read_qword(0x0000_0000_1000_0000), Ok(0xdead_beef_dead_beef));
///
/// // We can restore the virtual address space from a snapshot.
/// vma.restore_from_snapshot(&vma_snapshot).unwrap();
/// ```
///
/// Now it's also possible to map code and make the cpu execute arbitrary programs.
///
/// ```ignore
/// use applevisor as av;
/// use keystone as ks;
/// use hyperpom::memory::{PhysMemAllocator, VirtMemAllocator};
///
/// // Creates a new hypervisor virtual machine for this process.
/// let vm = av::VirtualMachine::new().unwrap();
///
/// // Creates an address space of size 0x1000_0000.
/// let pma = PhysMemAllocator::new(0x1000_0000).unwrap();
///
/// // Creates a virtual memory allocator.
/// let mut vma = VirtMemAllocator::new(pma.clone()).unwrap();
///
/// // Creates a new Vcpu.
/// let mut vcpu = av::Vcpu::new().unwrap();
///
/// // Initializes Vcpu system registers.
/// vma.init(&mut vcpu, true).unwrap();
///
/// // Maps an executable page at address 0x10_0000.
/// vma.map(0x10_0000, 0x1000, av::MemPerms::RX).unwrap();
///
/// // We compile a small program using the keystone engine.
/// let ks = ks::Keystone::new(keystone::Arch::ARM64, keystone::Mode::LITTLE_ENDIAN)
///     .expect("Could not initialize Keystone engine");
/// let asm = String::from(
///     "mov x0, #0x0000
///     movk x0, #0x20, lsl #16
///     blr x0
///     brk #0",
/// );
/// let entry_func = ks.asm(asm, 0).expect("could not assemble");
///
/// // We write the function at address 0x10_0000.
/// vma.write(0x10_0000, &entry_func.bytes).unwrap();
///
/// // We create a mapping and write a second function (that will be called by the first one) at
/// // address 0x20_0000.
/// vma.map(0x20_0000, 0x1000, av::MemPerms::RX).unwrap();
/// let asm = String::from(
///     "mov x0, #0x42
///     ret",
/// );
/// let func = ks.asm(asm, 0).expect("could not assemble");
/// vma.write(0x200000, &func.bytes).unwrap();
///
/// // Sets PC to the entry point address.
/// vcpu.set_reg(av::Reg::PC, 0x10_0000).unwrap();
///
/// // Runs the program
/// vcpu.run().unwrap();
///
/// // Checks that the value stored after the program execution is 0x42.
/// assert_eq!(vcpu.get_reg(av::Reg::X0), Ok(0x42));
///
/// // Checks that the Vcpu stopped its execution after an exception was raised when hitting
/// // the breakpoint.
/// let exit = vcpu.get_exit_info();
/// assert_eq!(exit.reason, av::ExitReason::EXCEPTION);
/// assert_eq!(exit.exception.syndrome, 0xf2000000);
/// ```
pub struct VirtMemAllocator {
    /// Page table for the upper virtual address range.
    pub(crate) upper_table: PageTableManager,
    /// Page table for the lower virtual address range.
    pub(crate) lower_table: PageTableManager,
    /// See [`Self::checkpoint_memory`]: oldest first.
    memory_intervals: Vec<MemoryInterval>,
    next_memory_checkpoint: u64,
    /// See [`Self::write_code`].
    code_written: bool,
}

/// A state of guest memory that [`VirtMemAllocator::restore_memory`] can go back to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryCheckpoint(u64);

/// The guest memory written since a checkpoint (and before the next), as it was at the
/// checkpoint, by host page.
struct MemoryInterval {
    checkpoint: MemoryCheckpoint,
    undo: BTreeMap<u64, Box<[u8]>>,
}

impl VirtMemAllocator {
    /// Creates a new virtual memory allocator over the physical memory allocator `pma`.
    pub fn new(pma: PhysMemAllocator) -> Result<Self> {
        let upper_table = PageTableManager::new(pma.clone())?;
        let lower_table = PageTableManager::new(pma)?;
        Ok(Self {
            upper_table,
            lower_table,
            memory_intervals: Vec::new(),
            next_memory_checkpoint: 0,
            code_written: false,
        })
    }

    /// Records the current state of guest memory, to [`Self::restore_memory`] later.
    ///
    /// Covers the guest's 1:1 mappings (memory it maps and the images appbox loads), which it
    /// tracks copy-on-write: they're write-protected in the VM, and each page's contents are saved
    /// when the guest first writes to it after a checkpoint. Writes that don't go through the VM
    /// (the host's, e.g. a syscall filling a buffer) must be announced with
    /// [`Self::log_host_write`] first. Mappings made or removed after a checkpoint aren't undone
    /// by restoring it; that's up to whoever made them.
    pub fn checkpoint_memory(&mut self) -> Result<MemoryCheckpoint> {
        self.write_protect_1to1()?;
        let checkpoint = MemoryCheckpoint(self.next_memory_checkpoint);
        self.next_memory_checkpoint += 1;
        self.memory_intervals.push(MemoryInterval {
            checkpoint,
            undo: BTreeMap::new(),
        });
        Ok(checkpoint)
    }

    /// Saves a host page's contents for the current interval, unless already saved.
    fn save_page(&mut self, host_page: u64) {
        let Some(interval) = self.memory_intervals.last_mut() else {
            return;
        };
        interval.undo.entry(host_page).or_insert_with(|| {
            // SAFETY: 1:1 mapped host memory, which the guest isn't running to change.
            unsafe { std::slice::from_raw_parts(host_page as *const u8, HOST_PAGE_SIZE as usize) }
                .into()
        });
    }

    /// Handles a stage-2 fault at `paddr` if it's a guest write to a page write-protected for
    /// checkpoints: saves the page and makes it writable.
    pub fn handle_checkpoint_write_fault(&mut self, paddr: u64) -> Result<bool> {
        if self.memory_intervals.is_empty() {
            return Ok(false);
        }
        let Some(host_page) = self.take_write_fault(paddr)? else {
            return Ok(false);
        };
        self.save_page(host_page);
        Ok(true)
    }

    /// Announces a write to guest memory `addr..addr + size` that won't go through the VM, so
    /// that checkpoints can undo it. Call it before writing.
    pub fn log_host_write(&mut self, addr: u64, size: usize) {
        if self.memory_intervals.is_empty() {
            return;
        }
        for page in self.one_to_one_host_pages(addr, size) {
            self.save_page(page);
        }
    }

    /// Whether memory checkpoints are being kept.
    pub fn checkpointing(&self) -> bool {
        !self.memory_intervals.is_empty()
    }

    fn interval_index(&self, checkpoint: MemoryCheckpoint) -> Option<usize> {
        self.memory_intervals
            .iter()
            .position(|interval| interval.checkpoint == checkpoint)
    }

    /// Puts guest memory back how it was at `checkpoint`, discarding later checkpoints. Returns
    /// false if there's no such checkpoint.
    pub fn restore_memory(&mut self, checkpoint: MemoryCheckpoint) -> Result<bool> {
        let Some(index) = self.interval_index(checkpoint) else {
            return Ok(false);
        };
        // Newest first, so a page's oldest saved contents are what's left.
        for interval in self.memory_intervals[index..].iter().rev() {
            for (&host_page, contents) in &interval.undo {
                // Pages since unmapped aren't the guest's any more.
                if self
                    .one_to_one_host_pages(host_page, HOST_PAGE_SIZE as usize)
                    .is_empty()
                {
                    continue;
                }
                // SAFETY: 1:1 mapped host memory, which the guest isn't running to change.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        contents.as_ptr(),
                        host_page as *mut u8,
                        HOST_PAGE_SIZE as usize,
                    )
                };
            }
        }
        self.memory_intervals.truncate(index + 1);
        self.memory_intervals[index].undo.clear();
        self.write_protect_1to1()?;
        Ok(true)
    }

    /// Forgets `checkpoint`, which can't be restored any more (but those around it still can).
    /// Returns false if there's no such checkpoint.
    pub fn discard_memory_checkpoint(&mut self, checkpoint: MemoryCheckpoint) -> Result<bool> {
        let Some(index) = self.interval_index(checkpoint) else {
            return Ok(false);
        };
        let interval = self.memory_intervals.remove(index);
        if index > 0 {
            // The previous interval now runs on to the next checkpoint. Its saved contents are
            // older, so they win.
            let previous = &mut self.memory_intervals[index - 1].undo;
            for (host_page, contents) in interval.undo {
                previous.entry(host_page).or_insert(contents);
            }
        }
        if self.memory_intervals.is_empty() {
            self.stop_write_protecting_1to1()?;
        }
        Ok(true)
    }

    /// The memory checkpoints' saved pages' total size.
    pub fn checkpointed_bytes(&self) -> usize {
        self.memory_intervals
            .iter()
            .map(|interval| interval.undo.len() * HOST_PAGE_SIZE as usize)
            .sum()
    }

    /// Modifies different system registers to:
    ///
    ///  * set the page memory attributes;
    ///  * set the granule size;
    ///  * set the size of the upper and lower virtual address ranges;
    ///  * set the page table address of the upper and lower virtual address ranges;
    ///  * enable caches and the MMU;
    ///  * disable SIMD and FP registers access trapping;
    ///  * set the current exception level to EL0;
    ///  * unmask interrupts;
    ///  * initialize the [`Exceptions`] vector table;
    ///  * enable debug features for the hypervisor.
    ///
    /// The `map_exceptions` argument determines if we need to remap the exception vector table
    /// in the current address space. This argument should be set to `false` if the function
    /// is called after restoring from a snapshot.
    pub fn init(&mut self, vcpu: &mut av::Vcpu, map_exceptions: bool) -> Result<()> {
        // MAIR_EL1: 0booooiiii = 0xff
        //  - 0b11RWiiii -> Normal memory, Outer Write-Back Non-transient (Allocate / Allocate)
        //  - 0boooo11RW -> Normal memory, Inner Write-Back Non-transient (Allocate / Allocate)
        vcpu.set_sys_reg(av::SysReg::MAIR_EL1, 0xff)?;
        // TCR_EL1
        //  - T0SZ: Size offset of the memory region addressed by TTBR0_EL1.
        //      16 -> Lower address space size = 2^48
        //  - TG0: Granule size for TTBR0_EL1.
        //      0  -> 4KB
        //  - T1SZ: Size offset of the memory region addressed by TTBR1_EL1.
        //      16 -> Upper address space size = 2^48
        //  - TG1: Granule size for TTBR1_EL1.
        //      2  -> 4KB
        //  - IPS: Intermediate Physical Address Size.
        //      0b110 -> 52 bit (4PB) - as big as it can be
        //  - HA: Hardware Access flag update in stage 1 translations from EL0 and EL1.
        //      1  -> Stage 1 Access flag update enabled.
        //  - HD: Hardware management of dirty state in stage 1 translations from EL0 and EL1.
        //      1  -> Stage 1 hardware management of dirty state enabled, only if the HA bit is
        //            also set to 1.
        //  - TBI0: Top Byte Ignore for the lower VA range, because PAC breaks us otherwise. It's
        //    not clear why exactly, since we don't rely on pointers already signed with a key we
        //    don't have, but libobjc dies without it, on a heap data pointer authenticated with
        //    the B key of all things, which should be process-specific anyway.
        vcpu.set_sys_reg(
            av::SysReg::TCR_EL1,
            0x10 | (0x10 << 16) | (0b10 << 30) | (0b110 << 32) | (1 << 37) | (1 << 39) | (1 << 40),
        )?;
        // TTBRX_EL1
        //  - BADDR: stage 1 translation table base address
        self.set_trans_table_base_registers(vcpu)?;
        // SCTRL_EL1
        //  - Defaults to `0x30100180`.
        //  - I: Stage 1 instruction access Cacheability control, for accesses at EL0 and EL1.
        //  - C: Stage 1 Cacheability control, for data accesses.
        //  - M: MMU enable for EL1&0 stage 1 address translation.
        //  - DZE, UCT, UCI: EL0 can use DC ZVA (e.g. in bzero), read CTR_EL0, and do cache
        //    maintenance, as XNU lets user processes.
        vcpu.set_sys_reg(
            av::SysReg::SCTLR_EL1,
            0x1005 | (1 << 14) | (1 << 15) | (1 << 26),
        )?;
        // CPACR_EL1
        //  - FPEN: This control does not cause execution of any instructions that access the
        //          Advanced SIMD and floating-point registers to be trapped.
        vcpu.set_sys_reg(av::SysReg::CPACR_EL1, 0x3 << 20)?;
        // CPSR
        //  - M: 0b0000 -> User mode.
        //  - F: FIQ unmasked.
        //  - I: RIQ unmasked.
        //  - A: SError unmasked.
        vcpu.set_reg(av::Reg::CPSR, 0x3c0).unwrap();
        if map_exceptions {
            // Maps and sets VBAR_EL1
            Exceptions::init(vcpu, self)?;
        } else {
            vcpu.set_sys_reg(av::SysReg::VBAR_EL1, EVTABLE_ADDR)?;
        }
        // Enables debug features for the hypervisor
        vcpu.set_trap_debug_exceptions(true)?;
        vcpu.set_trap_debug_reg_accesses(true)?;
        Ok(())
    }

    /// Sets TTBR0_EL1 and TTBR1_EL1 to the addresses of the current virtual address space page
    /// tables.
    pub fn set_trans_table_base_registers(&self, vcpu: &av::Vcpu) -> Result<()> {
        vcpu.set_sys_reg(
            av::SysReg::TTBR1_EL1,
            self.upper_table.pgd.entries.guest_addr as u64,
        )?;
        vcpu.set_sys_reg(
            av::SysReg::TTBR0_EL1,
            self.lower_table.pgd.entries.guest_addr as u64,
        )?;
        Ok(())
    }

    /// Maps a non-privileged virtual address range of size `size`, starting at address `addr` and
    /// with permissions `perms`.
    #[inline]
    pub fn map(&mut self, addr: u64, size: usize, perms: av::MemPerms) -> Result<()> {
        // Determines which page table should be used based on the region the address is from.
        match addr >> 0x30 {
            0x0000 => self.lower_table.map(addr, size, perms, false),
            0xffff => self.upper_table.map(addr, size, perms, false),
            _ => Err(MemoryError::InvalidAddress(addr))?,
        }
    }

    /// Lazily maps a non-privileged 1:1 range; see [`PageTableManager::map_1to1_lazy`].
    #[inline]
    pub fn map_1to1_lazy(&mut self, addr: u64, size: usize, perms: av::MemPerms) -> Result<()> {
        match addr >> 0x30 {
            0x0000 => self.lower_table.map_1to1_lazy(addr, size, perms, false),
            0xffff => self.upper_table.map_1to1_lazy(addr, size, perms, false),
            _ => Err(MemoryError::InvalidAddress(addr))?,
        }
    }

    /// Removes a 1:1 range from the VM; see [`PageTableManager::unmap_1to1`].
    #[inline]
    pub fn unmap_1to1(&mut self, addr: u64, size: usize) -> Result<()> {
        match addr >> 0x30 {
            0x0000 => self.lower_table.unmap_1to1(addr, size),
            0xffff => self.upper_table.unmap_1to1(addr, size),
            _ => Err(MemoryError::InvalidAddress(addr))?,
        }
    }

    /// Whether the guest's TLBs may hold translations since removed or replaced, or its
    /// instruction caches code since rewritten, which must be invalidated before it runs again.
    /// Clears it.
    pub fn take_caches_stale(&mut self) -> bool {
        std::mem::take(&mut self.code_written)
            | std::mem::take(&mut self.lower_table.tlb_stale)
            | std::mem::take(&mut self.upper_table.tlb_stale)
    }

    /// Like [`Self::write`], for (possibly) rewriting code the guest may have run, whose stale
    /// copies in the instruction caches are then invalidated before the guest runs again.
    pub fn write_code(&mut self, addr: u64, buf: &[u8]) -> Result<usize> {
        self.code_written = true;
        self.write(addr, buf)
    }

    /// See [`PageTableManager::write_protect_1to1`].
    pub fn write_protect_1to1(&mut self) -> Result<()> {
        self.lower_table.write_protect_1to1()?;
        self.upper_table.write_protect_1to1()
    }

    /// See [`PageTableManager::stop_write_protecting_1to1`].
    pub fn stop_write_protecting_1to1(&mut self) -> Result<()> {
        self.lower_table.stop_write_protecting_1to1()?;
        self.upper_table.stop_write_protecting_1to1()
    }

    /// See [`PageTableManager::take_write_fault`].
    pub fn take_write_fault(&mut self, paddr: u64) -> Result<Option<u64>> {
        match self.lower_table.take_write_fault(paddr)? {
            Some(host) => Ok(Some(host)),
            None => self.upper_table.take_write_fault(paddr),
        }
    }

    /// See [`PageTableManager::one_to_one_host_pages`].
    pub fn one_to_one_host_pages(&self, addr: u64, size: usize) -> Vec<u64> {
        match addr >> 0x30 {
            0x0000 => self.lower_table.one_to_one_host_pages(addr, size),
            0xffff => self.upper_table.one_to_one_host_pages(addr, size),
            _ => Vec::new(),
        }
    }

    /// Handles a stage-2 fault at guest physical address `paddr` if it belongs to a lazy 1:1
    /// range; see [`PageTableManager::fault_in_lazy_1to1`].
    pub fn fault_in_lazy_1to1(&mut self, paddr: u64) -> Result<bool> {
        Ok(self.lower_table.fault_in_lazy_1to1(paddr)?
            || self.upper_table.fault_in_lazy_1to1(paddr)?)
    }

    /// Maps a non-privileged virtual address range of size `size`, starting at address `addr` and
    /// with permissions `perms`.
    #[inline]
    pub fn map_1to1(&mut self, addr: u64, size: usize, perms: av::MemPerms) -> Result<()> {
        // Determines which page table should be used based on the region the address is from.
        match addr >> 0x30 {
            0x0000 => self.lower_table.map_1to1(addr, size, perms, false),
            0xffff => self.upper_table.map_1to1(addr, size, perms, false),
            _ => Err(MemoryError::InvalidAddress(addr))?,
        }
    }

    /// Maps a privileged virtual address range of size `size`, starting at address `addr` and
    /// with permissions `perms`.
    ///
    /// This function exists mainly because PAN is enabled by default on Apple Silicon. Therefore,
    /// all code that runs at EL1 (cache maintenance, exception handling, etc.) should be mapped
    /// using this function, otherwise it will trigger an exception.
    #[inline]
    pub fn map_privileged(&mut self, addr: u64, size: usize, perms: av::MemPerms) -> Result<()> {
        // Determines which page table should be used based on the region the address is from.
        match addr >> 0x30 {
            0x0000 => self.lower_table.map(addr, size, perms, true),
            0xffff => self.upper_table.map(addr, size, perms, true),
            _ => Err(MemoryError::InvalidAddress(addr))?,
        }
    }

    /// Unmaps a virtual address range of size `size` and starting at address `addr`.
    #[inline]
    pub fn unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        // Determines which page table should be used based on the region the address is from.
        match addr >> 0x30 {
            0x0000 => self.lower_table.unmap(addr, size),
            0xffff => self.upper_table.unmap(addr, size),
            _ => Err(MemoryError::InvalidAddress(addr))?,
        }
    }

    /// Returns the host address backing virtual address `addr`.
    pub fn host_addr(&self, addr: u64) -> Result<*const u8> {
        match addr >> 0x30 {
            0x0000 => self.lower_table.host_addr(addr),
            0xffff => self.upper_table.host_addr(addr),
            _ => Err(MemoryError::InvalidAddress(addr))?,
        }
    }

    /// Reads from virtual address `addr` into the slice `buf`. The number of bytes read is the
    /// size of `buf`.
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        self.copy_pages(addr, buf.len(), |host, offset, len| unsafe {
            // SAFETY: `host` is valid for `len` bytes, all in one guest page.
            std::ptr::copy(host, buf.as_mut_ptr().add(offset), len)
        })?;
        Ok(buf.len())
    }

    /// Calls `copy(host address, offset into the range, length)` for each page's part of the
    /// virtual range `addr..addr + len`.
    fn copy_pages(
        &self,
        addr: u64,
        len: usize,
        mut copy: impl FnMut(*mut u8, usize, usize),
    ) -> Result<()> {
        let end = addr
            .checked_add(len as u64)
            .ok_or(MemoryError::Overflow(addr, len))?;
        let mut cursor = addr;
        while cursor < end {
            let page_end = align_virt_page!(cursor) + VIRT_PAGE_SIZE as u64;
            let chunk = (page_end.min(end) - cursor) as usize;
            let host = self.host_addr(cursor)? as *mut u8;
            copy(host, (cursor - addr) as usize, chunk);
            cursor += chunk as u64;
        }
        Ok(())
    }

    /// Reads one byte at virtual address `addr`.
    #[inline]
    pub fn read_byte(&self, addr: u64) -> Result<u8> {
        let mut data = [0u8; 1];
        self.read(addr, &mut data)?;
        Ok(data[0])
    }

    /// Reads one word at virtual address `addr`.
    #[inline]
    pub fn read_word(&self, addr: u64) -> Result<u16> {
        let mut data = [0u8; 2];
        self.read(addr, &mut data)?;
        Ok(u16::from_le_bytes(data[..2].try_into().unwrap()))
    }

    /// Reads one dword at virtual address `addr`.
    #[inline]
    pub fn read_dword(&self, addr: u64) -> Result<u32> {
        let mut data = [0u8; 4];
        self.read(addr, &mut data)?;
        Ok(u32::from_le_bytes(data[..4].try_into().unwrap()))
    }

    /// Reads one qword at virtual address `addr`.
    #[inline]
    pub fn read_qword(&self, addr: u64) -> Result<u64> {
        let mut data = [0u8; 8];
        self.read(addr, &mut data)?;
        Ok(u64::from_le_bytes(data[..8].try_into().unwrap()))
    }

    /// Reads a C-string at virtual address `addr`.
    #[inline]
    pub fn read_cstring(&self, addr: u64) -> Result<String> {
        let mut chars = vec![];
        let mut c = self.read_byte(addr)?;
        let mut offset = 0;
        while c != 0 {
            chars.push(c);
            offset += 1;
            c = self.read_byte(addr + offset)?;
        }
        Ok(String::from_utf8_lossy(&chars).to_string())
    }

    /// Writes to virtual address `addr` from the slice `buf`. The number of bytes written is the
    /// size of `buf`.
    pub fn write(&mut self, addr: u64, buf: &[u8]) -> Result<usize> {
        self.copy_pages(addr, buf.len(), |host, offset, len| unsafe {
            // SAFETY: `host` is valid for `len` bytes, all in one guest page.
            std::ptr::copy(buf.as_ptr().add(offset), host, len)
        })?;
        Ok(buf.len())
    }

    /// Writes one byte at virtual address `addr`.
    #[inline]
    pub fn write_byte(&mut self, addr: u64, data: u8) -> Result<usize> {
        self.write(addr, &[data])
    }

    /// Writes one word at virtual address `addr`.
    #[inline]
    pub fn write_word(&mut self, addr: u64, data: u16) -> Result<usize> {
        self.write(addr, &data.to_le_bytes())
    }

    /// Writes one dword at virtual address `addr`.
    #[inline]
    pub fn write_dword(&mut self, addr: u64, data: u32) -> Result<usize> {
        self.write(addr, &data.to_le_bytes())
    }

    /// Writes one qword at virtual address `addr`.
    #[inline]
    pub fn write_qword(&mut self, addr: u64, data: u64) -> Result<usize> {
        self.write(addr, &data.to_le_bytes())
    }

    /// Writes a C-string at virtual address `addr`.
    #[inline]
    pub fn write_cstring(&mut self, addr: u64, s: &str) -> Result<usize> {
        for (i, c) in s.chars().enumerate() {
            self.write_byte(addr + i as u64, c as u8)?;
        }
        self.write_byte(addr + s.len() as u64, 0)?;
        Ok(s.len())
    }
}

// -----------------------------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macro_page_round_align() {
        let addr = 0x1234567u64;
        let phys_mask = !(av::PAGE_SIZE as u64 - 1);
        let virt_mask = !(VIRT_PAGE_SIZE as u64 - 1);

        assert_eq!(
            round_phys_page!(addr),
            (addr + av::PAGE_SIZE as u64 - 1) & phys_mask
        );
        assert_eq!(align_phys_page!(addr), addr & phys_mask);
        assert_eq!(
            round_virt_page!(addr),
            (addr + VIRT_PAGE_SIZE as u64 - 1) & virt_mask
        );
        assert_eq!(align_virt_page!(addr), addr & virt_mask);
    }

    // -------------------------------------------------------------------------------------------
    // Guest Page Tables

    #[test]
    fn page_table_table_descriptor() {
        let mut td = TableDescriptor(0);
        td.set_aptable(2);
        assert_eq!(td.0, 2 << 61);
    }
}
