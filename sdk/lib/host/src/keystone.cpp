//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <sys/stat.h>
#include <sys/mman.h>
#include <keystone_user.h>
#include "keystone.h"
#include "elffile.h"
#include "keystone_user.h"
#include "page.h"
#include "hash_util.h"
#include "edge_dispatch.h"
#include "performance.h"
#include <math.h>

#define PAGE_TABLE_PAGES 128
#define MAX_DR_REQUEST_ARGS 8

static int host_fd;

Keystone::Keystone() {
    state = ENCLAVE_STATE_INVALID;
    runtimeFile = NULL;
    enclaveFile = NULL;
    untrusted_size = 0;
    untrusted_start = 0;
    pt_free_list = 0;
    epm_free_list = 0;
    root_page_table = 0;
    start_addr = 0;
    eid = -1;
    new_mem_handler = NULL;
    custom = NULL;
    target_call_id = (unsigned long)-1;

    region_n = 0;
}

Keystone::~Keystone() {
    if(runtimeFile)
        delete runtimeFile;
    if(enclaveFile)
        delete enclaveFile;
    destroy();
    if(custom){
        free(custom); // now assuming that custom is malloced
    }
}

unsigned long calculate_required_pages(
        unsigned long eapp_sz,
        unsigned long rt_sz) {
    unsigned long req_pages = 0;

    req_pages += ceil(eapp_sz / PAGE_SIZE);
    req_pages += ceil(rt_sz / PAGE_SIZE);

    /* FIXME: calculate the required number of pages for the page table.
     * We actually don't know how many page tables the enclave might need,
     * because the SDK never knows how its memory will be aligned.
     * Ideally, this should be managed by the driver.
     * For now, we naively allocate enough pages so that we can temporarily get away from this problem.
     * 15 pages will be more than sufficient to cover several hundreds of megabytes of enclave/runtime. */
    req_pages += PAGE_TABLE_PAGES;
    return req_pages;
}


// set up the vaddr mapping to the shared memory
keystone_status_t Keystone::loadUntrusted() {
    vaddr_t va_start = ROUND_DOWN(untrusted_start, PAGE_BITS);
    vaddr_t va_start_u = ROUND_UP(untrusted_start + (untrusted_size >> 1), PAGE_BITS);
    vaddr_t va_end = ROUND_UP(untrusted_start + untrusted_size, PAGE_BITS);
    // for this untrusted region the physical address is also contiguous
    // as secondary page tables are created in utm_free_list
    while (va_start < va_end) {
        if (allocPage(va_start, utm_free_list, va_start < va_start_u ? UTM_FULL : UTM_FULL_U) == KEYSTONE_ERROR){
            PERROR("failed to add page - allocPage() failed");
        }
        utm_free_list += PAGE_SIZE;
        va_start += PAGE_SIZE;
    }
    return KEYSTONE_SUCCESS;
}

/* This function will be deprecated when we implement freemem */
// FIXME: now the address of the stack is still specified in advanced
// ideally it should also be suggested by the operating system
keystone_status_t Keystone::initStack(vaddr_t start, size_t size, bool is_rt)
{
    //assert(0);
    vaddr_t high_addr = ROUND_UP(start, PAGE_BITS);
    vaddr_t va_start_stk = ROUND_DOWN((high_addr - size), PAGE_BITS);
    int stk_pages = (high_addr - va_start_stk) / PAGE_SIZE;

    for (int i = 0; i < stk_pages; i++) {
        if (allocPage(va_start_stk, epm_free_list, (is_rt ? RT_NOEXEC : USER_NOEXEC)) == KEYSTONE_ERROR)
            return KEYSTONE_ERROR;

        va_start_stk += PAGE_SIZE;
        epm_free_list += PAGE_SIZE;
    }

    return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::allocPage(vaddr_t va, vaddr_t page_addr, unsigned int mode)
{
    pte_t* pte = __ept_walk_create(pMemory, &pt_free_list, (pte_t *) root_page_table, va);

    /* if the page has been already allocated, return the page */
    if(pte_val(*pte) & PTE_V) {
        return KEYSTONE_SUCCESS;
    }

    page_addr = ppn(page_addr);

    /* otherwise, allocate one from EPM freelist */

    switch (mode) {
        case USER_NOEXEC: {
                              *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_U | PTE_V);
                              break;
                          }
        case RT_NOEXEC: {
                            *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_V);
                            break;
                        }
        case RT_FULL: {
                          *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_V);
                          break;
                      }
        case USER_FULL: {
                            *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_U | PTE_V);
                            break;
                        }
        case UTM_FULL: {
                           *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_V);
                           break;
                       }
        case UTM_FULL_U: {
                             *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_V | PTE_U);
                             break;
                         }
        default: {
                     PERROR("failed to add page - mode is invalid");
                     return KEYSTONE_ERROR;
                 }
    }

    return KEYSTONE_SUCCESS;

}


#define R_RISCV_64 2

keystone_status_t Keystone::loadELF(ELFFile* elf, uintptr_t* data_start)
{
    unsigned int mode = elf->getPageMode();
    //unsigned int mode = RT_FULL;

    size_t num_pages = ROUND_DOWN(elf->getTotalMemorySize(), PAGE_BITS) / PAGE_SIZE;
    *data_start = epm_free_list;
    vaddr_t va_real = (vaddr_t)pMemory->ReadMem((vaddr_t)epm_free_list, num_pages << PAGE_BITS);
    vaddr_t va_elf = elf->getMinVaddr();
    memset((void*)va_real, 0, num_pages << PAGE_BITS);

    // get the pages for secondary enclave page table in place first
    // creating all the secondary page tables needed for vaddr starting from va for num_pages
    if (epm_alloc_vspace(pMemory, &pt_free_list, (pte_t *) root_page_table, va_elf, num_pages) != num_pages)
    {
        ERROR("failed to allocate vspace\n");
        return KEYSTONE_ERROR;
    }
    for (unsigned int i = 0; i < elf->getNumProgramHeaders(); i++) {
        if (elf->getProgramHeaderType(i) != PT_LOAD) {
            continue;
        }

        // all va in enclave
        vaddr_t start = elf->getProgramHeaderVaddr(i);
        vaddr_t file_end = start + elf->getProgramHeaderFileSize(i);
        vaddr_t memory_end = start + elf->getProgramHeaderMemorySize(i);
        char* src = (char*) elf->getProgramSegment(i);
        vaddr_t va = start, pa = start - va_elf + epm_free_list;

        // the required pages for second page tables have been allocated in epm_alloc_vspace
        // here it is actually guaranteed that only pages for code and data would be created
        // the paddrs are therefore contiguous
        if(!IS_ALIGNED(va, PAGE_SIZE)) {
            size_t length = PAGE_UP(va) - va;
            if (allocPage(PAGE_DOWN(va), PAGE_DOWN(pa), mode) != KEYSTONE_SUCCESS)
                return KEYSTONE_ERROR;
            va += length;
            pa += length;
        }

        /* first load all pages that do not include .bss segment */
        while (va + PAGE_SIZE <= file_end) {
            if (allocPage(va, pa, mode) != KEYSTONE_SUCCESS)
                return KEYSTONE_ERROR;
            va += PAGE_SIZE;
            pa += PAGE_SIZE;
        }

        /* next, load the page that has both initialized and uninitialized segments */
        if (va < file_end) {
            if (allocPage(va,  pa, mode) != KEYSTONE_SUCCESS)
                return KEYSTONE_ERROR;
            va += PAGE_SIZE;
            pa += PAGE_SIZE;
        }

        /* finally, load the remaining .bss segments */
        while (va < memory_end)
        {
            if (allocPage(va,  pa, mode) != KEYSTONE_SUCCESS)
                return KEYSTONE_ERROR;
            va += PAGE_SIZE;
            pa += PAGE_SIZE;
        }
        if(src != NULL)
            memcpy((void*)(start - va_elf + va_real), src, 
                    elf->getProgramHeaderFileSize(i));
    }
    epm_free_list += num_pages << PAGE_BITS;

    return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::validate_and_hash_enclave(struct runtime_params_t args,
        struct keystone_hash_enclave* cargs){

    hash_ctx_t hash_ctx;
    int ptlevel = RISCV_PGLEVEL_TOP;

    hash_init(&hash_ctx);

    // hash the runtime parameters
    hash_extend(&hash_ctx, &args, sizeof(struct runtime_params_t));


    uintptr_t runtime_max_seen=0;
    uintptr_t user_max_seen=0;

    // hash the epm contents including the virtual addresses
    int valid = validate_and_hash_epm(&hash_ctx,
            ptlevel,
            (pte_t*) root_page_table,
            0, 0, cargs, &runtime_max_seen, &user_max_seen, fd);

    if(valid == -1){
        return KEYSTONE_ERROR;
    }

    hash_finalize(hash, &hash_ctx);

    return KEYSTONE_SUCCESS;
}

bool Keystone::initFiles(const char* eapppath, const char* runtimepath)
{
    if (runtimeFile || enclaveFile) {
        ERROR("ELF files already initialized");
        return false;
    }

    runtimeFile = new ELFFile(runtimepath);
    enclaveFile = new ELFFile(eapppath);

    if(!runtimeFile->initialize(true)) {
        ERROR("Invalid runtime ELF\n");
        destroy();
        return false;
    }

    if(!enclaveFile->initialize(false)) {
        ERROR("Invalid enclave ELF\n");
        destroy();
        return false;
    }

    if (!runtimeFile->isValid()) {
        ERROR("runtime file is not valid");
        destroy();
        return false;
    }
    if (!enclaveFile->isValid()) {
        ERROR("enclave file is not valid");
        destroy();
        return false;
    }

    return true;
}

bool Keystone::initDevice()
{
    if (!params.isSimulated()) {
        /* open device driver */
        fd = open(KEYSTONE_DEV_PATH, O_RDWR);
        if (fd < 0) {
            PERROR("cannot open device file");
            return false;
        }
    }
    return true;
}

bool Keystone::prepareEnclave(struct keystone_ioctl_create_enclave* enclp,
        uintptr_t alternate_phys_addr)
{
    enclp->params.untrusted_ptr = (unsigned long) params.getUntrustedMem();
    enclp->params.untrusted_size = (unsigned long) params.getUntrustedSize();

    enclp->params.runtime_entry = (unsigned long) runtimeFile->getEntryPoint();
    enclp->params.user_entry = (unsigned long) enclaveFile->getEntryPoint();
    enclp->runtime_vaddr = (unsigned long) runtimeFile->getMinVaddr();
    enclp->user_vaddr = (unsigned long) enclaveFile->getMinVaddr();

    // FIXME: this will be deprecated with complete freemem support.
    // We just add freemem size for now.
    enclp->min_pages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS)/PAGE_SIZE;
    enclp->min_pages += calculate_required_pages(enclaveFile->getTotalMemorySize(),
            runtimeFile->getTotalMemorySize()); // here pages for the page table are also counted
    // in addition to those for the runtime and the application


    // for now the vaddrs are
    // 1. seperate: the runtime and the user take separate vaddr regions
    // 2. preset in the executable files

    untrusted_size = params.getUntrustedSize();
    untrusted_start = params.getUntrustedMem();

    if (params.isSimulated()) {
        eid = -1; // simulated
        pMemory->init(0, 0);
        root_page_table = pMemory->AllocMem(PAGE_SIZE * enclp->min_pages);
        start_addr = root_page_table;
        pt_free_list = start_addr + PAGE_SIZE; // pages for secondary page tables
        epm_free_list = start_addr + PAGE_SIZE * PAGE_TABLE_PAGES;
        return true;
    }

    /* Pass in pages to map to enclave here. */

    /* Call Keystone Driver */
    int ret = ioctl(fd, KEYSTONE_IOC_CREATE_ENCLAVE, enclp);
    // what this ioctl does:
    // 1. enclave id assigning
    // 2. enclave physical memory allocation
    // 3. set up in params
    //	pt_ptr (paddr of page table, also the paddr of the epm physical memory region)
    //	epm_size (size of enclave protected memory)
    // 4. initialise the epm
    //	allocate the physical memory and zero it

    if (ret) {
        ERROR("failed to create enclave - ioctl() failed: %d", ret);
        return false;
    }

    /* We switch out the phys addr as needed */

    uintptr_t starting_phys_range;
    if(alternate_phys_addr){
        starting_phys_range = alternate_phys_addr;
    }
    else{
        starting_phys_range = enclp->pt_ptr;
    }

    pMemory->init(fd, starting_phys_range);
    eid = enclp->eid;
    start_addr = starting_phys_range;
    root_page_table = pMemory->AllocMem(PAGE_SIZE * PAGE_TABLE_PAGES); 
    // this only maps the first page (root page table) to the process virtual memory space
    epm_free_list = starting_phys_range + PAGE_SIZE * PAGE_TABLE_PAGES; // paddr of the next available page in epm
    pt_free_list = start_addr + PAGE_SIZE; // pages for secondary page tables
    return true;
}

keystone_status_t Keystone::init(const char *eapppath, const char *runtimepath, Params _params){
    return this->init(eapppath, runtimepath, _params, (uintptr_t)0);
}

keystone_status_t Keystone::init(const char *eapppath, const char *runtimepath, Params _params, uintptr_t alternate_phys_addr)
{
    params = _params;

    if (params.isSimulated()) {
        pMemory = new SimulatedEnclaveMemory();
    } else {
        pMemory = new PhysicalEnclaveMemory();
    }

    if(!initFiles(eapppath, runtimepath)) {
        return KEYSTONE_ERROR;
    }

    if(!initDevice()) {
        destroy();
        return KEYSTONE_ERROR;
    }

    struct keystone_ioctl_create_enclave enclp;
    if(!prepareEnclave(&enclp, alternate_phys_addr)) {
        destroy();
        return KEYSTONE_ERROR;
    }

    //Map root page table to user space
    struct keystone_hash_enclave hash_enclave;

    uintptr_t data_start;


    if(loadELF(runtimeFile, &data_start) != KEYSTONE_SUCCESS) {
        ERROR("failed to load runtime ELF");
        destroy();
        return KEYSTONE_ERROR;
    }
    hash_enclave.runtime_paddr = epm_free_list;
    enclp.runtime_paddr = (data_start - start_addr) + enclp.pt_ptr; // physical starting address for the runtime

    if(loadELF(enclaveFile, &data_start) != KEYSTONE_SUCCESS) {
        ERROR("failed to load enclave ELF");
        destroy();
        return KEYSTONE_ERROR;
    }
    hash_enclave.user_paddr = epm_free_list;
    enclp.user_paddr = (data_start - start_addr) + enclp.pt_ptr;


    /* initialize stack. If not using freemem */
#ifndef USE_FREEMEM
    if( initStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0) != KEYSTONE_SUCCESS){
        ERROR("failed to init static stack");
        destroy();
        return KEYSTONE_ERROR;
    }
#endif /* USE_FREEMEM */
    if(params.isSimulated()) {
        utm_free_list = pMemory->AllocMem(enclp.params.untrusted_size);
        hash_enclave.free_paddr = (epm_free_list - start_addr) + enclp.pt_ptr;
        hash_enclave.utm_paddr = utm_free_list;

        loadUntrusted();
    } else {
        int ret;
        ret = ioctl(fd, KEYSTONE_IOC_UTM_INIT, &enclp);
        // set up the utm, allocate the physical memory
        // based on params:
        //	untrusted_size
        // returns utm_free_ptr which is the physical address of the utm region
        if (ret) {
            ERROR("failed to init untrusted memory - ioctl() failed: %d", ret);
            destroy();
            return KEYSTONE_ERROR;
        }
        utm_free_list = enclp.utm_free_ptr;

        if (mapUntrusted(params.getUntrustedSize()))
        {
            ERROR("failed to finalize enclave - cannot obtain the untrusted buffer pointer \n");
            destroy();
            return KEYSTONE_ERROR;
        }
        loadUntrusted();
        enclp.params.untrusted_ptr = untrusted_start;
    }

    enclp.free_paddr = (epm_free_list - start_addr) + enclp.pt_ptr;
    if(params.isSimulated()) {
        hash_enclave.utm_size = params.getUntrustedSize();
        hash_enclave.epm_size = PAGE_SIZE * enclp.min_pages;
        hash_enclave.epm_paddr = root_page_table;
        hash_enclave.untrusted_ptr = enclp.params.untrusted_ptr;
        hash_enclave.untrusted_size = enclp.params.untrusted_size;

        validate_and_hash_enclave(enclp.params, &hash_enclave);
        printHash(hash);
    } else {
        int ret;
        // SM: set up PMP, doing measurement
        // is_init of enclave is set to false (which will change the semantics of mmap)
        ret = ioctl(fd, KEYSTONE_IOC_FINALIZE_ENCLAVE, &enclp);

        if (ret) {
            ERROR("failed to finalize enclave - ioctl() failed: %d", ret);
            destroy();
            return KEYSTONE_ERROR;
        }
    }

    /* ELF files are no longer needed */
    delete enclaveFile;
    delete runtimeFile;
    enclaveFile = NULL;
    runtimeFile = NULL;

    performance_stats_init(&run_stats);

    futex_initialised = false;

    state = ENCLAVE_STATE_INITIALISED;


    return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::mapUntrusted(size_t size)
{
    if (size == 0) {
        return KEYSTONE_SUCCESS;
    }

    shared_buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    memset((void*)shared_buffer, 0, size);
    // here updated mmap interface: to map untrusted memory it is necessary to use an offset >= trusted_size

    if (shared_buffer == NULL) {
        return KEYSTONE_ERROR;
    }

    untrusted_start = (vaddr_t)shared_buffer; // the virtual address should be the same inside the enclave

    shared_buffer_size = size >> 1;

    // for enclave call
    o_shared_buffer = (void*)((uintptr_t)shared_buffer + shared_buffer_size);
    o_shared_buffer_size = shared_buffer_size;

    return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::destroy()
{
    /* if the enclave has ever created, we destroy it. */
    if(eid >= 0)
    {
        struct keystone_ioctl_create_enclave enclp;
        enclp.eid = eid;
        int ret = ioctl(fd, KEYSTONE_IOC_DESTROY_ENCLAVE, &enclp);

        if (ret) {
            ERROR("failed to destroy enclave - ioctl() failed: %d", ret);
            return KEYSTONE_ERROR;
        }
    }

    if(enclaveFile) {
        delete enclaveFile;
        enclaveFile = NULL;
    }

    if(runtimeFile) {
        delete runtimeFile;
        runtimeFile = NULL;
    }

    return KEYSTONE_SUCCESS;
}

void Keystone::process_new_memory_region(uintptr_t size){
    void* vaddr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(new_mem_handler)
        new_mem_handler(vaddr);
}

keystone_status_t Keystone::runOnce(int* ret_code){
    int ret;

    if(state == ENCLAVE_STATE_INITIALISED){
        run_args.eid = eid;
        run_args.dr_request_resp0 = 0;
        run_args.dr_request_resp1 = 0;
        run_args.dr_request_args = (__u64)dr_request_args;

        performance_check_start(&run_stats);
        ret = ioctl(fd, KEYSTONE_IOC_RUN_ENCLAVE, &run_args);
        performance_check_end(&run_stats);
        performance_count(&run_stats);
    } else if(state == ENCLAVE_STATE_LAUNCHED){
        performance_check_start(&run_stats);
        ret = ioctl(fd, KEYSTONE_IOC_RESUME_ENCLAVE, &run_args);
        performance_check_end(&run_stats);
        performance_count(&run_stats);
    } else if(state == ENCLAVE_STATE_BLOCKED){
        if(ocall_dispatcher != NULL){
            int cont = !ocall_dispatcher->dispatchBlocked(this, getSharedBuffer());
            if(!cont)
                return KEYSTONE_SUCCESS;
            state = ENCLAVE_STATE_LAUNCHED;
            performance_check_start(&run_stats);
            ret = ioctl(fd, KEYSTONE_IOC_RESUME_ENCLAVE, &run_args);
            performance_check_end(&run_stats);
            performance_count(&run_stats);
        } else
            return KEYSTONE_SUCCESS;
    } else{
        return KEYSTONE_ERROR;
    }

    state = ENCLAVE_STATE_LAUNCHED;

    int cont;
    while(ret){
        cont = 0;
        switch(ret){
            case KEYSTONE_ENCLAVE_EDGE_CALL_HOST:
                if(ocall_dispatcher != NULL){
                    cont = !ocall_dispatcher->dispatch(this, getSharedBuffer()); // TODO: cont decided by the dispatch function
                    if(!cont){ // need to block until future
                        state = ENCLAVE_STATE_BLOCKED;
                    }
                } else
                    cont = 1;
                break;
            case KEYSTONE_ENCLAVE_CALL_RETURN:
            case KEYSTONE_ENCLAVE_INTERRUPTED:
            case KEYSTONE_ENCLAVE_YIELDED:
                cont = 0;
                break;
            case KEYSTONE_ENCLAVE_NEW_MEM_REGION:
                process_new_memory_region(dr_request_args[0]);
                cont = 1;
                break;
            default:
                destroy();
                ERROR("failed to run enclave - ioctl() failed: %d", ret);
                return KEYSTONE_ERROR;
        }
        if(!cont)
            break;
        performance_check_start(&run_stats);
        ret = ioctl(fd, KEYSTONE_IOC_RESUME_ENCLAVE, &run_args);
        performance_check_end(&run_stats);
        performance_count(&run_stats);
    }

    if(!ret)
        state = ENCLAVE_STATE_ENDED;

    *ret_code = ret;
    return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::run()
{
    int ret;
    if (params.isSimulated()) {
        return KEYSTONE_SUCCESS;
    }

    do{
        if(runOnce(&ret) != KEYSTONE_SUCCESS)
            return KEYSTONE_ERROR;
    } while(ret);

    return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::call(unsigned long call_id, void* data, size_t data_len, void* return_buffer, size_t return_len){
    return call_with_stats(call_id, data, data_len, return_buffer, return_len, &ecall_stats);
}

// enclave call
keystone_status_t Keystone::call_with_stats(unsigned long call_id, void* data, size_t data_len, void* return_buffer, size_t return_len, struct ecall_stats* stats)
{
    if(params.isSimulated())
        return KEYSTONE_ERROR;

    struct shared_region shared_region;
    shared_region.shared_start = (uintptr_t)o_shared_buffer;
    shared_region.shared_len = o_shared_buffer_size;
    void* shared_buffer = o_shared_buffer;
    size_t shared_buffer_size = o_shared_buffer_size;



    int ret;
    struct edge_call* edge_call = (struct edge_call*)shared_buffer;
    uintptr_t buffer_data_start = edge_call_data_ptr(&shared_region);

    if(data_len > (shared_buffer_size - (buffer_data_start - (uintptr_t)shared_buffer))){
        return KEYSTONE_ERROR;
    }

    if(call_id == target_call_id)
        performance_check_start(&stats->args_copy_stats);
    memcpy((void*)buffer_data_start, (void*)data, data_len);
    if(call_id == target_call_id){
        performance_check_end(&stats->args_copy_stats);
        performance_count(&stats->args_copy_stats);
        performance_count_data(&stats->args_copy_stats, data_len);
    }

    if(edge_call_setup_call(edge_call, (void*)buffer_data_start, data_len, &shared_region) != 0){
        return KEYSTONE_ERROR;
    }


    edge_call->call_id = call_id; // only finally set the call_id
    do{
        if(runOnce(&ret) != KEYSTONE_SUCCESS){
            return KEYSTONE_ERROR;
        }
    } while(ret && ret != KEYSTONE_ENCLAVE_CALL_RETURN);


    if(!ret){
        return KEYSTONE_ERROR;
    }

    if(edge_call->return_data.call_status != CALL_STATUS_OK){
        return KEYSTONE_ERROR;
    }

    if( return_len == 0 ){
        /* Done, no return */
        return KEYSTONE_SUCCESS;
    }

    uintptr_t return_ptr;
    size_t ret_len_untrusted;
    if(edge_call_ret_ptr(edge_call, &return_ptr, &ret_len_untrusted, &shared_region) != 0){
        return KEYSTONE_ERROR;
    }

    if(ret_len_untrusted < return_len)
        return_len = ret_len_untrusted;

    if(call_id == target_call_id)
        performance_check_start(&stats->retval_copy_stats);
    memcpy(return_buffer, (void*)return_ptr, return_len);
    if(call_id == target_call_id){
        performance_check_end(&stats->retval_copy_stats);
        performance_count(&stats->retval_copy_stats);
        performance_count_data(&stats->retval_copy_stats, return_len);
    }

    return KEYSTONE_SUCCESS;
}

void *Keystone::getSharedBuffer() {
    return shared_buffer;
}

size_t Keystone::getSharedBufferSize() {
    return shared_buffer_size;
}

enum enclave_state Keystone::getState() const{
    return state;
}

keystone_status_t Keystone::registerOcallDispatch(EdgeCallDispatcher* dispatcher) {
    dispatcher->setupSharedRegion((uintptr_t)shared_buffer, shared_buffer_size);
    ocall_dispatcher = dispatcher;
    return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::registerNewMemHandler(NewMemHandler handler){
    new_mem_handler = handler;
    return KEYSTONE_SUCCESS;
}

int Keystone::getSID() const{
    int ret= ioctl(fd, KEYSTONE_IOC_GET_ENCLAVE_ID, &eid);
    return ret;
}

keystone_status_t EnclaveGroup::run(){
    int i, ret;
    bool cont = true;
    while(cont){
        cont = false;
        for(i = 0; i < enclave_n; i ++){
            if(enclaves[i]->getState() != ENCLAVE_STATE_ENDED &&
                    enclaves[i]->getState() != ENCLAVE_STATE_INVALID){
                cont = true;
                enclaves[i]->runOnce(&ret);
            }
        }
    }
    return KEYSTONE_SUCCESS;
}


uid_t elasticlave_create(size_t size){
    uid_t uid;
    struct keystone_ioctl_elasticlave_create params = {
        .size = size,
        .uid = &uid
    };
    int ret = ioctl(host_fd, KEYSTONE_IOC_ELASTICLAVE_CREATE, &params);
    if(ret == -1)
        return 0;
    return uid;
}

int elasticlave_change(uid_t uid, unsigned long perm){
    struct keystone_ioctl_elasticlave_change params = {
        .uid = (__u64)uid,
        .perm = (__u64)perm
    };
    return ioctl(host_fd, KEYSTONE_IOC_ELASTICLAVE_CHANGE, &params);
}

int elasticlave_destroy(uid_t uid){
    return ioctl(host_fd, KEYSTONE_IOC_ELASTICLAVE_DESTROY, &uid);
}

void* elasticlave_map(uid_t uid){
    uintptr_t size;
    struct keystone_ioctl_elasticlave_map params = {
        .uid = uid,
        .size = (__u64)&size
    };
    int ret = ioctl(host_fd, KEYSTONE_IOC_ELASTICLAVE_MAP, &params);
    if(ret == -1)
        return NULL;
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, host_fd, 0);
}

int elasticlave_unmap(void* vaddr){
    uintptr_t size;
    struct keystone_ioctl_elasticlave_unmap params = {
        .vaddr = (__u64)vaddr,
        .size = (__u64)&size
    };
    int ret = ioctl(host_fd, KEYSTONE_IOC_ELASTICLAVE_UNMAP, &params);
    if(ret)
        return ret;
    return munmap(vaddr, size);
}

void Keystone::set_target_call(unsigned long target){
    target_call_id = target;
}

void Keystone::print_call_stats(){
    print_ecall_stats(&ecall_stats);
}

bool keystone_init(){
    host_fd = open(KEYSTONE_DEV_PATH, O_RDWR);
    if (host_fd < 0) {
        PERROR("cannot open device file");
        return false;
    }
    return true;
}

int Keystone::print_sm_stats(struct enclave_stats* stats){
    struct keystone_ioctl_sm_stats ioc_data;
    ioc_data.eid = eid;
    ioc_data.stats = stats;
    int ret = ioctl(fd, KEYSTONE_IOC_SM_PRINT_STATS, &ioc_data);
    return ret;
}

int Keystone::print_rt_stats(struct enclave_rt_stats* rt_stats){
    struct keystone_ioctl_rt_stats ioc_data;
    ioc_data.eid = eid;
    ioc_data.rt_stats = rt_stats;
    int ret = ioctl(fd, KEYSTONE_IOC_SM_PRINT_RT_STATS, &ioc_data);
    return ret;
}

struct performance_stats Keystone::get_run_stats() const{
    return run_stats;
}

keystone_status_t Keystone::elasticlave_transfer(uid_t uid){
    struct keystone_ioctl_elasticlave_transfer params = {
        .uid = uid,
        .eid = (__u64)this->eid
    };
    int ret = ioctl(fd, KEYSTONE_IOC_ELASTICLAVE_TRANSFER, &params);
    return ret ? KEYSTONE_ERROR : KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::elasticlave_share(uid_t uid, unsigned long perm){
    struct keystone_ioctl_elasticlave_share params = {
        .uid = uid,
        .perm = (__u64)perm,
        .eid = (__u64)this->eid
    };
    int ret = ioctl(fd, KEYSTONE_IOC_ELASTICLAVE_SHARE, &params);
    return ret ? KEYSTONE_ERROR : KEYSTONE_SUCCESS;
}

void* Keystone::get_region_buffer(uid_t uid) const{
    int i;
    for(i = 0; i < region_n; i ++){
        if(region_uids[i] == uid)
            return region_bufs[i];
    }
    return NULL;
}

void Keystone::add_region_buffer(uid_t uid, void* buf){
    region_uids[region_n] = uid;
    region_bufs[region_n] = buf;
    ++ region_n;
}

