//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __LOADER_H__
#define __LOADER_H__

#include <string>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include "common.h"
#include "elf.h"
#include "keystone_user.h"

class ELFFile
{
  public:
    ELFFile(std::string filename);
    ~ELFFile();
    size_t getFileSize() { return fileSize; }
    bool isValid();

    vaddr_t getMinVaddr() { return minVaddr; }
    size_t getTotalMemorySize() { return maxVaddr - minVaddr; }
    bool initialize(bool isRuntime);

    unsigned int getPageMode() { return (isRuntime ? RT_FULL : USER_FULL); }

    /* libelf wrapper function */
    size_t getNumProgramHeaders(void);
    size_t getProgramHeaderType(size_t ph);
    size_t getProgramHeaderFileSize(size_t ph);
    size_t getProgramHeaderMemorySize(size_t ph);
    vaddr_t getProgramHeaderVaddr(size_t ph);
    vaddr_t getEntryPoint();
    void* getProgramSegment(size_t ph);
	const char* getSectionName(size_t sh);
	size_t getNumSections(void);
	void* getSection(size_t sh);
	size_t getSectionSize(size_t sh);
	size_t getSectionLink(size_t sh);
	unsigned int getSectionType(size_t sh);
	uintptr_t getSectionAddr(size_t sh);

  private:
    int filep;

    /* virtual addresses */
    vaddr_t minVaddr;
    vaddr_t maxVaddr;

    void* ptr;
    size_t fileSize;

    /* is this runtime binary */
    bool isRuntime;

    /* libelf structure */
    elf_t elf;
};

#endif /* loader */
