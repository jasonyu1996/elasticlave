#ifndef __KEYSTONE_H_STRING
#define __KEYSTONE_H_STRING

#include <stddef.h>
#include <stdint.h>
#include <ctype.h>


#ifdef __cplusplus
extern "C"{
#endif

static void* ks_memcpy(void* dest, const void* src, size_t len)
{
  const char* s = (const char*)src;
  char *d = (char*)dest;

  if ((((uintptr_t)dest | (uintptr_t)src) & (sizeof(uintptr_t)-1)) == 0) {
    while ((void*)d < (dest + len - (sizeof(uintptr_t)-1))) {
      *(uintptr_t*)d = *(const uintptr_t*)s;
      d += sizeof(uintptr_t);
      s += sizeof(uintptr_t);
    }
  }

  while (d < (char*)(dest + len))
    *d++ = *s++;

  return dest;
}

static size_t ks_strlen(char* str){
  size_t len = 0;
  while(*str != '\0'){
    str++;
    len++;
  }

  return len;
}

static void* ks_memset(void* dest, int byte, size_t len)
{
  if ((((uintptr_t)dest | len) & (sizeof(uintptr_t)-1)) == 0) {
    uintptr_t word = byte & 0xFF;
    word |= word << 8;
    word |= word << 16;
    word |= word << 16 << 16;

    uintptr_t *d = (uintptr_t*)dest;
    while (d < (uintptr_t*)(dest + len))
      *d++ = word;
  } else {
    char *d = (char*)dest;
    while (d < (char*)(dest + len))
      *d++ = byte;
  }
  return dest;
}

static int ks_memcmp(const void* s1, const void* s2, size_t n)
{
  unsigned char u1, u2;

  for ( ; n-- ; s1++, s2++) {
    u1 = * (unsigned char *) s1;
    u2 = * (unsigned char *) s2;
    if ( u1 != u2) {
      return (u1-u2);
    }
  }
  return 0;
}
//TODO this is from Linux src, needs licence

/**
 * memmove - Copy one area of memory to another
 * @dest: Where to copy to
 * @src: Where to copy from
 * @count: The size of the area.
 * 
 * Unlike memcpy(), memmove() copes with overlapping areas.
 */
static void *ks_memmove(void *dest, const void *src, size_t count)
{
  char *tmp;
  const char *s;

  if (dest <= src) {
    tmp = (char*)dest;
    s = (const char*)src;
    while (count--)
      *tmp++ = *s++;
  } else {
    tmp = (char*)dest;
    tmp += count;
    s = (const char*)src;
    s += count;
    while (count--)
      *--tmp = *--s;
  }
  return dest;
}

static char* ks_strbuilds(char* dest, char* s){
	size_t len = ks_strlen(s);
	ks_memcpy((void*)dest, s, len);
	return dest + len;
}

static char* ks_strbuildi(char* dest, unsigned long n){
	if(n >= 10)
		dest = ks_strbuildi(dest, n / 10);
	*dest = (char)(n % 10 + '0');
	return dest + 1;
}

#ifdef __cplusplus
}
#endif

#endif
