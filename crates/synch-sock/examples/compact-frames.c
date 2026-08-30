/* compact-frames — opt into a smaller contiguous call-frame layout.
 *
 *   synch socket build examples/compact-frames.c -o compact-frames.o
 *   cp compact-frames.o ~/synchronicity/code/compact-frames.sock
 *   synch socket declare code/compact-frames.sock
 *   synch socket arm code/compact-frames.sock
 *   synch socket connect nas:code/compact-frames.sock
 *
 * Synchronicity normally uses guarded 16 KiB local-call frames. This program's
 * compiler setting and locals fit in 512 bytes, so it asks for smaller frames
 * and explicitly accepts the contiguous layout. A 512-byte frame cannot be
 * guarded because it is not aligned to any supported host page size.
 */

#include <synch.h>

/* The stack shape is declared beside everything else the program claims: one
   JSON document, validated whole when the file is inspected or served. */
SY_MANIFEST("{\"manifest\":1,\"name\":\"compact-frames\","
            "\"max_streams\":16,"
            "\"stack_frame_size\":512,\"guarded_stack_frames\":false}");

SY_ENTRY sy_s64 entry(void) {
  sy_s64 n = sy_write_all(SY_SELF, SY_STR("compact frames\n"), 5000);
  if (n < 0) return n;
  sy_shutdown(SY_SELF);
  return 0;
}
