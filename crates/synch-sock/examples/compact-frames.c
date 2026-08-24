/* compact-frames — opt into a smaller contiguous call-frame layout.
 *
 *   synch socket build examples/compact-frames.c -o compact-frames.o
 *   synch socket add code/compact-frames.sock
 *   synch socket arm code/compact-frames.sock
 *   synch connect nas:code/compact-frames.sock
 *
 * Synchronicity normally uses guarded 16 KiB local-call frames. This program's
 * compiler setting and locals fit in 512 bytes, so it asks for smaller frames
 * and explicitly accepts the contiguous layout. A 512-byte frame cannot be
 * guarded because it is not aligned to any supported host page size.
 */

#include <synch.h>

SY_INIT_ENTRY sy_s64 declare(void) {
  sy_declare_name(SY_STR("compact-frames"));
  sy_declare_max_streams(16);

  /* Declaration order is not significant: the runtime validates the complete
     pair after `synchronicity.init` returns. Both lines appear at arm review. */
  if (sy_declare_stack_frame_size(512) < 0) return -1;
  if (sy_declare_guarded_stack_frames(0) < 0) return -2;
  return 0;
}

SY_ENTRY sy_s64 entry(void) {
  sy_s64 n = sy_write_all(SY_SELF, SY_STR("compact frames\n"), 5000);
  if (n < 0) return n;
  sy_shutdown(SY_SELF);
  return 0;
}
