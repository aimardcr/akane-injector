/*
 * akane bootstrap stub. Lives in the controller binary; mem_written into a
 * target-side boot region so any .so injects unmodified. Position-independent:
 * no GOT/PLT/globals; everything reached through the saved_state ptr in x0.
 *
 * It spawns a worker thread to run .init_array (so a blocking constructor
 * can't ANR the host), sets the done flag, restores regs, and branches back
 * to the original pc. The controller detaches (not frees) the region because
 * the worker keeps executing from this same blob.
 *
 * Saved-state buffer (must match the controller):
 *   off 0..240  -> regs[0..30] (x0..x30)
 *   off 248     -> sp
 *   off 256     -> pc
 *   off 264     -> pstate
 *   off 384     -> init_array_addr (0 = none)
 *   off 392     -> init_array_count
 *   off 400     -> pthread_create_addr (target VA, 0 = skip)
 *   off 408     -> tid storage (written by pthread_create)
 *   off 424     -> linker_register_addr (0 = skip)
 *   off 512     -> done flag (bootstrap writes 1; controller polls + detaches)
 *
 * Boot blob layout (one RX page): bootstrap code, then akane_init_runner.
 */

.section .text.akane_bootstrap, "ax"
.balign 16
.global akane_bootstrap_start
.global akane_bootstrap_end
.global akane_init_runner

akane_bootstrap_start:
	// x0 = saved_state ptr
	stp	x29, x30, [sp, #-48]!
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	mov	x29, sp

	mov	x19, x0                         // saved_state ptr

	// Spawn worker thread for init_array iteration:
	//   pthread_create(&tid, NULL, akane_init_runner, &saved_state[384])
	ldr	x9, [x19, #400]                 // pthread_create target VA
	cbz	x9, 2f                          // skip if not provided

	add	x0, x19, #408                   // &tid storage
	mov	x1, #0                          // attr = NULL
	adr	x2, akane_init_runner           // start_routine (PIC)
	add	x3, x19, #384                   // arg = &{init_addr, count}
	blr	x9
2:

	// Restore + resume.
	mov	x0, x19
	ldr	x1, [x0, #256]                  // saved pc
	ldr	x2, [x0, #248]                  // saved sp
	mov	sp, x2

	ldp	x19, x20, [x0, #152]
	ldp	x21, x22, [x0, #168]
	ldp	x23, x24, [x0, #184]
	ldp	x25, x26, [x0, #200]
	ldp	x27, x28, [x0, #216]
	ldp	x29, x30, [x0, #232]

	// Signal completion; controller polls this byte and detaches the region.
	mov	w9, #1
	str	w9, [x0, #512]

	ldr	x0, [x0, #0]

	br	x1

// Worker thread entry. Iterates the .init_array on a fresh thread so
// the hijacked main thread is freed in microseconds.
//   x0 = saved_state + 384  (the worker descriptor)
//        +0   init_array_addr (8B)
//        +8   init_array_count (8B)
//        +16  pthread_create_addr (unused here, bootstrap reads it)
//        +24  tid storage (unused here)
//        +40  linker_register_addr (8B, 0 = skip)
.balign 16
akane_init_runner:
	stp	x29, x30, [sp, #-48]!
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	mov	x29, sp

	// Optional: register payload in solist before init_array, so solist
	// introspectors (Frida) see the gadget during constructors.
	ldr	x9, [x0, #40]                   // linker_register_addr
	cbz	x9, 7f
	mov	x21, x0                         // preserve worker arg
	blr	x9
	mov	x0, x21                         // restore for the loads below
7:

	ldr	x19, [x0, #0]                   // init_array_addr (target VA)
	ldr	x20, [x0, #8]                   // count

	cbz	x19, 5f
	cbz	x20, 5f
	mov	x21, #0
4:
	cmp	x21, x20
	b.ge	5f
	ldr	x9, [x19, x21, lsl #3]
	cbz	x9, 6f
	mov	x0, #0
	mov	x1, #0
	mov	x2, #0
	blr	x9
6:
	add	x21, x21, #1
	b	4b
5:
	mov	x0, #0
	ldp	x21, x22, [sp, #32]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #48
	ret

akane_bootstrap_end:

.section .note.GNU-stack, "", %progbits
