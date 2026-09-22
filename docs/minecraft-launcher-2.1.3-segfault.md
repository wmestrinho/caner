# Minecraft Launcher 2.1.3 — bootstrapper SIGSEGV on button activation

**Status: analysed here, NOT filed upstream.** Investigated from a
systemd-coredump core dump on 2026-09-21. A submission packet was prepared for
<https://report.bugs.mojang.com> (project **Minecraft: Launcher**, key `MCL`),
but filing was abandoned on 2026-09-22: since Mojang's Feb-2025 migration both
filing *and* duplicate search require a Microsoft sign-in, and the portal was
too unreliable to complete the form. Verified that day: anonymous
`rest/api/3/project/search` returns `total: 0`, `project/MCL` returns 404, and
`search/jql` returns an empty set because it is unauthorised — not because there
are no matches. **So this has not been checked for duplicates either.**

If anyone picks this up, the ready-to-paste packet is on Seat 3 at
`~/Work/minecraft-launcher-2.1.3-MOJIRA-SUBMISSION.md` and
`~/Work/mojira-description.txt`. Treat the analysis below as sound and the
upstream status as unknown.

---

## Summary

    Launcher bootstrapper segfaults on button activation: "clicked" handler reads
    user_data from the wrong argument register (NULL call through GObjectClass)

**Affects version:** Native Launcher 2.1.3 (`Running launcher bootstrap (version 2.1.3)`)

## Environment

    OS:        Arch Linux (Omarchy), kernel 7.2.5-3-omarchy, x86_64
    Session:   Hyprland / Wayland (GDK Wayland backend, not XWayland)
    GTK:       gtk3 (Arch), glib2/gobject 2.x
    Binary:    /usr/bin/minecraft-launcher, stripped, PIE
               BuildID[sha1] 437da748feca84c0aac35184c9b112f8fabe13cd
    Package:   Arch AUR minecraft-launcher 1:2.1.3-3 (repackages the official
               Mojang tarball; the binary itself is unmodified Mojang code, and
               the version string above comes from your own bootstrap log)

## What happens

On a first run, the bootstrapper opens its self-update progress window and begins
downloading the launcher. If a button in that window has keyboard focus and is
activated — I hit it with keypad Enter — the process dies instantly with SIGSEGV
on a call to address 0.

    kernel: minecraft-launc[601240]: segfault at 0 ip 0000000000000000
            sp 00007b6ed7ffd9a8 error 14

## Stack at the fault

Symbolized against Arch debuginfod; your frames are unresolved because the binary
is stripped.

    #0  0x0000000000000000
    #1  minecraft-launcher + 0x6565a
    #2  minecraft-launcher + 0x4a2ac
    #3  _g_closure_invoke_va               gobject/gclosure.c:980
    #4  signal_emit_valist_unlocked        gobject/gsignal.c:3465   signal_id=216 ("clicked")
    #7  gtk_button_clicked                 gtk/gtkbutton.c:1541
    #8  gtk_button_finish_activate         gtk/gtkbutton.c:2042
    #9  gtk_button_key_release             gtk/gtkbutton.c:1871
    #16 gtk_window_propagate_key_event     gtk/gtkwindow.c:8264
    #17 gtk_window_key_release_event       gtk/gtkwindow.c:8315
    #23 gtk_main_do_event
    #26 gdk_event_source_dispatch          gdk/wayland/gdkeventsource.c:124
    #31 gtk_main

## Root cause

The closure attached to `clicked` is:

    GCClosure {
      marshal  = g_cclosure_marshal_VOID__VOID
      data     = 0x57c435ba2470
      callback = 0x57c43204a2a0        (minecraft-launcher + 0x4a2a0)
    }

Your handler at `+0x4a2a0` is nine instructions:

    +0x4a2a0:  push   %rbx
    +0x4a2a1:  mov    %rdx,%rdi          <-- takes its object from RDX (3rd argument)
    +0x4a2a4:  mov    %rdx,%rbx
    +0x4a2a7:  call   +0x65650
    +0x4a2ac:  mov    %rbx,%rdi
    +0x4a2af:  call   +0x65730
    +0x4a2b4:  pop    %rbx
    +0x4a2b5:  movzbl %al,%eax           <-- returns a gboolean
    +0x4a2b8:  ret

    +0x65650:  mov    (%rdi),%rax        ; load vptr
    +0x65653:  push   %rbx
    +0x65654:  mov    %rdi,%rbx
    +0x65657:  call   *0x40(%rax)        ; virtual call -- FAULTS HERE
    +0x6565a:  mov    %al,0x28(%rbx)

`clicked` is a two-argument, void-returning signal: `void (GtkButton*, gpointer
user_data)`. GLib's `g_cclosure_marshal_VOID__VOIDv` passes `data1` in RDI and
`data2` in RSI, and **never writes RDX** — it tail-jumps to the callback with RDX
still holding the `instance` argument it received:

    g_cclosure_marshal_VOID__VOIDv:
        mov    %rdi,%rax
        mov    0x10(%rdi),%rdi
        testb  $0x20,0x3(%rax)
        mov    %rdi,%rcx
        cmove  %rdx,%rdi
        cmovne %rdx,%rcx
        mov    %rcx,%rsi
        ...
        jmp    *%r8                      ; RDX never touched

So the handler takes the **GtkButton** as its `this`. Registers at the fault
confirm it:

    rdi = rdx = rbx = 0x7b6ed00ab9a0    the GtkButton instance
    rsi = rcx       = 0x57c435ba2470    the closure's actual user_data
    rax             = 0x7b6ed00fe6e0    *(GtkButton) -- the GtkButtonClass

`*(GtkButton)` is the GObject class pointer, not a C++ vtable. Offset `0x40` into
it lands on `GObjectClass::notify`, which GtkButton does not override:

    +0x10 constructor    0x7b6efa77c810  (libgobject)
    +0x18 set_property   0x7b6efa0ba010  (libgtk)
    +0x20 get_property   0x7b6efa0b9d60
    +0x28 dispose        0x7b6efa0b8100
    +0x30 finalize       0x7b6efa0b5930
    +0x38 dispatch_properties_changed
    +0x40 notify         0x0000000000000000   <-- called this
    +0x48 constructed    0x7b6efa0b9870

Hence the jump to 0.

The `user_data` it should have used is a valid object — vptr `0x57c4324c6280`, and
slot `+0x40` there holds `minecraft-launcher + 0x4bd10`, a real function.
**Reading RSI instead of RDX would have worked.**

The `gboolean` return at `+0x4a2b5` is the other tell: this function is written
with the three-argument GTK *event handler* signature, `gboolean f(GtkWidget*,
GdkEvent*, gpointer self)`, where `self` legitimately arrives in RDX — but it is
connected to `clicked`, where it does not.

**Suggested fix:** give the handler the signature `clicked` actually has —
`void f(GtkButton*, gpointer user_data)` — or connect it to the event signal it
was written for.

## Steps to reproduce

1. Install the launcher fresh (no `~/.minecraft`).
2. Start it. The bootstrapper's update window appears and begins downloading.
3. Without clicking anything first, press keypad Enter (Return or Space should
   also work — GtkButton binds all three to `activate`). The focused widget is a
   button in that window, reported elsewhere as "Cancel".
4. The process segfaults immediately.

The triggering event, recovered from the core:

    GdkEventKey { type = GDK_KEY_RELEASE, keyval = 0xff8d (KP_Enter),
                  hardware_keycode = 104, state = 0 }

**Expected:** the button does whatever it's meant to do.

**Actual:** SIGSEGV, no error dialog, no log entry. The last line in
`bootstrap_log.txt` is just the in-flight download.

## Notes

- The focused widget is definitely a `GtkButton` inside a `GtkWindow` (both type
  names read out of the core), but the binary is stripped and I could not recover
  its label from this dump. A separate occurrence of the same crash, on the same
  launcher version, identified it as the update window's **"Cancel"** button; I did
  not verify that label myself, so treat it as corroboration rather than as
  something established here. Consistent with it: the function adjacent to the
  handler calls `gtk_progress_bar_get_type`, which fits the update window.
- I could not check whether a mouse click reproduces it, but since the fault is in
  the `clicked` handler itself, it very likely does.
- Ruled out: no OOM (swap had headroom), no third-party libraries in the address
  space (all loaded objects are stock distribution `/usr/lib`), and no recent GTK
  update.

---

*Filed by Claude Opus 5 via Claude Code.*
