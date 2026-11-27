# gom: Game on-another Machine

gom lets you play native Linux games you don't fully trust, at full speed, as if they were
running on another computer. The game can't see your files, can't touch the internet, and
can't spy on your desktop.

I made it for the
[Native Linux Games Collection](https://archive.org/details/native-linux-games-collection)
on archive.org. It's a great archive, but you are downloading old binaries and installers from
strangers, and you have no idea what's inside them. The same goes for games from itch.io, random
forums, old CDs and so on. gom is for exactly that kind of game.

Before gom I used a QEMU/KVM virtual machine for this. It was safe, but slow: I lost about
35–55% FPS in normal scenes, I had to wait for boot every time, and games with `.sh` launchers
(Java games like Project Zomboid, for example) didn't work at all. gom starts in under a second
and runs at native speed.

## Quick start

```sh
git clone https://github.com/merthium/gom
cd gom && make
ln -s "$PWD/bin/gom" ~/.local/bin/gom

gom --selftest                          # check that the sandbox really works on your machine
gom ~/Games/Dusk/game/DUSK.x86_64       # run a game binary
gom ~/Games/Zomboid/game                # or a folder: gom finds start.sh / *.sh / the binary
```

More options:

```sh
gom -w -r 1280x720 GAME     # windowed, 720p
gom -g GAME                 # always lock the mouse (good for shooters)
gom -m GAME                 # no sound
gom -e SDL_AUDIODRIVER=pulse GAME   # set an environment variable for the game (repeatable)
gom --shell GAME            # open a shell in the same sandbox the game gets
gom --keep-compositor GAME  # leave picom running (by default it is paused during the game)
gom --list                  # show profiles (saves and settings)
gom --launchers DIR         # what gom would start in DIR (exit 3: you must pick, 4: nothing)
gom --reset NAME            # delete a profile
```

In the game window, `Super+F` toggles fullscreen and `Super+G` toggles the keyboard grab.

### Installers

Self-extracting installers (GOG/MojoSetup `.sh`, makeself, YAD installers from repacks) run
inside the sandbox like a game. They install into the profile's private home, which they see as
`/home/player`. When the installer closes, gom prints where the game landed and how to start it:

```sh
gom ~/Games/Foo/foo-installer.sh                # install; pick /home/player as the target
gom ~/.local/share/gom/Foo/home/Foo             # play: runs in the same profile, no overlay
```

Nothing from the installer ever touches your real home.

### shelf: a window instead of a terminal

[shelf](https://github.com/bedeaf/shelf) is a game library for gom: cover art, play time, an
archive.org browser that installs games without running anything, and one-click start into
gom's sandbox. I'm lazy and didn't want a terminal just to play games, so I made it.

![shelf](https://raw.githubusercontent.com/bedeaf/shelf/main/art/shelf-library.png)

### What you need

Linux with Landlock turned on (most kernels from 6.x have it), `bubblewrap` 0.8 or newer,
`gamescope`, `xauth`, `gcc` and `make`. For sound you also need `pulseaudio`, `pacat` and
`python3`. I use it on Void Linux with X11, PulseAudio and an Intel iGPU. Other setups should
work too, but I haven't tested them, so please run `gom --selftest` first.

## How it works

Every time you start a game, gom builds three small sandboxes with bubblewrap. They are
separate from each other, and none of them can see your home folder.

1. **Display sandbox:** runs gamescope with its own private X server (Xwayland). This is the
   only part that is allowed to talk to your real X server, and it only uses it to show one
   window.
2. **Audio sandbox:** runs a private PulseAudio with no sound card and no microphone. It has no
   connection to your real sound server either. It just writes raw sound into a pipe, and a
   small `pacat` outside reads the pipe and plays it.
3. **Game sandbox:** this is where the game runs. It can only see:
   - `/usr` (read-only) and a fake `/etc` with a fake user, hostname and machine-id
   - the game folder, through an overlay. The game *thinks* it can change its own files, but
     every change goes into the profile, and the original folder stays exactly as it was
   - its own private home folder, which is where saves and settings end up
   - the GPU render node, so it stays fast

On top of the sandbox, every program is started through `gom-lock`, a small C helper. It turns
on `no_new_privs`, Landlock and a seccomp filter, and sets some limits (no core dumps, a maximum
number of processes). If any of these steps fails, the game is not started at all.

Saves live in `~/.local/share/gom/NAME/home/`. Files the game wrote into its own folder are in
`~/.local/share/gom/NAME/layer/`.

## What it protects you from

`gom --selftest` runs a fake "evil game" inside the sandbox. It tries all the usual tricks, and
then gom checks from the outside that nothing got through. On my machine all 90 attacks inside
and all 11 checks outside pass. Some examples:

| The malware wants to... | What happens |
|---|---|
| steal SSH keys, browser passwords, Discord tokens, crypto wallets | your home folder simply doesn't exist inside |
| send your data to a server, or download more malware | there is no network, only `lo` |
| log your keys or take screenshots of your desktop | it only sees gamescope's private display, not yours |
| read your clipboard | the private display doesn't get your clipboard (tested) |
| listen to your microphone | the private sound server has no microphone and no sound card |
| use the sound server to get out | the audio sandbox has no link to the real one, only a pipe |
| stay on your PC (autostart, `.bashrc`, changing system files) | writes go to the profile only; `/usr` is read-only |
| become root with sudo or setuid programs | `no_new_privs`, and all capabilities are dropped |
| use common kernel exploit tricks | seccomp blocks user namespaces, `io_uring`, `bpf`, `userfaultfd`, `ptrace`, `mount`, kernel modules and odd socket types, also through the 32-bit and x32 entry points |
| type commands into your terminal | blocked (`TIOCSTI`) |
| use a file handle that leaked in from outside | gom closes its own handles before starting a sandbox (tested) |
| crash your PC with a fork bomb | the process limit stops it |

## What it does NOT protect you from

I want to be honest here. No sandbox is perfect, and gom isn't either. What's left would need a
real exploit, not ordinary malware:

- **A bug in the kernel or the GPU driver.** A game needs the GPU to be fast, so the GPU driver
  is always reachable. A virtual machine helps only a little here (it still uses your GPU through
  virglrenderer) and costs a lot of FPS. Keep your kernel and Mesa up to date.
- **Two bugs chained together through the display.** If a game breaks Xwayland or gamescope
  first, it gets the display sandbox, and that sandbox is connected to your real X server. X11
  doesn't isolate programs from each other, so at that point keylogging would be possible. I
  tried giving gamescope an "untrusted" X cookie, and I also tried putting it inside Xephyr, but
  gamescope can't show anything in either case. If you want to close this hole too, play on a
  separate TTY with gamescope's DRM backend, without any X server.
- **Code running inside the sandbox.** A game is native code, and engines like Java or Mono need
  JIT memory, so gom can't stop a game from running extra code of its own, even programs it
  drops into `/tmp` (installers rely on that). It can only make sure that code stays inside the
  sandbox.
- CPU side-channel attacks (Spectre and friends), or a game that is "evil" in a harmless way,
  for example it ruins its own saves or uses a lot of CPU.
- `--direct-x` turns off the display sandbox. Only use it for games you trust anyway.

## Speed

Same OpenGL benchmark, 1080p fullscreen, Intel Iris Xe:

| Test | Normal desktop | gom | Old QEMU/virgl VM |
|---|---|---|---|
| 4000 draw calls per frame | 542 fps | **648 fps** | 247 fps |
| 1000 draw calls per frame | 1016 fps | **1499 fps** | 670 fps |
| heavy pixel shader | 66.5 fps | **64.8 fps** | 63.4 fps |
| 720k triangles | 197 fps | **198 fps** | 162 fps |
| 1080p texture upload every frame | 750 fps | **1115 fps** | 339 fps |

Yes, gom is sometimes faster than the normal desktop. gamescope just skips frames that would
never reach the screen, while the normal X server and compositor copy every single one.

## Settings

| Variable | What it does | Default |
|---|---|---|
| `GOM_GAMESCOPE_ARGS` | extra gamescope flags, for example `-F fsr` | none |
| `GOM_AUDIO_LATENCY_MS` | audio buffer size | 30 |
| `GOM_NPROC` | max processes and threads for the game | 4096 |
| `GOM_KEEP_COMPOSITOR` | `1` leaves picom (or another X compositor) running during games | off |

While a game runs, gom stops the X compositor of that display (picom, compton, xcompmgr…) and
starts it again with the same command line when the last game ends. On X with the modesetting
driver, which has no TearFree, compositing gamescope's window tore badly; only no compositor at
all gave clean frames, even compared with picom's own per-window unredirect.

## Files

```
bin/gom                    the main script (bash)
src/lock.c                 gom-lock: no_new_privs + Landlock + seccomp + limits, then runs the program
src/denied-syscalls.txt    blocked syscalls (numbers come from your kernel headers)
src/gen-syscalls.sh        turns the list above into build/syscalls.h
tests/attack.c             the fake evil game used by --selftest
```

`make check` runs shellcheck and the self-test.

## Disclaimer

This is a hobby project that I made for myself and share because it might be useful to someone.
It makes running untrusted games a lot safer, but it can't make it 100% safe, and nothing can.
I am not responsible for anything that happens to your computer, your files or your accounts
because you used gom: malware, data loss, broken saves, or anything else. You use it at your own
risk. If you need real security, don't run software you don't trust, or use a separate machine.
The software is provided "as is", without any warranty (see [LICENSE](LICENSE)).
