#!/usr/bin/env python3
"""Tests for bin/shelf that need no display: library, covers, gom integration, command line.
Run: python3 tests/shelf_test.py   (make check runs it too)"""

import fcntl
import importlib.machinery
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
TMP = tempfile.mkdtemp(prefix="shelf-test-")
os.environ["XDG_DATA_HOME"] = os.path.join(TMP, "data")
os.environ["GOM"] = os.path.join(ROOT, "bin", "gom")
os.environ["SHELF_OFFLINE"] = "1"

loader = importlib.machinery.SourceFileLoader("shelf", os.path.join(ROOT, "bin", "shelf"))
spec = importlib.util.spec_from_loader("shelf", loader)
shelf = importlib.util.module_from_spec(spec)
loader.exec_module(shelf)

from gi.repository import GdkPixbuf  # noqa: E402


def mkdir(*parts):
    p = os.path.join(TMP, *parts)
    os.makedirs(p, exist_ok=True)
    return p


def put_elf(path):
    shutil.copy("/bin/true", path)
    os.chmod(path, 0o755)


def put_script(path, body="echo hi\n"):
    with open(path, "w") as f:
        f.write("#!/bin/sh\n" + body)
    os.chmod(path, 0o755)


def png(path, w, h, alpha=False):
    pb = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, alpha, 8, w, h)
    pb.fill(0xd0d0d0ff if not alpha else 0xd0d0d080)
    pb.savev(path, "png", [], [])


def png_header_only(path, w, h):
    """A PNG that claims to be w x h but has no pixel data: enough for the header check."""
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    chunk = b"IHDR" + ihdr
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + chunk
                + struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF))


class Names(unittest.TestCase):
    def test_profile_like_gom(self):
        self.assertEqual(shelf.derive_profile(mkdir("g1", "Dusk", "game")), "Dusk")
        self.assertEqual(shelf.derive_profile(mkdir("g1", "Başka Oyun")), "Ba__ka_Oyun")
        self.assertEqual(shelf.derive_profile(mkdir("g1", ".hidden")), "hidden")
        inside = mkdir("data", "gom", "Prof", "home", "Installed", "bin")
        self.assertEqual(shelf.derive_profile(inside), "Prof")

    def test_profile_matches_gom_dry_run(self):
        d = mkdir("g2", "Çılgın Oyun")
        put_elf(os.path.join(d, "run"))
        r = subprocess.run([os.environ["GOM"], "--dry-run", os.path.join(d, "run")],
                           capture_output=True, text=True, timeout=60, check=False)
        if r.returncode != 0:
            self.skipTest("gom --dry-run does not work here: " + r.stderr.strip()[-200:])
        self.assertIn("/gom/%s/" % shelf.derive_profile(d), r.stdout + r.stderr)

    def test_titles(self):
        self.assertEqual(shelf.clean_title("ULTRAKILL (v.17d4) [Unity3D] [Goldberg].sh"), "ULTRAKILL")
        self.assertEqual(shelf.clean_title("DUSK_[Linux,_GOG]"), "DUSK")
        self.assertEqual(shelf.clean_title("Some.Game.Name"), "Some Game Name")
        self.assertEqual(shelf.clean_title("Half-Life 2"), "Half-Life 2")
        self.assertEqual(shelf.title_from_path(mkdir("g3", "Zomboid", "game")), "Zomboid")

    def test_sort_key(self):
        titles = ["Doom 10", "The Doom 2", "doom 2a", "Alpha"]
        self.assertEqual(sorted(titles, key=shelf.sort_key), ["Alpha", "The Doom 2", "doom 2a", "Doom 10"])

    def test_formatting(self):
        self.assertEqual(shelf.fmt_duration(30), "under a minute")
        self.assertEqual(shelf.fmt_duration(25 * 60), "25 min")
        self.assertEqual(shelf.fmt_duration(3 * 3600), "3 h")
        self.assertEqual(shelf.fmt_duration(int(3.5 * 3600)), "3.5 h")
        self.assertEqual(shelf.fmt_long_duration(12 * 3600 + 30 * 60), "12 h 30 min")
        self.assertEqual(shelf.fmt_when(time.time()), "today")
        self.assertEqual(shelf.fmt_when(time.time() - 86400), "yesterday")

    def test_env_and_tags(self):
        self.assertEqual(shelf.parse_env("A=1 'B=two words'"), ["A=1", "B=two words"])
        with self.assertRaises(ValueError):
            shelf.parse_env("1BAD=x")
        self.assertEqual(shelf.parse_tags("fps, FPS ,  co-op,,"), ["fps", "co-op"])

    def test_sanitize(self):
        self.assertEqual(shelf.sanitize("\x1b[31mred\x1b[0m\r\nok\x07\x1b]0;title\x07"), "red\nok")

    def test_similar(self):
        self.assertEqual(shelf.similar("Postal 2", "POSTAL"), 0.0)
        self.assertEqual(shelf.similar("Unreal Tournament 2004", "Unreal Tournament 2003"), 0.0)
        self.assertEqual(shelf.similar("Dusk", "DUSK"), 1.0)
        self.assertGreater(shelf.similar("Quake III Arena", "Quake III: Arena"), 0.88)


class Covers(unittest.TestCase):
    def test_portrait_is_cropped(self):
        src = os.path.join(TMP, "tall.png")
        png(src, 300, 600, alpha=True)
        name = shelf.import_cover(src, "x1", untrusted=True)
        pb = GdkPixbuf.Pixbuf.new_from_file(os.path.join(shelf.COVERS, name))
        self.assertEqual((pb.get_width(), pb.get_height()), (shelf.COVER_W, shelf.COVER_H))
        self.assertFalse(pb.get_has_alpha())
        self.assertTrue(name.endswith(".jpg"))

    def test_wide_is_letterboxed(self):
        src = os.path.join(TMP, "wide.png")
        png(src, 800, 200)
        pb = GdkPixbuf.Pixbuf.new_from_file(os.path.join(shelf.COVERS, shelf.import_cover(src, "x2")))
        px = pb.get_pixels()
        stride, mid = pb.get_rowstride(), shelf.COVER_H // 2
        self.assertLess(px[0], 16)                              # black bar on top
        self.assertGreater(px[mid * stride + 300 * 3], 150)     # picture in the middle

    def test_untrusted_formats_and_bombs(self):
        bmp = os.path.join(TMP, "x.bmp")
        GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, False, 8, 20, 20).savev(bmp, "bmp", [], [])
        with self.assertRaises(ValueError):
            shelf.import_cover(bmp, "x3", untrusted=True)
        shelf.import_cover(bmp, "x3", untrusted=False)          # fine when you pick it yourself
        bomb = os.path.join(TMP, "bomb.png")
        png_header_only(bomb, 20000, 20000)
        with self.assertRaises(ValueError):
            shelf.import_cover(bomb, "x4", untrusted=True)


class LibraryTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TMP, "lib-%d.json" % time.time_ns())

    def test_two_writers_keep_both_changes(self):
        a = shelf.Library(self.path)
        with a.edit():
            gid = a.add({"title": "T", "path": "/x"})["id"]
        b = shelf.Library(self.path)                 # e.g. `shelf --run` in a terminal
        a.update(gid, favorite=True)
        b.update(gid, playtime=60)                   # b's copy is stale; it must reload first
        a.reload()
        self.assertEqual((a.get(gid)["favorite"], a.get(gid)["playtime"]), (True, 60))

    def test_broken_file_is_kept(self):
        with open(self.path, "w") as f:
            f.write("{not json")
        lib = shelf.Library(self.path)
        self.assertEqual(lib.games, [])
        self.assertIn("could not be read", lib.warning)
        self.assertTrue([n for n in os.listdir(TMP) if n.startswith(os.path.basename(self.path) + ".broken-")])

    def test_history_survives_removal(self):
        lib = shelf.Library(self.path)
        with lib.edit():
            gid = lib.add({"title": "Old", "path": "/games/Old", "archive": "old-item"})["id"]
        lib.update(gid, playtime=3600, sessions=4, last_played=111)
        with lib.edit():
            lib.delete(gid)
        again = shelf.Library(self.path)            # what is on disk, not just in memory
        self.assertEqual(again.history["archive:old-item"]["playtime"], 3600)
        self.assertIn("removed", again.history["archive:old-item"])
        with again.edit():
            g = again.add({"title": "Old", "path": "/elsewhere/Old", "archive": "old-item"})
        self.assertEqual((g["playtime"], g["sessions"], g["last_played"]), (3600, 4, 111))
        self.assertNotIn("removed", again.history["archive:old-item"])
        with again.edit():
            h = again.add({"title": "Other", "path": "/games/Other"})
        self.assertNotIn("playtime", h)

    def test_bad_entries_are_skipped(self):
        with open(self.path, "w") as f:
            json.dump({"games": [{"id": "a", "title": "ok", "path": "/p"}, {"id": 5}, "junk"]}, f)
        self.assertEqual([g["id"] for g in shelf.Library(self.path).games], ["a"])

    def test_find(self):
        lib = shelf.Library(self.path)
        with lib.edit():
            for t in ("Dusk", "Dusk World", "Zomboid"):
                lib.add({"title": t, "path": "/x"})
        self.assertEqual([g["title"] for g in lib.find("dusk")], ["Dusk"])
        self.assertEqual([g["title"] for g in lib.find("zom")], ["Zomboid"])
        self.assertEqual(len(lib.find("u")), 2)

    def test_book_run(self):
        g = {"session": {"start": 1}}
        shelf.book_run(g, 100, 100 + 3600, True, 0)
        self.assertEqual((g["playtime"], g["sessions"], g["last_error"], g["session"]), (3600, 1, None, None))
        shelf.book_run(g, 0, 3, True, 1)
        self.assertIn("quit after 3 s", g["last_error"])
        self.assertEqual(g["sessions"], 2)
        shelf.book_run(g, 0, 2, True, 143)           # stopped by shelf: not an error
        self.assertIsNone(g["last_error"])
        shelf.book_run(g, 0, 1, False, 3, "several launchers in /x")
        self.assertEqual((g["last_error"], g["playtime"]), ("several launchers in /x", 3605))


class GomTests(unittest.TestCase):
    gom = os.environ["GOM"]

    def test_parse_run_log(self):
        r = shelf.parse_run_log("gom: warning: x\ngom: running 'a.sh' as profile 'P' (log: l)\n"
                                "gom: new game folder in the private home: /d/home/Game\n"
                                "gom: error: boom\n")
        self.assertEqual((r["started"], r["errors"], r["installed"]), (True, ["boom"], ["/d/home/Game"]))

    def test_launchers(self):
        one, two, none = mkdir("l", "One", "game"), mkdir("l", "Two"), mkdir("l", "None")
        put_elf(os.path.join(one, "One.x86_64"))
        put_elf(os.path.join(one, "OneWorld.x86_64"))
        put_elf(os.path.join(two, "alpha"))
        put_elf(os.path.join(two, "beta"))
        self.assertEqual(shelf.gom_launchers(self.gom, one), ("ok", ["One.x86_64", "OneWorld.x86_64"]))
        self.assertEqual(shelf.gom_launchers(self.gom, two)[0], "choose")
        self.assertEqual(shelf.gom_launchers(self.gom, none), ("none", []))

    def test_find_game_and_scan(self):
        root = mkdir("scan")
        put_elf(os.path.join(mkdir("scan", "Deep", "game"), "Deep.x86_64"))
        put_script(os.path.join(mkdir("scan", "Inst"), "inst-setup.sh"))
        mkdir("scan", "Empty")
        put_script(os.path.join(root, "loose.sh"))
        self.assertEqual(shelf.find_game(self.gom, os.path.join(root, "Deep"))[0],
                         os.path.join(root, "Deep", "game"))
        prof = mkdir("data", "gom", "Remembered")
        target = mkdir("elsewhere", "Rem")
        put_elf(os.path.join(target, "rem"))
        with open(os.path.join(prof, "game.path"), "w") as f:
            f.write(os.path.join(target, "rem") + "\n")
        found, skipped, loose = shelf.scan_games(self.gom, root, {os.path.join(root, "Inst"): "Inst"})
        titles = sorted(c["title"] for c in found)
        self.assertEqual(titles, ["Deep", "Remembered"])
        self.assertEqual((skipped, loose), (1, 1))
        dropped, _s, _l = shelf.scan_games(self.gom, None, {}, [os.path.join(root, "Deep")])
        self.assertEqual([c["path"] for c in dropped], [os.path.join(root, "Deep", "game")])
        rem = next(c for c in found if c["title"] == "Remembered")
        self.assertEqual(rem["profile"], "Remembered")

    def test_installed_game_beats_its_installer(self):
        both = mkdir("inst", "Both")
        with open(os.path.join(both, "game_1_2_345.sh"), "wb") as f:
            f.write(b"#!/bin/sh\n" + b"\0" * (2 << 20))
        put_elf(os.path.join(mkdir("inst", "Both", "game"), "Both.x86_64"))
        self.assertEqual(shelf.find_game(self.gom, both)[0], os.path.join(both, "game"))
        only = mkdir("inst", "Only")
        shutil.copy(os.path.join(both, "game_1_2_345.sh"), os.path.join(only, "setup.sh"))
        path, note = shelf.find_game(self.gom, only)
        self.assertEqual(path, os.path.join(only, "setup.sh"))
        self.assertIn("installer", note)
        found, skipped, _l = shelf.scan_games(self.gom, os.path.join(TMP, "inst"),
                                              {os.path.join(both, "game"): "Both"})
        from_folder = [c["title"] for c in found if not c["note"].startswith("from gom profile")]
        self.assertEqual((from_folder, skipped), (["Only"], 1))

    def test_64_bit_folder_first(self):
        root = mkdir("arch", "Retro")
        for d in ("drmfree.i386", "drmfree.x86_64"):
            put_elf(os.path.join(mkdir("arch", "Retro", d), "retro"))
        self.assertEqual(shelf.find_game(self.gom, root)[0], os.path.join(root, "drmfree.x86_64"))

    def test_profile_lock_seen_without_touching_it(self):
        prof = mkdir("data", "gom", "Locked")
        lock = os.path.join(prof, ".lock")
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT, 0o600)
        self.assertFalse(shelf.profile_running("Locked", shelf.held_locks()))
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.assertTrue(shelf.profile_running("Locked", shelf.held_locks()))
        os.close(fd)
        self.assertFalse(shelf.profile_running("Locked", shelf.held_locks()))

    def test_icon(self):
        pb = shelf.shelf_icon(64)
        self.assertEqual((pb.get_width(), pb.get_height()), (64, 64))
        a = shelf.make_shelf(shelf.ICON)
        self.assertEqual(a, shelf.make_shelf(dict(shelf.ICON)))      # same seed, same shelf
        self.assertNotEqual(a, shelf.make_shelf(dict(shelf.ICON, seed=7)))
        lean, nb = a[-1], a[-2]
        # the leaner's face touches its neighbour's top corner
        foot = lean["pts"][0]
        touch_x = foot[0] - nb["h"] * __import__("math").tan(lean["th"])
        self.assertAlmostEqual(touch_x, nb["pts"][1][0], places=9)

    def test_missing_libraries(self):
        if not shutil.which("gcc"):
            self.skipTest("no gcc")
        game = mkdir("deps", "Game")
        lib = mkdir("deps", "Game", "lib")
        src = os.path.join(TMP, "foo.c")
        with open(src, "w") as f:
            f.write("int foo(void){return 1;}\n")
        so = os.path.join(lib, "libfoo-1.2.so")          # file name differs from its soname
        subprocess.run(["gcc", "-shared", "-fPIC", "-Wl,-soname,libfoo.so.1", "-o", so, src], check=True)
        main = os.path.join(TMP, "main.c")
        with open(main, "w") as f:
            f.write("int foo(void); int main(void){return foo();}\n")
        subprocess.run(["gcc", "-o", os.path.join(game, "game"), main, so], check=True)
        # an orphan plugin that needs something absent: nothing loads it, so it must not count
        plug = os.path.join(TMP, "plug.c")
        with open(plug, "w") as f:
            f.write("int bar(void); int baz(void){return bar();}\n")
        bar = os.path.join(TMP, "libbar.so")
        subprocess.run(["gcc", "-shared", "-fPIC", "-Wl,-soname,libbar.so.7", "-o", bar, src], check=True)
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", os.path.join(lib, "plugin.so"), plug, bar], check=True)
        self.assertEqual(shelf.missing_libs(game), {})
        os.unlink(so)
        self.assertEqual(shelf.missing_libs(game), {("libfoo.so.1", 64): ["game"]})
        self.assertEqual(shelf.elf_needs(os.path.join(game, "game"))[:2], (64, ["libfoo.so.1", "libc.so.6"]))
        self.assertIsNone(shelf.elf_needs(src))

    def test_install_commands_per_distribution(self):
        owners = {"libopenal.so.1": {"void": "libopenal", "debian": "libopenal1", "arch": "openal",
                                     "fedora": "openal-soft", "opensuse": "libopenal1", "gentoo": "media-libs/openal"},
                  "libpulse.so.0": {"void": "libpulseaudio", "debian": "libpulse0", "arch": "libpulse",
                                    "fedora": "pulseaudio-libs", "opensuse": "libpulse0",
                                    "gentoo": "media-libs/libpulse"}}
        owner = lambda fam, lib: owners.get(lib, {}).get(fam)     # noqa: E731
        miss = {("libopenal.so.1", 32): ["runner"]}
        expect = {"void": "xbps-install -S libopenal-32bit libpulseaudio-32bit",
                  "debian": "apt install libopenal1:i386 libpulse0:i386",
                  "arch": "pacman -S --needed lib32-openal lib32-libpulse",
                  "fedora": "dnf install openal-soft.i686 pulseaudio-libs.i686",
                  "opensuse": "zypper install libopenal1-32bit libpulse0-32bit",
                  "gentoo": "emerge --ask 'media-libs/openal[abi_x86_32]' 'media-libs/libpulse[abi_x86_32]'"}
        for fam, tail in expect.items():
            cmd = shelf.install_hint(miss, family=fam, owner=owner, have={})
            self.assertTrue(cmd.endswith(tail), (fam, cmd))
        self.assertIn("dpkg --add-architecture i386", shelf.install_hint(miss, "debian", owner, {}))
        self.assertNotIn("libpulse", shelf.install_hint(miss, "arch", owner, {"libpulse.so.0": {32}}))
        self.assertIsNone(shelf.install_hint(miss, None, owner, {}) if shelf.distro()[0] is None else None)

    def test_game_log_diagnosis(self):
        d = shelf.diagnose_game_log
        self.assertIn("libopenal.so.1", d("./runner: error while loading shared libraries: libopenal.so.1: "
                                          "cannot open shared object file: No such file or directory"))
        self.assertIn("'zenity'", d("./start.sh: line 4: zenity: command not found"))
        self.assertIsNone(d("all fine\n"))

    def test_command(self):
        g = {"path": "/g", "profile": "P", "windowed": True, "res": "1280x720", "grab": True,
             "mute": True, "env": ["A=1 2"], "args": "-x 'y z'"}
        self.assertEqual(shelf.gom_command("gom", g),
                         ["gom", "-w", "-r", "1280x720", "-g", "-m", "-e", "A=1 2", "-n", "P", "/g",
                          "--", "-x", "y z"])
        self.assertEqual(shelf.gom_environ({"gamescope": "-F fsr"})["GOM_GAMESCOPE_ARGS"], "-F fsr")


class Archive(unittest.TestCase):
    def test_titles_and_payloads(self):
        self.assertEqual(shelf.ia_title("Trine 2: Complete Story (v2.01 build 425) [Linux, GOG, Archive]"),
                         ("Trine 2: Complete Story", "v2.01 build 425", ["GOG", "Archive"]))
        self.assertEqual(shelf.ia_title("Samorost 2 + Bonus [Linux, Ruffle]")[0], "Samorost 2 + Bonus")
        files = [{"name": "Games/gta.tar.xz", "size": "1290", "source": "original", "md5": "a"},
                 {"name": "Games/old/gta-old.tar.xz", "size": "1300", "source": "original"},
                 {"name": "Games/hq.7z", "size": "10", "source": "original"},
                 {"name": "Images/logo_GTA.jpg", "size": "5", "source": "original"},
                 {"name": "x.tar.xz", "size": "9", "source": "derivative"}]
        c = shelf.payload_candidates(files)
        self.assertEqual([f["name"] for f in c], ["Games/gta.tar.xz", "Games/hq.7z"])
        self.assertEqual(shelf.pick_payload(c)["name"], "Games/gta.tar.xz")
        self.assertIsNone(shelf.pick_payload([{"size": 100}, {"size": 90}]))
        self.assertEqual(shelf.logo_file(files), "Images/logo_GTA.jpg")
        self.assertEqual(shelf.strip_html("<p>Hi&amp;<b>there</b></p><script>x</script>"), "Hi& there")

    def make_tree(self, root):
        os.makedirs(os.path.join(root, "Game", "game"), exist_ok=True)
        put_elf(os.path.join(root, "Game", "game", "Game.x86_64"))
        put_script(os.path.join(root, "Game", "uninstall.sh"))

    def test_yad_installer(self):
        src = mkdir("yad-src")
        self.make_tree(src)
        tarzst = os.path.join(TMP, "payload.tar.zst")
        subprocess.run("tar -C %s -cf - Game | zstd -q -o %s" % (src, tarzst), shell=True, check=True)
        arcsz = os.path.getsize(tarzst)
        inst = os.path.join(TMP, "Game [LinuxRuleZ!].sh")
        with open(inst, "wb") as f, open(tarzst, "rb") as p:
            f.write(b"#!/bin/bash\n# YAD Simple Installer script\nappsz=1\narcsz=%d\nexit 0\n" % arcsz)
            f.write(b"\0" * 5000 + p.read())
        self.assertEqual(shelf.yad_payload_size(inst), arcsz)
        dest = mkdir("yad-out")
        self.assertEqual(shelf.unpack(inst, dest, lambda: False), ("yad", 0))
        shelf.flatten(dest)
        self.assertTrue(os.access(os.path.join(dest, "game", "Game.x86_64"), os.X_OK))
        self.assertEqual(shelf.find_game(os.environ["GOM"], dest)[0], os.path.join(dest, "game"))

    def test_gog_installer(self):
        inst = os.path.join(TMP, "gog_game_1_2.sh")
        with open(inst, "wb") as f:
            f.write(b"#!/bin/sh\n# Makeself with mojosetup\nexit 0\n" + b"x" * 100)
        with zipfile.ZipFile(inst, "a") as z:
            info = zipfile.ZipInfo("data/noarch/game/run.sh")
            info.external_attr = 0o755 << 16
            z.writestr(info, "#!/bin/sh\n")
            z.writestr("data/noarch/start.sh", "#!/bin/sh\n")
            z.writestr("scripts/evil.sh", "rm -rf ~\n")
        dest = mkdir("gog-out")
        self.assertEqual(shelf.unpack(inst, dest, lambda: False), ("gog", 0))
        self.assertEqual(os.listdir(dest), ["run.sh"])
        self.assertTrue(os.access(os.path.join(dest, "run.sh"), os.X_OK))

    def test_hostile_tar_stays_inside(self):
        import io
        import tarfile
        path = os.path.join(TMP, "evil.tar.xz")
        with tarfile.open(path, "w:xz") as t:
            def add(name, data=b"x", **kw):
                ti = tarfile.TarInfo(name)
                for k, v in kw.items():
                    setattr(ti, k, v)
                ti.size = len(data) if ti.type == tarfile.REGTYPE else 0
                t.addfile(ti, io.BytesIO(data) if ti.type == tarfile.REGTYPE else None)
            add("ok/file.txt")
            add("../escape.txt")
            add("/tmp/shelf-abs-escape.txt")
            add("ok/link", type=tarfile.SYMTYPE, linkname="../../../../etc/passwd")
            add("ok/suid", mode=0o4755)
        dest = mkdir("tar-out")
        kind, skipped = shelf.unpack(path, dest, lambda: False)
        self.assertEqual(kind, "tar")
        self.assertGreaterEqual(skipped, 2)
        self.assertTrue(os.path.isfile(os.path.join(dest, "ok", "file.txt")))
        self.assertFalse(os.path.exists(os.path.join(TMP, "escape.txt")))
        self.assertFalse(os.path.exists("/tmp/shelf-abs-escape.txt"))
        self.assertFalse(os.path.lexists(os.path.join(dest, "ok", "link")))
        self.assertFalse(os.stat(os.path.join(dest, "ok", "suid")).st_mode & 0o4000)

    def test_tar_hard_links(self):
        src = mkdir("hl-src", "G")
        put_elf(os.path.join(src, "a"))
        os.link(os.path.join(src, "a"), os.path.join(src, "b"))
        arc = os.path.join(TMP, "hl.tar.gz")
        subprocess.run(["tar", "-C", os.path.dirname(src), "-czf", arc, "G"], check=True)
        dest = mkdir("hl-out")
        self.assertEqual(shelf.unpack(arc, dest, lambda: False), ("tar", 0))
        self.assertTrue(os.access(os.path.join(dest, "G", "b"), os.X_OK))

    def test_7z(self):
        if not shutil.which("7z"):
            self.skipTest("no 7z")
        src = mkdir("7z-src")
        self.make_tree(src)
        arc = os.path.join(TMP, "g.7z")
        subprocess.run(["7z", "a", "-bd", arc, os.path.join(src, "Game")], capture_output=True, check=True)
        dest = mkdir("7z-out")
        self.assertEqual(shelf.unpack(arc, dest, lambda: False)[0], "7z")
        self.assertTrue(os.path.isfile(os.path.join(dest, "Game", "game", "Game.x86_64")))

    def test_download_checks_md5(self):
        import hashlib
        src = os.path.join(TMP, "dl-src.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(300000))
        good = hashlib.md5(open(src, "rb").read()).hexdigest()
        part = os.path.join(TMP, "dl.part")
        shelf.download("file://" + src, part, 300000, good, lambda *a: None, lambda: False)
        self.assertEqual(os.path.getsize(part), 300000)
        os.unlink(part)
        with self.assertRaises(ValueError):
            shelf.download("file://" + src, part, 300000, "0" * 32, lambda *a: None, lambda: False)
        self.assertFalse(os.path.exists(part))

    def test_download_resumes_after_a_dropped_connection(self):
        import hashlib
        import http.server
        import threading
        data = os.urandom(400000)
        seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                rng = self.headers.get("Range")
                seen.append(rng)
                start = int(rng[6:-1]) if rng else 0
                body = data[start:]
                self.send_response(206 if rng else 200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not rng:
                    self.wfile.write(body[:150000])      # then hang up mid-file
                    self.wfile.flush()
                    self.connection.shutdown(2)
                    return
                self.wfile.write(body)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        part = os.path.join(TMP, "resume.part")
        orig = shelf.time.sleep
        shelf.time.sleep = lambda s: None                # no back-off waits in the test
        try:
            shelf.download("http://127.0.0.1:%d/f" % srv.server_port, part, len(data),
                           hashlib.md5(data).hexdigest(), lambda *a: None, lambda: False)
        finally:
            shelf.time.sleep = orig
            srv.shutdown()
        self.assertEqual(open(part, "rb").read(), data)
        self.assertEqual(seen, [None, "bytes=150000-"])

    def test_install_end_to_end(self):
        src = mkdir("e2e-src")
        self.make_tree(src)
        arc = os.path.join(TMP, "e2e.tar.gz")
        subprocess.run(["tar", "-C", src, "-czf", arc, "Game"], check=True)
        games = mkdir("e2e-games")
        orig = shelf.ia_file_url
        shelf.ia_file_url = lambda ident, name: "file://" + arc
        try:
            path, kind, note = shelf.install_archive_item(
                {"id": "x", "title": "Cool: Game"}, {"name": "e2e.tar.gz", "size": os.path.getsize(arc),
                                                     "md5": ""},
                games, os.environ["GOM"], lambda *a: None, lambda: False)
        finally:
            shelf.ia_file_url = orig
        self.assertEqual(path, os.path.join(games, "Cool - Game", "game"))
        self.assertEqual(sorted(os.listdir(games)), ["Cool - Game"])     # no .downloads left behind
        self.assertEqual(shelf.folder_name("Cool: Game", games), "Cool - Game (2)")


class CommandLine(unittest.TestCase):
    def run_shelf(self, *args, gom_body):
        fake = os.path.join(TMP, "fakegom-%d" % time.time_ns())
        put_script(fake, gom_body)
        env = dict(os.environ, GOM=fake)
        return subprocess.run([sys.executable, os.path.join(ROOT, "bin", "shelf"), *args],
                              capture_output=True, text=True, env=env, timeout=30, check=False)

    def test_run_counts_play_time_and_errors(self):
        game = mkdir("cli", "Game")
        put_elf(os.path.join(game, "game"))
        lib = shelf.Library()
        with lib.edit():
            gid = lib.add({"title": "Cli Game", "path": os.path.join(game, "game"), "profile": "CliGame"})["id"]
        ok = self.run_shelf("--run", "cli game", gom_body=(
            "echo \"gom: running 'game' as profile 'CliGame' (log: x)\" >&2\nsleep 1\nexit 0\n"))
        self.assertEqual(ok.returncode, 0, ok.stderr)
        lib.reload()
        g = lib.get(gid)
        self.assertEqual((g["sessions"], g["session"], g["last_error"]), (1, None, None))
        self.assertGreaterEqual(g["playtime"], 1)
        bad = self.run_shelf("--run", "Cli", gom_body="echo 'gom: error: no display' >&2\nexit 1\n")
        self.assertEqual(bad.returncode, 1)
        lib.reload()
        self.assertEqual((lib.get(gid)["last_error"], lib.get(gid)["sessions"]), ("no display", 1))
        listed = self.run_shelf("--list", gom_body="exit 0\n")
        self.assertIn("Cli Game", listed.stdout.splitlines())
        nope = self.run_shelf("--run", "no such thing", gom_body="exit 0\n")
        self.assertEqual(nope.returncode, 2)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
