import hashlib
import copy
import threading
import time
import json
import os


### === Integrity Engine === ###
class IntegrityEngine:
    """
    Helper methods to compute cryptographic hashes:
      - compute_file_hash: SHA-256 over raw file bytes.
      - compute_dir_hash: SHA-256 over a sorted listing of (name, child_hash) pairs.
      - compute_ovm_root: SHA-256 over a sorted listing of (key, value) entries in a flat OVM.
    """

    @staticmethod
    def compute_file_hash(data: bytes) -> str:
        """
        Compute a SHA-256 hash of the given file content bytes.

        :param data: Raw bytes of the file.
        :return: Hex string of the SHA-256 digest.
        """
        # TODO: Compute hash over file content + metadata + counter
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def compute_dir_hash(children_hash_map: dict) -> str:
        """
        Compute a SHA-256 hash for a directory by hashing its children’s names and hashes.

        Steps:
          1. Sort items of children_hash_map by child name.
          2. Serialize sorted list via repr(...) and UTF-8 encode.
          3. Compute SHA-256 digest over the resulting bytes.

        :param children_hash_map: Dict mapping child_name (str) to child_hash (str).
        :return: Hex string of the SHA-256 digest representing directory state.
        """
        items = sorted(children_hash_map.items())
        serialized = repr(items).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    @staticmethod
    def compute_ovm_root(ovm_map: dict) -> str:
        """
        Compute a SHA-256 “Merkle” root for the flattened object-version map (OVM).

        This naive root is SHA-256 over repr() of the sorted list of (key, value)
        pairs **excluding** any seal entries.

        :param ovm_map: Dict mapping OVM key (str) to its value (str).
        :return: Hex string of the SHA-256 digest for the entire OVM state.
        """
        items = sorted((k, v) for k, v in ovm_map.items() if not k.startswith("seal|"))
        serialized = repr(items).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()


### === File Object === ###
class FileObject:
    """
    Represents a single file in the simulated file system.

    Attributes:
      - name (str): Filename (e.g., "foo.txt").
      - parent (DirectoryObject): Reference to containing directory.
      - content (bytearray): Mutable bytes of the file.
      - file_hash (str): Last‐fsynced SHA-256 hash of content.
      - dirty (bool): True if content changed since last fsync.
      - last_ctr (int or None): Monotonic counter at last fsync.
      - lock (threading.Lock): Ensures atomic reads/writes.
    """

    def __init__(self, name: str, parent):
        """
        Initialize a new FileObject with empty content.

        :param name: The file’s name (not full path).
        :param parent: The DirectoryObject that contains this file.
        """
        self.name = name
        self.parent = parent
        self.content = bytearray()
        self.file_hash = IntegrityEngine.compute_file_hash(self.content)
        self.dirty = False
        self.last_ctr = None
        self.lock = threading.Lock()

    def read(self, offset: int = 0, length: int = None) -> bytes:
        """
        Read bytes from the file after authenticating integrity up to the root.

        Steps:
          1. Acquire lock.
          2. authenticate_proof() verifies file & directory hashes.
          3. Return requested content slice.

        :param offset: Byte offset to start reading.
        :param length: Number of bytes to read; if None, read to EOF.
        :return: Bytes read.
        :raises IOError: If any integrity check fails.
        """
        with self.lock:
            self.authenticate_proof()
            if length is None:
                return bytes(self.content[offset:])
            return bytes(self.content[offset : offset + length])

    def write(self, offset: int, new_data: bytes):
        """
        Write to the file’s content at the specified offset, marking it dirty.

        Steps:
          1. Acquire lock.
          2. Extend content with zeros if writing past EOF.
          3. Overwrite slice with new_data.
          4. Set dirty = True.

        :param offset: Byte offset to begin writing.
        :param new_data: Bytes to write.
        """
        with self.lock:
            end = offset + len(new_data)
            if end > len(self.content):
                self.content.extend(b"\x00" * (end - len(self.content)))
            self.content[offset:end] = new_data
            self.dirty = True

    def fsync(self) -> str:
        """
        Simulate fsync: recompute file_hash over content, clear dirty,
        then propagate directory hash updates. Return new file_hash.

        :return: Updated file_hash (hex string).
        """
        with self.lock:
            if not self.dirty:
                return self.file_hash
            self.file_hash = IntegrityEngine.compute_file_hash(self.content)
            self.dirty = False

        if self.parent:
            self.parent.propagate_hash_update()

        return self.file_hash

    def close(self):
        """
        Simulate closing a file handle (no-op here).
        """
        pass

    def authenticate_proof(self):
        """
        Verify integrity from this file up to the root:

          1. Recompute and compare this file’s SHA-256(content) to file_hash.
          2. Walk parent chain, recomputing each directory’s dir_hash.
          3. Collect and pretty-print a proof path like "/ > /docs > /docs/foo.txt".

        :raises IOError: On any hash mismatch.
        """
        # Step 1: verify file hash
        recomputed = IntegrityEngine.compute_file_hash(self.content)
        if recomputed != self.file_hash:
            raise IOError(
                f"File hash mismatch for '{self.name}': expected {self.file_hash}, got {recomputed}"
            )

        # Step 2: build chain from root → this file
        chain = []
        node = self
        while node:
            chain.append(node)
            node = node.parent
        chain.reverse()

        # Step 3: verify each node and collect proof entries
        proof = []
        for idx, node in enumerate(chain):
            if isinstance(node, DirectoryObject):
                path = (
                    "/"
                    if idx == 0
                    else "/" + "/".join(n.name for n in chain[1 : idx + 1])
                )
                stored = node.dir_hash
                child_map = {
                    name: (
                        child.file_hash
                        if isinstance(child, FileObject)
                        else child.dir_hash
                    )
                    for name, child in node.children.items()
                }
                recomputed_dir = IntegrityEngine.compute_dir_hash(child_map)
                if recomputed_dir != stored:
                    raise IOError(
                        f"Directory hash mismatch at '{path}': "
                        f"expected {stored}, got {recomputed_dir}"
                    )
                proof.append((path, stored))
            else:
                path = "/" + "/".join(n.name for n in chain[1 : idx + 1])
                proof.append((path, node.file_hash))

        # Step 4: print proof path
        proof_str = " > ".join(f"{p} ({h[:8]})" for p, h in proof)
        print("Authentication proof:")
        print(proof_str)

    def __deepcopy__(self, memo):
        """
        Deep-copy for snapshots: clone content, file_hash, dirty flag, fresh lock.
        Parent will be reattached by DirectoryObject’s deepcopy.
        """
        clone = FileObject(self.name, parent=None)
        clone.content = bytearray(self.content)
        clone.file_hash = str(self.file_hash)
        clone.dirty = bool(self.dirty)
        clone.last_ctr = self.last_ctr
        clone.lock = threading.Lock()
        return clone


### === Directory Object === ###
class DirectoryObject:
    """
    Represents a directory in the simulated file system.

    Attributes:
      - name (str): Directory name (root is "/").
      - parent (DirectoryObject or None): Parent reference.
      - children (dict): name → FileObject or DirectoryObject.
      - dir_hash (str): SHA-256 over sorted [(child_name, child_hash)].
      - lock (threading.Lock): Protects modifications.
    """

    def __init__(self, name: str, parent):
        """
        Initialize an empty directory.

        :param name: Directory’s name.
        :param parent: Parent DirectoryObject or None if root.
        """
        self.name = name
        self.parent = parent
        self.children = {}
        self.dir_hash = IntegrityEngine.compute_dir_hash({})
        self.lock = threading.Lock()

    def add_child(self, child):
        """
        Add or overwrite a child node and update hashes.

        Steps:
          1. Acquire lock.
          2. Set child.parent = self and insert into children.
          3. Recompute this dir_hash.
          4. Release lock, then propagate_hash_update() on parent.

        :param child: FileObject or DirectoryObject.
        """
        with self.lock:
            child.parent = self
            self.children[child.name] = child
            self._recompute_hash_locked()
        if self.parent:
            self.parent.propagate_hash_update()

    def remove_child(self, child_name: str):
        """
        Remove a child by name and update hashes.

        :param child_name: Name of the child to remove.
        :raises KeyError: If child not present.
        """
        with self.lock:
            if child_name not in self.children:
                raise KeyError(f"Child '{child_name}' not in '{self.name}'")
            del self.children[child_name]
            self._recompute_hash_locked()
        if self.parent:
            self.parent.propagate_hash_update()

    def get_child(self, child_name: str):
        """
        Retrieve a child by name.

        :param child_name: Name of the child.
        :return: FileObject or DirectoryObject.
        :raises KeyError: If missing.
        """
        with self.lock:
            if child_name not in self.children:
                raise KeyError(f"Child '{child_name}' not in '{self.name}'")
            return self.children[child_name]

    def _recompute_hash_locked(self):
        """
        Internal: recompute dir_hash from current children.
        Must be called with self.lock held.
        """
        mapping = {
            name: (child.file_hash if isinstance(child, FileObject) else child.dir_hash)
            for name, child in self.children.items()
        }
        self.dir_hash = IntegrityEngine.compute_dir_hash(mapping)

    def propagate_hash_update(self):
        """
        Called when a child’s hash changes:
          1. Acquire lock and call _recompute_hash_locked().
          2. Release lock, then recurse on parent.
        """
        with self.lock:
            self._recompute_hash_locked()
        if self.parent:
            self.parent.propagate_hash_update()

    def __deepcopy__(self, memo):
        """
        Deep-copy directory and recursively its children for snapshots.
        """
        clone = DirectoryObject(self.name, parent=None)
        clone.dir_hash = str(self.dir_hash)
        clone.lock = threading.Lock()
        for name, child in self.children.items():
            child_copy = copy.deepcopy(child, memo)
            child_copy.parent = clone
            clone.children[name] = child_copy
        return clone


### === File System Simulator with Unified OVM & Audit Log === ###
class FileSystemSimulator:
    """
    In-memory file system simulator featuring:
      - File & directory integrity via SHA-256 hashes.
      - Single flat OVM for file-versions, raw data, snapshots, audit lines, and seals.
      - One monotonic counter seals the OVM root after every event.
      - Stub inclusion proofs for OVM entries.
      - Supports create/delete, open/read/write/fsync, selective rollback,
        coarse rollback, snapshots, and full-system authentication.
      - Writes `ovm.json` after every change so you can inspect the OVM map.
    """

    def __init__(self, audit_log_path="o/audit.log", ovm_path="o/ovm.json"):
        """
        Initialize simulator state:
          - Create root DirectoryObject.
          - Monotonic counter = 0.
          - Flat OVM dict.
          - Content store: key → raw bytes.
          - Audit log file + in-memory list.
          - Recursive lock.
          - Paths for audit log and OVM dump.
        """
        self.root = DirectoryObject("/", None)
        self._monotonic_counter = 0
        self._ovm = {}  # key → hash or JSON string
        self._content_store = {}  # key → raw content bytes
        self._audit_log = []
        self.audit_log_path = audit_log_path
        open(self.audit_log_path, "w").close()

        self._ovm_path = ovm_path
        self.lock = threading.RLock()

        self._append_audit("init")

        self._verify_startup()

    def _dump_ovm(self):
        """
        Write the entire flat OVM dict to disk as JSON.
        """
        with open(self._ovm_path, "w") as f:
            json.dump({k: self._ovm[k] for k in sorted(self._ovm)}, f, indent=2)

    def _verify_startup(self):
        """
        After loading state, ensure:
          a) live tree root == stored root|ctr
          b) recomputed OVM root == stored seal|ctr
        """
        ctr = self._monotonic_counter
        root_key = f"root|{ctr}"
        seal_key = f"seal|{ctr}"

        # a) directory-tree hasn’t shifted under us
        expected = self._ovm.get(root_key)
        if expected is None or expected != self.root.dir_hash:
            raise IOError(
                f"Startup root mismatch: {expected!r} vs {self.root.dir_hash!r}"
            )

        # b) our on-disk OVM matches its own seal
        recomputed = IntegrityEngine.compute_ovm_root(self._ovm)
        if recomputed != self._ovm.get(seal_key):
            raise IOError("Startup OVM root digest mismatch")

    def _seal(self):
        """
        Recompute and store the OVM root under the current counter,
        **including** a root|ctr payload, then dump OVM to disk.
        """
        # 1) capture the directory-tree root hash (protects directory structure)
        live_root = self.root.dir_hash
        self._ovm[f"root|{self._monotonic_counter}"] = live_root

        # 2) now compute the Merkle root over all non-seal entries
        # (protects all file contents + directory structure (via root|ctr))
        ovm_root = IntegrityEngine.compute_ovm_root(self._ovm)
        self._ovm[f"seal|{self._monotonic_counter}"] = ovm_root

        # 3) write out
        self._dump_ovm()

    def generate_inclusion_proof(self, key: str):
        """
        Stub: generate an inclusion proof for OVM key by returning
        all *non-seal* entries except the target key itself.
        """
        return [
            (k, v)
            for k, v in sorted(self._ovm.items())
            if not k.startswith("seal|") and k != key
        ]

    def verify_inclusion_proof(self, key: str, value: str, proof, root: str) -> bool:
        """
        Stub: verify proof by recomputing root over proof + (key,value),
        but ignoring any `seal|…` entries.
        """
        full = proof + [(key, value)]
        full_sorted = sorted(full, key=lambda kv: kv[0])
        recomputed = hashlib.sha256(repr(full_sorted).encode("utf-8")).hexdigest()
        return recomputed == root

    def _append_audit(self, message: str):
        """
        Append an audit entry with timestamp, record in OVM, then seal & dump.

        :param message: Descriptive text.
        """
        ts = time.time()
        line = f"{ts:.3f}|{message}"
        self._audit_log.append(line)
        with open(self.audit_log_path, "a") as f:
            f.write(line + "\n")
        h = hashlib.sha256(line.encode("utf-8")).hexdigest()
        key = f"audit|{self._monotonic_counter}"
        self._ovm[key] = h
        self._seal()

    def _traverse_path(self, path: str):
        """
        Walk tree for absolute path, auto-creating directories.

        :param path: Absolute path ("/foo/bar.txt").
        :return: (parent_dir, final_name).
        :raises ValueError: If not absolute.
        """
        if not path.startswith("/"):
            raise ValueError(f"Path must start with '/': {path}")
        comps = [c for c in path.split("/") if c]
        cur = self.root
        for comp in comps[:-1]:
            try:
                node = cur.get_child(comp)
                if not isinstance(node, DirectoryObject):
                    raise NotADirectoryError(f"'{comp}' is not a directory")
                cur = node
            except KeyError:
                nd = DirectoryObject(comp, parent=cur)
                cur.add_child(nd)
                cur = nd
        final = comps[-1] if comps else ""
        return cur, final

    def _find_node(self, path: str):
        """
        Locate an existing node (no auto-create).

        :param path: Absolute path.
        :return: FileObject or DirectoryObject.
        """
        if not path.startswith("/"):
            raise ValueError(f"Path must start with '/': {path}")
        comps = [c for c in path.split("/") if c]
        node = self.root
        for comp in comps:
            if not isinstance(node, DirectoryObject):
                raise NotADirectoryError(f"'{node.name}' is not a directory")
            node = node.get_child(comp)
        return node

    def create_file(self, path: str):
        """
        Create an empty file at path, auto-creating parent dirs.

        :param path: Absolute file path.
        :raises FileExistsError: If the file already exists.
        """
        with self.lock:
            parent, name = self._traverse_path(path)
            if name in parent.children:
                raise FileExistsError(f"'{path}' already exists")
            fo = FileObject(name, parent)
            parent.add_child(fo)

    def delete_file(self, path: str):
        """
        Delete file at path.

        :param path: Absolute file path.
        :raises FileNotFoundError: If missing.
        :raises IsADirectoryError: If path is a directory.
        """
        with self.lock:
            parent, name = self._traverse_path(path)
            if name not in parent.children:
                raise FileNotFoundError(f"'{path}' not found")
            node = parent.children[name]
            if not isinstance(node, FileObject):
                raise IsADirectoryError(f"'{path}' is not a file")
            parent.remove_child(name)

    def create_directory(self, path: str):
        """
        Create directory at path, auto-creating parents.

        :param path: Absolute directory path.
        :raises FileExistsError: If it already exists.
        """
        with self.lock:
            parent, name = self._traverse_path(path)
            if name in parent.children:
                raise FileExistsError(f"Directory '{path}' exists")
            nd = DirectoryObject(name, parent)
            parent.add_child(nd)

    def delete_directory(self, path: str):
        """
        Delete empty directory at path.

        :param path: Absolute directory path.
        :raises PermissionError: If root.
        :raises FileNotFoundError: If missing.
        :raises NotADirectoryError: If not a directory.
        :raises OSError: If not empty.
        """
        with self.lock:
            if path == "/":
                raise PermissionError("Cannot delete root")
            parent, name = self._traverse_path(path)
            if name not in parent.children:
                raise FileNotFoundError(f"'{path}' not found")
            node = parent.children[name]
            if not isinstance(node, DirectoryObject):
                raise NotADirectoryError(f"'{path}' is not a directory")
            if node.children:
                raise OSError(f"Directory '{path}' not empty")
            parent.remove_child(name)

    def open_file(self, path: str) -> FileObject:
        """
        Open and return the FileObject at path.

        :param path: Absolute file path.
        :return: FileObject instance.
        """
        node = self._find_node(path)
        if not isinstance(node, FileObject):
            raise IsADirectoryError(f"'{path}' is not a file")
        return node

    def close_file(self, path: str):
        """
        Close file handle (no-op).
        """
        pass

    def read_file(self, path: str, offset: int = 0, length: int = None) -> bytes:
        """
        Read file content with integrity check.

        :param path: Absolute file path.
        :param offset: Byte offset.
        :param length: Number of bytes or None.
        :return: Bytes read.
        """
        fo = self.open_file(path)
        return fo.read(offset, length)

    def write_file(self, path: str, offset: int, data: bytes):
        """
        Write bytes to a file (marks dirty).

        :param path: Absolute file path.
        :param offset: Byte offset.
        :param data: Bytes to write.
        """
        fo = self.open_file(path)
        fo.write(offset, data)

    def fsync_file(self, path: str) -> int:
        """
        fsync a file, record OVM entry + content, append audit, seal & dump.

        Steps:
          1. fo.fsync() → new_hash
          2. bump monotonic counter → ctr
          3. _ovm[f"file|{path}|{ctr}"] = new_hash
             _content_store[f"data|{path}|{ctr}"] = raw bytes
          4. fo.last_ctr = ctr
          5. _append_audit(f"fsync {path} → {new_hash[:8]}")
          6. return ctr
        """
        fo = self.open_file(path)
        new_hash = fo.fsync()

        with self.lock:
            self._monotonic_counter += 1
            ctr = self._monotonic_counter

            self._ovm[f"file|{path}|{ctr}"] = new_hash
            # Note: _content_store is separate for performance -- otherwise
            # computing the OVM root would require hashing all file contents.
            self._content_store[f"data|{path}|{ctr}"] = bytes(fo.content)
            fo.last_ctr = ctr

            self._append_audit(f"fsync {path} → {new_hash[:8]}")
        return ctr

    def take_snapshot(self) -> int:
        """
        Take a coarse-grained snapshot:

          1. fsync all dirty files (populates fo.last_ctr entries).
          2. bump monotonic counter → ctr_s
          3. build snapshot_record = {
                fs_root: self.root.dir_hash,
                file_map: {path: fo.last_ctr, …},
                timestamp: now
             }
          4. store JSON: _ovm[f"snapshot|{ctr_s}"] = json.dumps(record)
          5. dump OVM
          6. _append_audit("snapshot")
          7. return ctr_s

        :return: Counter at which snapshot was taken.
        """
        # Note: Maybe snapshot-on-close (IOCTL) - enumerate these for performance evaluation
        with self.lock:

            def collect(dir_obj):
                out = []
                for c in dir_obj.children.values():
                    if isinstance(c, FileObject):
                        out.append(c)
                    else:
                        out.extend(collect(c))
                return out

            # fsync dirty files
            for fo in collect(self.root):
                if fo.dirty:
                    p = self._absolute_path_of(fo)
                    self.fsync_file(p)

            # bump counter
            self._monotonic_counter += 1
            ctr_s = self._monotonic_counter
            ts = time.time()

            # build and store snapshot record/manifest
            file_map = {
                path: self.open_file(path).last_ctr for path in self.list_all_files()
            }
            rec = {"fs_root": self.root.dir_hash, "file_map": file_map, "timestamp": ts}
            self._ovm[f"snapshot|{ctr_s}"] = json.dumps(rec)
            self._dump_ovm()

            # audit + seal
            self._append_audit("snapshot")
            return ctr_s

    def rollback_file(self, path: str, target_ctr: int, verify_against_ctr=None) -> int:
        """
        Selectively rollback a single file to the version at target_ctr.

        Steps:
          1. Lookup self._ovm["file|{path}|{target_ctr}"] → sealed_hash.
          2. Choose which seal to verify against:
               - if verify_against_ctr is None, use the current latest counter,
               - else use verify_against_ctr.
          3. Build inclusion proof over all payload entries up through that counter.
          4. Verify the proof vs seal|that_ctr.
          5. Pull raw bytes from self._content_store["data|{path}|{target_ctr}"].
          6. Recompute SHA-256(raw_bytes) and compare to sealed_hash.
          7. Overwrite live file, propagate directory hashes.
          8. Bump monotonic counter → new_ctr; record new file/data entries; audit; reseal.
          9. Return new_ctr.

        :param path: Absolute file path.
        :param target_ctr: Counter of the version to restore.
        :param verify_against_ctr: Seal counter to authenticate against.
        :raises KeyError: If no version exists.
        :raises IOError: If any integrity check fails.
        :return: New monotonic counter after reseal.
        """
        key_f = f"file|{path}|{target_ctr}"
        key_d = f"data|{path}|{target_ctr}"
        if key_f not in self._ovm or key_d not in self._content_store:
            raise KeyError(f"No version for {path} at ctr={target_ctr}")

        seal_ctr = (
            self._monotonic_counter
            if verify_against_ctr is None
            else verify_against_ctr
        )
        root_key = f"seal|{seal_ctr}"
        if root_key not in self._ovm:
            raise IOError(f"No seal available for counter {seal_ctr}")
        root = self._ovm[root_key]

        # build and verify proof
        proof = [
            (k, v)
            for k, v in self._ovm.items()
            if not k.startswith("seal|")
            for ctr_str in [k.rsplit("|", 1)[-1]]
            if ctr_str.isdigit() and int(ctr_str) <= seal_ctr and k != key_f
        ]
        proof_sorted = sorted(proof, key=lambda kv: kv[0])
        full = proof_sorted + [(key_f, self._ovm[key_f])]
        full_sorted = sorted(full, key=lambda kv: kv[0])
        recomputed = hashlib.sha256(repr(full_sorted).encode("utf-8")).hexdigest()
        if recomputed != root:
            raise IOError("Invalid inclusion proof for rollback")

        # fetch and verify raw data
        raw = self._content_store[key_d]
        if IntegrityEngine.compute_file_hash(raw) != self._ovm[key_f]:
            raise IOError("Data hash mismatch after fetch")

        # apply to live file
        fo = self.open_file(path)
        with fo.lock:
            fo.content = bytearray(raw)
            fo.file_hash = self._ovm[key_f]
            fo.dirty = False
        if fo.parent:
            fo.parent.propagate_hash_update()

        # ensure the post-rollback tree hash is what we'll seal next:
        if self.root.dir_hash != IntegrityEngine.compute_dir_hash(
            {
                **{
                    name: (c.file_hash if isinstance(c, FileObject) else c.dir_hash)
                    for name, c in self.root.children.items()
                }
            }
        ):
            raise IOError("Rollback left tree in inconsistent state")
        # (if you have a helper to recompute the full directory tree hash, call it here)

        # bump counter, record new version, audit
        with self.lock:
            self._monotonic_counter += 1
            new_ctr = self._monotonic_counter
            self._ovm[f"file|{path}|{new_ctr}"] = fo.file_hash
            self._content_store[f"data|{path}|{new_ctr}"] = raw
            fo.last_ctr = new_ctr
            self._append_audit(f"rollback {path} to ctr={target_ctr}")
        return new_ctr

    def rollback_file_to_snapshot(self, path: str, snapshot_ctr: int) -> int:
        """
        Roll back a single file to the version it had when a given snapshot was taken.

        Steps:
          1. Lookup JSON in self._ovm["snapshot|{snapshot_ctr}"] → rec.
          2. Find rec["file_map"][path] → file_version_ctr.
          3. Call rollback_file(path, file_version_ctr, verify_against_ctr=snapshot_ctr).
          4. Return the new counter.

        :param path: Absolute file path.
        :param snapshot_ctr: Counter at which snapshot was taken.
        :raises KeyError: If snapshot record missing or file not in file_map.
        :raises IOError: If proof or data-hash fails.
        :return: New monotonic counter after selective rollback.
        """
        snap_key = f"snapshot|{snapshot_ctr}"
        if snap_key not in self._ovm:
            raise KeyError(f"No snapshot record at ctr={snapshot_ctr}")
        rec = json.loads(self._ovm[snap_key])

        file_map = rec.get("file_map", {})
        if path not in file_map:
            raise KeyError(f"No version of {path} in snapshot ctr={snapshot_ctr}")
        file_ctr = file_map[path]

        return self.rollback_file(path, file_ctr, verify_against_ctr=snapshot_ctr)

    def rollback_snapshot(self, snapshot_ctr: int):
        """
        Coarse rollback using the snapshot record at snapshot_ctr:

          1. parse rec = json.loads(_ovm["snapshot|snapshot_ctr"])
          2. verify rec["fs_root"] == self._ovm[f"root|{snapshot_ctr}"]
          3. OPTIONAL: verify historical seal|snapshot_ctr
          4. rebuild tree from rec["file_map"] + content_store
          5. verify new_root.dir_hash == rec["fs_root"]
          6. swap in, bump counter, _append_audit & seal
        """
        key = f"snapshot|{snapshot_ctr}"
        if key not in self._ovm:
            raise KeyError(f"No snapshot at ctr={snapshot_ctr}")
        rec = json.loads(self._ovm[key])
        fs_root = rec["fs_root"]

        # 2) snapshot’s fs_root must match what we recorded at seal time:
        payload_root = self._ovm.get(f"root|{snapshot_ctr}")
        if payload_root != fs_root:
            raise IOError("Snapshot payload root|snapshot_ctr mismatch")

        # 3) OPTIONAL: re-verify the historical OVM seal at snapshot_ctr
        entries = []
        for k, v in self._ovm.items():
            if k.startswith("seal|"):
                continue
            *_, ctr_str = k.rsplit("|", 1)
            if ctr_str.isdigit() and int(ctr_str) <= snapshot_ctr:
                entries.append((k, v))
        recomputed = hashlib.sha256(
            repr(sorted(entries, key=lambda kv: kv[0])).encode("utf-8")
        ).hexdigest()
        if recomputed != self._ovm.get(f"seal|{snapshot_ctr}"):
            raise IOError("Invalid historical seal at snapshot_ctr")

        # 4) rebuild from content_store
        new_root = DirectoryObject("/", None)
        for path, ver_ctr in rec["file_map"].items():
            data_key = f"data|{path}|{ver_ctr}"
            hash_key = f"file|{path}|{ver_ctr}"
            if data_key not in self._content_store or hash_key not in self._ovm:
                raise KeyError(f"No version for {path} at ctr={ver_ctr}")
            raw = self._content_store[data_key]
            h = IntegrityEngine.compute_file_hash(raw)
            if h != self._ovm[hash_key]:
                raise IOError(f"Data-hash mismatch for {path}@{ver_ctr}")

            # mkdir -p under new_root
            comps = [c for c in path.split("/") if c]
            parent = new_root
            for d in comps[:-1]:
                try:
                    node = parent.get_child(d)
                except KeyError:
                    node = DirectoryObject(d, parent)
                    parent.add_child(node)
                parent = node

            fo = FileObject(comps[-1], parent)
            fo.content = bytearray(raw)
            fo.file_hash = h
            fo.dirty = False
            fo.last_ctr = ver_ctr
            parent.add_child(fo)

        # 5) rebuilt root must match the snapshot fs_root
        if new_root.dir_hash != fs_root:
            raise IOError("Rebuilt tree root mismatch")

        # 6) install and reseal
        with self.lock:
            self.root = new_root
            self._monotonic_counter += 1
            self._append_audit(f"rollback_snapshot to ctr={snapshot_ctr}")

    def list_all_files(self) -> list:
        """
        Return a list of all absolute file paths in the file system.

        :return: List of strings like "/docs/report.txt".
        """

        def recurse(dir_obj, base):
            for name, child in dir_obj.children.items():
                path = f"{base}/{name}" if base else f"/{name}"
                if isinstance(child, FileObject):
                    yield path
                else:
                    yield from recurse(child, path)

        return list(recurse(self.root, ""))

    def authenticate_all_files(self):
        """
        Walk all files and print their authentication proofs via read().
        """
        for path in self.list_all_files():
            print(f"\nAuthenticating {path}:")
            self.read_file(path)

    def get_file_hash(self, path: str) -> str:
        """
        Return the last-fsynced file_hash for the given path.

        :param path: Absolute file path.
        :return: Hex string of the file's SHA-256 hash.
        """
        return self.open_file(path).file_hash

    def get_directory_hash(self, path: str = "/") -> str:
        """
        Return the stored dir_hash of a directory.

        :param path: Absolute directory path.
        :return: Hex string of the directory's SHA-256 digest.
        :raises NotADirectoryError: If path not a directory.
        """
        if path == "/":
            return self.root.dir_hash
        node = self._find_node(path)
        if not isinstance(node, DirectoryObject):
            raise NotADirectoryError(f"'{path}' is not a directory")
        return node.dir_hash

    def list_seals(self) -> dict:
        """
        Return all OVM seals: counter → root digest.

        :return: Dict mapping int counter to hex root digest.
        """
        return {
            int(k.split("|", 1)[1]): v
            for k, v in self._ovm.items()
            if k.startswith("seal|")
        }

    def list_snapshots(self) -> list:
        """
        List all snapshots with their counters and timestamps.

        :return: List of dicts: {"ctr": int, "timestamp": float}.
        """
        out = []
        for k, v in self._ovm.items():
            if k.startswith("snapshot|"):
                ctr = int(k.split("|", 1)[1])
                rec = json.loads(v)
                out.append({"ctr": ctr, "timestamp": rec["timestamp"]})
        return sorted(out, key=lambda x: x["ctr"])

    def _absolute_path_of(self, fo: FileObject) -> str:
        """
        Reconstruct absolute path by walking parents.

        :param fo: FileObject instance.
        :return: Absolute path string (e.g. "/docs/foo.txt").
        """
        parts = []
        node = fo
        while node:
            if isinstance(node, FileObject):
                parts.insert(0, node.name)
                node = node.parent
            else:
                if node.parent is None:
                    parts.insert(0, "")
                    node = None
                else:
                    parts.insert(0, node.name)
                    node = node.parent
        return "/".join(parts)


def run_interactive_test():
    """
    Interactive test harness that exercises both simple and complex scenarios.

      SIMPLE TEST (steps 1–8):
        1. Create /docs/report.txt, write “Hello” (dirty).
        2. fsync and inspect file, directory, and root hashes.
        3. Dirty-write “ World” and show stale hash.
        4. Take three snapshots, mutating before each (except the first).
        5. List snapshots & prompt user to pick one.
        6. Selective per-file rollback of /docs/report.txt.
        7. Coarse rollback of the entire FS to the chosen snapshot.
        8. Print audit log & seal history.

      COMPLEX TEST (steps C1–C8):
        C1. Create four directories.
        C2. Create 10 files across them.
        C3. Write initial content to all files (dirty).
        C4. fsync every even-indexed file.
        C5. Append “ UPDATED” to every odd-indexed file.
        C6. Take two snapshots (auto-fsyncing dirty files).
        C7. Selectively rollback one chosen file, then coarse-rollback again.
        C8. Authenticate all files.
    """
    fs = FileSystemSimulator()

    # --- SIMPLE TEST ---
    fs.create_file("/docs/report.txt")
    fs.write_file("/docs/report.txt", 0, b"Hello")
    print("1) Wrote 'Hello' → Stale hash:", fs.get_file_hash("/docs/report.txt"))

    c1 = fs.fsync_file("/docs/report.txt")
    print("\n2) After fsync:")
    print("   File hash:", fs.get_file_hash("/docs/report.txt"))
    print("   Counter:", c1)
    print("   Seal @", c1, "→", fs.list_seals()[c1])
    print("   /docs hash:", fs.get_directory_hash("/docs"))
    print("   / (root dir) hash:", fs.get_directory_hash("/"))

    fs.write_file("/docs/report.txt", 5, b" World")
    print(
        "\n3) Wrote ' World' without fsync → Dirty hash stays:",
        fs.get_file_hash("/docs/report.txt"),
    )

    snapshot_ctrs = []
    for pass_no in range(3):
        if pass_no > 0:
            extra = chr(ord("!") + pass_no - 1)
            fs.write_file("/docs/report.txt", 11, extra.encode())
            print(f"\n   Mutated with '{extra}' before taking snapshot.")
        sid = fs.take_snapshot()
        snapshot_ctrs.append(sid)
        print(f"4.{pass_no+1}) Took snapshot at ctr={sid}")

    print("\n5) Available snapshots:")
    for rec in fs.list_snapshots():
        print(f"   [{rec['ctr']}] ctr={rec['ctr']} at {time.ctime(rec['timestamp'])}")
    choice = None
    available = [rec["ctr"] for rec in fs.list_snapshots()]
    while choice not in available:
        choice = int(input("Enter snapshot counter to restore /docs/report.txt from: "))

    new_ctr = fs.rollback_file_to_snapshot("/docs/report.txt", choice)
    print(
        f"\n6) Rolled back /docs/report.txt to snapshot ctr={choice} → new ctr {new_ctr}"
    )
    print("   Content now   :", fs.read_file("/docs/report.txt"))
    print("   File hash     :", fs.get_file_hash("/docs/report.txt"))
    print("   Root dir hash :", fs.get_directory_hash("/"))

    fs.rollback_snapshot(choice)
    print(f"\n7) Coarse rollback entire FS to snapshot ctr={choice}")
    print("   /docs/report.txt:", fs.read_file("/docs/report.txt"))
    print("   Root dir hash   :", fs.get_directory_hash("/"))

    print("\n8) Audit log entries:")
    for entry in fs._audit_log:
        print("   ", entry)
    print("\n   Seal history:")
    for ctr, root in sorted(fs.list_seals().items()):
        print(f"   ctr {ctr} → {root}")

    # --- COMPLEX TEST ---
    print("\n--- COMPLEX MULTI-FILE STRUCTURE TEST ---")
    for d in ("/docs", "/images", "/images/thumbnails", "/archive"):
        try:
            fs.create_directory(d)
        except FileExistsError:
            pass
    print("C1) Ensured directories: /docs, /images, /images/thumbnails, /archive")

    files = [
        "/docs/report1.txt",
        "/docs/report2.txt",
        "/docs/data.csv",
        "/docs/notes.txt",
        "/images/pic1.jpg",
        "/images/pic2.jpg",
        "/images/thumbnails/thumb1.jpg",
        "/images/thumbnails/thumb2.jpg",
        "/archive/log1.txt",
        "/archive/log2.txt",
    ]
    for path in files:
        try:
            fs.create_file(path)
        except FileExistsError:
            pass
    print("C2) Created 10 files")

    for path in files:
        fs.write_file(path, 0, f"Init {os.path.basename(path)}".encode())
    print("C3) Wrote initial content to all files (dirty)")

    print("C4) fsyncing even-indexed files:")
    for idx, path in enumerate(files):
        if idx % 2 == 0:
            ctr = fs.fsync_file(path)
            print(f"    {path} → ctr {ctr}")

    for idx, path in enumerate(files):
        if idx % 2 == 1:
            length = len(fs.open_file(path).content)
            fs.write_file(path, length, b" UPDATED")
    print("C5) Appended ' UPDATED' to odd-indexed files (dirty)")

    complex_ctrs = []
    for i in (1, 2):
        ctr = fs.take_snapshot()
        complex_ctrs.append(ctr)
        print(f"C6.{i}) Took snapshot ctr={ctr} at {time.ctime()}")

    target = files[3]
    sel_ctr = complex_ctrs[0]
    new_ctr2 = fs.rollback_file_to_snapshot(target, sel_ctr)
    print(f"C7a) Rolled back {target} to snapshot ctr={sel_ctr} → new ctr {new_ctr2}")
    print("     Content now:", fs.read_file(target))

    fs.rollback_snapshot(sel_ctr)
    print(f"C7b) Coarse rollback FS to snapshot ctr={sel_ctr}")
    print("     /docs/report1.txt:", fs.read_file("/docs/report1.txt"))

    print("\nC8) Authenticating all files in the system:")
    fs.authenticate_all_files()


if __name__ == "__main__":
    run_interactive_test()
