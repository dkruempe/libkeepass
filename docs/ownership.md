# Object ownership and aliasing policy

This document defines who owns what in the `Database`/`Group`/`Entry` object
graph. It is the reference for moving, deleting and trashing subtrees; code and
tests should follow it.

## Ownership rules

1. **The database owns the root.** `Database::root()` returns a
   `std::shared_ptr<Group>`. The database keeps the only strong reference to the
   root; callers may keep additional strong references for as long as they need
   the tree.
2. **Parents own children.** A `Group` keeps `std::shared_ptr<Entry>` and
   `std::shared_ptr<Group>` in its entry/group vectors. Removing a child from
   its parent is what ends the tree's ownership; local `shared_ptr` copies keep
   the object alive until they go out of scope.
3. **Children do not own parents.** `Entry::parent()` and `Group::parent()`
   return `std::weak_ptr<Group>`. Lock the weak pointer before following it.
   This avoids reference cycles and lets a detached subtree be destroyed.
4. **Weak references are caches, not ownership.** Custom icons
   (`Entry::custom_icon()`, `Group::custom_icon()`) and metadata references to
   groups (recycle bin, entry templates) are non-owning. Resolve them through
   the metadata/icon pool rather than assuming they stay alive.
5. **History items own themselves.** An entry owns its `history()` vector of
   `std::shared_ptr<Entry>` snapshots. History entries have no parent and no
   history of their own (`save_history()` detaches both).
6. **Attachments share binaries.** An `Attachment` holds a
   `std::shared_ptr<Binary>`; several attachments and metadata binaries may
   point at the same `Binary`. Treat binaries as immutable while shared and
   deduplicate by pointer when exporting.

## Moving, deleting and trashing

- `Database::AddEntry`/`AddGroup` attach a child and update its weak parent.
  Adding an object that already has a parent is not a move; use the move
  helpers.
- `Database::MoveEntry`/`MoveGroup` detach from the old parent and attach to the
  new one. The caller must keep the moved object alive (the `shared_ptr`
  argument does). Moving a group moves its whole subtree.
- `Database::DeleteEntry`/`DeleteGroup` remove the object from the tree. The
  object itself is destroyed once the last strong reference goes away. Deleting
  a group deletes its subtree and any history attached to its entries.
- `Database::TrashEntry`/`TrashGroup` move the object into the recycle-bin
  group and record `previous_parent_group()` (KDBX 4.1). `EmptyRecycleBin`
  deletes the recycled objects.
- Do not keep raw pointers to graph nodes. If you need a stable handle, keep a
  `shared_ptr` (strong) or a `weak_ptr` (non-owning) and lock it on use.

## Aliasing rules

- `Database::root()` and the group/entry vectors are **non-const views**. A
  caller must not mutate the graph concurrently from multiple threads; the
  library is safe for concurrent *reads/imports* of separate `KeePass`
  instances, not for mutating one graph from several threads.
- Metadata may reference groups by UUID. Those references are resolved through
  the node pool after parsing; they do not keep a group alive.
- A `Database` must not be copied. Move it or move the `unique_ptr` that owns
  it.
- When changing the KDF or cipher parameters, update the `Database` (which
  invalidates the cached transformed key); the codecs read the parameters at
  export time.
