// KeePass41FixtureGen - generates KDBX test fixtures with KeePass' own
// serializer (KeePassLib, shipped inside KeePass.exe).
//
// The generated files land in test/data/kdbx4/kdbx41/ and are used by
// test/kdbx4.cc to verify KDBX 4.1 import against databases produced by a
// real KeePass >= 2.48. All fixtures use the master password "password".
//
// Build & run (KeePass 2.x installed at /usr/lib/keepass2):
//   mcs -r:/usr/lib/keepass2/KeePass.exe -out:KeePass41FixtureGen.exe \
//       KeePass41FixtureGen.cs
//   MONO_PATH=/usr/lib/keepass2 mono KeePass41FixtureGen.exe <outdir>
//
// Fixtures:
//   kdbx41-all.kdbx             all 4.1 features -> version 0x00040001
//   kdbx41-prevparent-only.kdbx only PreviousParentGroup -> version 0x00040000
//                              (KeePass' migration rule, see KDBX 4.1 spec:
//                               a previous-parent-group reference does NOT
//                               enforce KDBX 4.1)
//   kdbx40-plain.kdbx           no 4.1 features -> version 0x00040000

using System;
using System.Collections.Generic;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Cryptography;
using KeePassLib.Cryptography.KeyDerivation;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;

public static class KeePass41FixtureGen {
  sealed class NullLogger : IStatusLogger {
    public bool SetText(string strNewText, LogStatusType slt) { return true; }
    public void StartLogging(string strOperation, bool bWriteOperationToLog) {}
    public void EndLogging() {}
    public bool ContinueWork() { return true; }
    public bool SetProgress(uint uPercent) { return true; }
  }

  static readonly byte[] kAesUuid = {0x31,0xC1,0xF2,0xE6,0xBF,0x71,0x43,0x50,
                                     0xBE,0x58,0x05,0x21,0x6A,0xFC,0x5A,0xFF};
  static readonly byte[] kArgon2dUuid = {0xEF,0x63,0x6D,0xDF,0x8C,0x29,0x44,0x4B,
                                         0x91,0xF7,0xA9,0xA4,0x03,0xE3,0x0A,0x0C};
  static readonly byte[] kUuidIcon = {0x41,0x01};
  static readonly byte[] kUuidPrevParentGroup = {0x99,0x01};
  static readonly byte[] kUuidPrevParentEntry = {0x88,0x02};
  static readonly byte[] kUuidDeletedEntry = {0xDE,0xAD,0xBE,0xEF};
  static readonly byte[] kUuidDeletedIcon = {0x42,0x01};

  static PwUuid U16(byte[] bytes) {
    byte[] b = new byte[16];
    for (int i = 0; i < b.Length; i++) b[i] = bytes[i % bytes.Length];
    return new PwUuid(b);
  }

  static DateTime T(int y, int mo, int d, int h, int mi, int s) {
    return new DateTime(y, mo, d, h, mi, s, DateTimeKind.Utc);
  }

  static PwDatabase NewDb(string path) {
    var db = new PwDatabase();
    var key = new CompositeKey();
    key.AddUserKey(new KcpPassword("password"));
    db.New(IOConnectionInfo.FromPath(path), key);
    db.Compression = PwCompressionAlgorithm.GZip;
    db.DataCipherUuid = U16(kAesUuid);
    var kdf = new KdfParameters(U16(kArgon2dUuid));
    kdf.SetUInt64("M", 65536);    // memory in bytes (keep KDF cheap)
    kdf.SetUInt64("I", 3);        // iterations
    kdf.SetUInt32("P", 2);        // parallelism
    kdf.SetUInt32("V", 0x13);     // Argon2 version 1.3
    kdf.SetByteArray("S", new byte[16]); // salt, fixed for determinism
    db.KdfParameters = kdf;
    db.RootGroup.Name = "Root";
    return db;
  }

  static PwGroup AddGroup(PwGroup parent, string name, byte[] uuid) {
    var g = new PwGroup(false, false);
    g.Uuid = U16(uuid);
    g.Name = name;
    parent.AddGroup(g, true);
    return g;
  }

  static PwEntry AddEntry(PwGroup parent, string title, string user, string pass,
                          byte[] uuid, bool qualityCheck) {
    var e = new PwEntry(false, false);
    e.Uuid = U16(uuid);
    e.Strings.Set(PwDefs.TitleField, new ProtectedString(false, title));
    e.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, user));
    e.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, pass));
    e.QualityCheck = qualityCheck;
    parent.AddEntry(e, true);
    return e;
  }

  static void SetTimes(PwGroup obj, DateTime creation, DateTime mod, DateTime access, DateTime expiry) {
    obj.CreationTime = creation;
    obj.LastModificationTime = mod;
    obj.LastAccessTime = access;
    obj.ExpiryTime = expiry;
  }

  static void SetTimes(PwEntry obj, DateTime creation, DateTime mod, DateTime access, DateTime expiry) {
    obj.CreationTime = creation;
    obj.LastModificationTime = mod;
    obj.LastAccessTime = access;
    obj.ExpiryTime = expiry;
  }

  static void Save(PwDatabase db, string path) {
    db.Save(new NullLogger());
    Console.WriteLine("Wrote " + path);
  }

  static void GenAll(string outdir) {
    // All KDBX 4.1 features present -> KeePass must write 0x00040001.
    string path = System.IO.Path.Combine(outdir, "kdbx41-all.kdbx");
    var db = NewDb(path);
    SetTimes(db.RootGroup, T(2023,11,14,22,13,20), T(2023,11,14,22,13,21),
             T(2023,11,14,22,13,22), T(2023,11,14,22,13,23));

    var finance = AddGroup(db.RootGroup, "Finance", new byte[] {0x11});
    finance.Tags = new List<string>{"finance", "banking"};
    SetTimes(finance, T(2023,11,14,22,14,00), T(2023,11,14,22,14,01),
             T(2023,11,14,22,14,02), T(2023,11,14,22,14,03));

    var bank = AddEntry(finance, "Bank Entry", "bank_user", "bank_password",
                        new byte[] {0x21}, false);
    bank.PreviousParentGroup = U16(kUuidPrevParentEntry);
    bank.CustomIconUuid = U16(kUuidIcon);
    SetTimes(bank, T(2023,11,14,22,15,00), T(2023,11,14,22,15,01),
             T(2023,11,14,22,15,02), T(2023,11,14,22,15,03));
    bank.Expires = true;

    var personal = AddGroup(db.RootGroup, "Personal", new byte[] {0x12});
    personal.PreviousParentGroup = U16(kUuidPrevParentGroup);
    SetTimes(personal, T(2023,11,14,22,16,00), T(2023,11,14,22,16,01),
             T(2023,11,14,22,16,02), T(2023,11,14,22,16,03));

    var plain = AddEntry(personal, "Plain Entry", "alice", "plain_password",
                         new byte[] {0x22}, true);
    SetTimes(plain, T(2023,11,14,22,17,00), T(2023,11,14,22,17,01),
             T(2023,11,14,22,17,02), T(2023,11,14,22,17,03));

    // Custom icon with name and last-modification time.
    var icon = new PwCustomIcon(U16(kUuidIcon), new byte[]{0x89,0x50,0x4E,0x47});
    icon.Name = "MyIcon";
    icon.LastModificationTime = T(2023,11,14,22,18,00);
    db.CustomIcons.Add(icon);

    // Custom data item (db-level) -> written with a last-modification time.
    db.CustomData.Set("kdbx41-key", "kdbx41-value");

    // Deletion tombstones (entry + icon), as written when objects are deleted.
    db.DeletedObjects.Add(new PwDeletedObject(U16(kUuidDeletedEntry), T(2023,11,14,22,19,00)));
    db.DeletedObjects.Add(new PwDeletedObject(U16(kUuidDeletedIcon), T(2023,11,14,22,20,00)));
    Save(db, path);
  }

  static void GenPrevParentOnly(string outdir) {
    // Only a PreviousParentGroup reference. KeePass' KDBX 4.1 spec says this
    // must NOT enforce version 4.1; verified against KeePass 2.57: the file is
    // written as 0x00040000 and the PreviousParentGroup element is then omitted
    // from the 4.0 output (the reference data is lost on save).
    string path = System.IO.Path.Combine(outdir, "kdbx41-prevparent-only.kdbx");
    var db = NewDb(path);
    SetTimes(db.RootGroup, T(2023,11,14,22,13,20), T(2023,11,14,22,13,21),
             T(2023,11,14,22,13,22), T(2023,11,14,22,13,23));

    var group = AddGroup(db.RootGroup, "Moved Group", new byte[] {0x13});
    group.PreviousParentGroup = U16(kUuidPrevParentGroup);
    SetTimes(group, T(2023,11,14,22,21,00), T(2023,11,14,22,21,01),
             T(2023,11,14,22,21,02), T(2023,11,14,22,21,03));

    var entry = AddEntry(group, "Moved Entry", "bob", "moved_password",
                         new byte[] {0x23}, true);
    entry.PreviousParentGroup = U16(kUuidPrevParentEntry);
    SetTimes(entry, T(2023,11,14,22,22,00), T(2023,11,14,22,22,01),
             T(2023,11,14,22,22,02), T(2023,11,14,22,22,03));
    Save(db, path);
  }

  static void GenPlain(string outdir) {
    // No 4.1 features -> version stays 0x00040000.
    string path = System.IO.Path.Combine(outdir, "kdbx40-plain.kdbx");
    var db = NewDb(path);
    SetTimes(db.RootGroup, T(2023,11,14,22,13,20), T(2023,11,14,22,13,21),
             T(2023,11,14,22,13,22), T(2023,11,14,22,13,23));

    var group = AddGroup(db.RootGroup, "Plain Group", new byte[] {0x14});
    SetTimes(group, T(2023,11,14,22,23,00), T(2023,11,14,22,23,01),
             T(2023,11,14,22,23,02), T(2023,11,14,22,23,03));

    var entry = AddEntry(group, "Plain Entry", "carol", "plain_password",
                         new byte[] {0x24}, true);
    SetTimes(entry, T(2023,11,14,22,24,00), T(2023,11,14,22,24,01),
             T(2023,11,14,22,24,02), T(2023,11,14,22,24,03));
    Save(db, path);
  }

  public static int Main(string[] args) {
    if (args.Length != 1) {
      Console.Error.WriteLine("usage: KeePass41FixtureGen <outdir>");
      return 1;
    }
    string outdir = args[0];
    System.IO.Directory.CreateDirectory(outdir);
    GenAll(outdir);
    GenPrevParentOnly(outdir);
    GenPlain(outdir);
    return 0;
  }
}