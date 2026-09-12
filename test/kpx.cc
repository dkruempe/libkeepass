/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
 * Copyright (C) 2024 Dominik Krümpelmann
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <gtest/gtest.h>

#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "libkeepass/entry.hh"
#include "libkeepass/group.hh"
#include "libkeepass/kdbx.hh"
#include "libkeepass/key.hh"

#include "../cli/kpx.hh"
#include "config.hh"

namespace {

using keepass::protect;
using keepass::secure_string;
using kpx::ExportDatabase;
using kpx::IsKdbPath;
using kpx::kDefaultGenerateLength;
using kpx::kGenerateCharset;
using kpx::kpx_main;
using kpx::kVersion;
using kpx::Options;
using kpx::ParseArgs;
using kpx::PrintUsage;
using kpx::ResolvePassword;

std::string GetDataPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/data/kdbx/" + name;
}

std::string GetTmpPath(const std::string& name) {
  return std::string(PROJECT_ROOT_PATH) + "/tmp/" + name;
}

// Redirects std::cout and std::cerr into in-memory buffers for the lifetime of
// the object, restoring the original streams when destroyed.
class OutputCapture {
public:
  OutputCapture() : cout_buf_(std::cout.rdbuf()), cerr_buf_(std::cerr.rdbuf()) {
    std::cout.rdbuf(out_.rdbuf());
    std::cerr.rdbuf(err_.rdbuf());
  }

  ~OutputCapture() {
    std::cout.rdbuf(cout_buf_);
    std::cerr.rdbuf(cerr_buf_);
  }

  std::string out() const { return out_.str(); }
  std::string err() const { return err_.str(); }

private:
  std::stringstream out_;
  std::stringstream err_;
  std::streambuf* cout_buf_;
  std::streambuf* cerr_buf_;
};

// Sets an environment variable for the lifetime of the object.
class EnvGuard {
public:
  EnvGuard(const char* name, const char* value) : name_(name) {
#ifdef _WIN32
    _putenv_s(name_, value);
#else
    setenv(name_, value, 1);
#endif
  }

  ~EnvGuard() {
#ifdef _WIN32
    _putenv_s(name_, "");
#else
    unsetenv(name_);
#endif
  }

private:
  const char* name_;
};

struct CliResult {
  int code = 0;
  std::string out;
  std::string err;
};

// Runs the CLI entry point with the given arguments (argv[0] is "kpx").
CliResult RunCli(std::initializer_list<std::string> args) {
  std::vector<const char*> argv;
  argv.reserve(args.size() + 1);
  argv.push_back("kpx");
  for (const std::string& arg : args)
    argv.push_back(arg.c_str());

  OutputCapture capture;
  const int code = kpx_main(static_cast<int>(argv.size()), argv.data());
  return CliResult{code, capture.out(), capture.err()};
}

std::string ReadFile(const std::string& path) {
  std::ifstream file(path);
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

// Builds a small database with known content. Metadata is reused from an
// existing fixture so the exporters have a fully populated database to write.
std::unique_ptr<keepass::Database> CreateTestDatabase() {
  keepass::KdbxFile reader;
  std::unique_ptr<keepass::Database> meta_source =
      reader.Import(GetDataPath("groups-2-random_entry-4-pw-aes.kdbx"), keepass::Key("password"));

  std::unique_ptr<keepass::Database> db(new keepass::Database());
  std::array<uint8_t, 16> master_seed{{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0,
                                       0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01}};
  db->set_master_seed(master_seed);
  db->set_init_vector({{0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                        0x0e, 0x0f, 0x10, 0x11}});
  db->set_meta(meta_source->meta());

  auto root = std::make_shared<keepass::Group>();
  root->set_name("root");

  auto internet = std::make_shared<keepass::Group>();
  internet->set_name("Internet");

  auto mail = std::make_shared<keepass::Entry>();
  mail->set_title(protect<secure_string>("mail, \"quoted\"", false));
  mail->set_username(protect<secure_string>("alice", false));
  mail->set_password(protect<secure_string>("s3cret", true));
  mail->set_url(protect<secure_string>("https://example.com", false));
  mail->set_notes(protect<secure_string>("important, note", false));
  internet->AddEntry(mail);

  auto empty = std::make_shared<keepass::Group>();
  empty->set_name("Empty");

  auto root_entry = std::make_shared<keepass::Entry>();
  root_entry->set_title(protect<secure_string>("RootEntry", false));
  root_entry->set_username(protect<secure_string>("rootuser", false));
  root_entry->set_password(protect<secure_string>("toppass", true));
  root_entry->set_url(protect<secure_string>("https://root.example", false));

  root->AddEntry(root_entry);
  root->AddGroup(internet);
  root->AddGroup(empty);
  db->set_root(root);
  return db;
}

// Exports the test database using the CLI's own export dispatch.
void ExportFixture(const std::string& path) {
  EXPECT_NO_THROW({
    std::unique_ptr<keepass::Database> db = CreateTestDatabase();
    ExportDatabase(path, *db, keepass::Key("password"));
  });
  std::ifstream file(path);
  EXPECT_TRUE(file.is_open()) << "expected fixture file to be created: " << path;
}

// Exports a fresh copy of the fixture database for edit tests.
std::string CreateEditFixture(const std::string& name) {
  const std::string path = GetTmpPath(name);
  std::remove(path.c_str());
  ExportFixture(path);
  return path;
}

class KpxTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    std::remove(Kdbx().c_str());
    std::remove(Kdb().c_str());
    ExportFixture(Kdbx());
    ExportFixture(Kdb());
  }

  static void TearDownTestSuite() {
    std::remove(Kdbx().c_str());
    std::remove(Kdb().c_str());
    std::remove(GetTmpPath("cli-out.csv").c_str());
    std::remove(GetTmpPath("cli-export.kdbx").c_str());
    std::remove(GetTmpPath("cli-attached.csv").c_str());
    std::remove(GetTmpPath("cli-attached-export.kdbx").c_str());
  }

  static const std::string& Kdbx() {
    static const std::string path = GetTmpPath("cli-test.kdbx");
    return path;
  }

  static const std::string& Kdb() {
    static const std::string path = GetTmpPath("cli-test.kdb");
    return path;
  }
};

TEST_F(KpxTest, Help) {
  CliResult result = RunCli({"--help"});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("Usage: kpx [options] <database>"));
  EXPECT_NE(std::string::npos, result.out.find("--password"));
}

TEST_F(KpxTest, Version) {
  CliResult result = RunCli({"--version"});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find(kVersion));
}

TEST_F(KpxTest, NoInput) {
  CliResult result = RunCli({});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("Usage:"));
}

TEST_F(KpxTest, UnknownFormat) {
  CliResult result = RunCli({"-f", "yaml", Kdbx()});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("unknown format"));
}

TEST_F(KpxTest, MissingLongValue) {
  CliResult result = RunCli({"--password"});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("requires a value"));
}

TEST_F(KpxTest, UnknownLongOption) {
  CliResult result = RunCli({"--nope"});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("unknown option '--nope'"));
}

TEST_F(KpxTest, MissingShortValue) {
  CliResult result = RunCli({"-p"});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("option '-p' requires a value"));
}

TEST_F(KpxTest, UnknownShortOption) {
  CliResult result = RunCli({"-z"});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("unknown option '-z'"));
}

TEST_F(KpxTest, ExtraPositionalArgument) {
  CliResult result = RunCli({"a.kdbx", "b.kdbx"});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("unexpected extra argument 'b.kdbx'"));
}

TEST_F(KpxTest, TextOutput) {
  CliResult result = RunCli({"-p", "password", "-f", "text", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("root/"));
  EXPECT_NE(std::string::npos, result.out.find("    Internet/"));
  EXPECT_NE(std::string::npos, result.out.find("- mail, \"quoted\" (alice) [https://example.com]"));
  EXPECT_NE(std::string::npos, result.out.find("    Empty/"));
  EXPECT_EQ(std::string::npos, result.out.find("s3cret"));
}

TEST_F(KpxTest, TextOutputWithPasswords) {
  CliResult result = RunCli({"-p", "password", "--with-passwords", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("password: s3cret"));
  EXPECT_NE(std::string::npos, result.out.find("notes: important, note"));
}

TEST_F(KpxTest, CsvOutput) {
  CliResult result = RunCli({"-p", "password", "-f", "csv", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("Group,Title,Username,Password,Url,Notes"));
  EXPECT_NE(std::string::npos,
            result.out.find("Internet,\"mail, \"\"quoted\"\"\",alice,,https://example.com,"
                            "\"important, note\""));
}

TEST_F(KpxTest, JsonOutput) {
  CliResult result = RunCli({"-p", "password", "-f", "json", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_EQ('{', result.out[0]);
  EXPECT_NE(std::string::npos, result.out.find("quoted"));
}

TEST_F(KpxTest, LongOptionSeparateValue) {
  CliResult result = RunCli({"--password", "password", "--format=json", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_EQ('{', result.out[0]);
}

TEST_F(KpxTest, ShortOptionAttachedValue) {
  CliResult result = RunCli({"-ppassword", "-f", "json", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_EQ('{', result.out[0]);
}

TEST_F(KpxTest, OutputToFile) {
  const std::string output_path = GetTmpPath("cli-out.csv");
  std::remove(output_path.c_str());

  CliResult result = RunCli({"-p", "password", "-f", "csv", "-o", output_path, Kdbx()});
  EXPECT_EQ(0, result.code);

  std::string file = ReadFile(output_path);
  EXPECT_NE(std::string::npos, file.find("Group,Title,Username,Password,Url,Notes"));
  EXPECT_NE(std::string::npos, file.find("alice"));
}

TEST_F(KpxTest, OutputToFileFails) {
  CliResult result = RunCli({"-p", "password", "-o", "/nonexistent/dir/cli-out", Kdbx()});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("cannot open output file"));
}

TEST_F(KpxTest, ExportToKdbx) {
  const std::string export_path = GetTmpPath("cli-export.kdbx");
  std::remove(export_path.c_str());

  CliResult result = RunCli({"-p", "password", "-e", export_path, Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_FALSE(ReadFile(export_path).empty());
}

TEST_F(KpxTest, ExportToKdbxVerbose) {
  const std::string export_path = GetTmpPath("cli-export.kdbx");

  CliResult result = RunCli({"-p", "password", "-v", "-e", export_path, Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.err.find("exported to"));
}

TEST_F(KpxTest, KdbInput) {
  CliResult result = RunCli({"-p", "password", "-v", Kdb()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.err.find("(kdb)"));
  EXPECT_NE(std::string::npos, result.out.find("- mail, \"quoted\" (alice) [https://example.com]"));
  EXPECT_EQ(std::string::npos, result.out.find("s3cret"));
}

TEST_F(KpxTest, WrongPassword) {
  CliResult result = RunCli({"-p", "wrong_password", Kdbx()});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("error:"));
}

TEST_F(KpxTest, MissingFile) {
  CliResult result = RunCli({"-p", "password", GetTmpPath("does-not-exist.kdbx")});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("error:"));
}

TEST_F(KpxTest, PasswordFromEnvironment) {
  EnvGuard env("KEEPASS_PASSWORD", "password");
  CliResult result = RunCli({Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("- mail, \"quoted\" (alice) [https://example.com]"));
}

TEST_F(KpxTest, KeyFile) {
  const std::string database = GetDataPath("complex-1-key_pw-aes.kdbx");
  const std::string keyfile = GetDataPath("complex-1-key_pw-aes.key");

  CliResult result = RunCli({"-p", "password", "-k", keyfile, database});
  EXPECT_EQ(0, result.code);
  EXPECT_GT(result.out.size(), 0);
}

TEST_F(KpxTest, DoubleDashSeparator) {
  CliResult result = RunCli({"-p", "password", "--", "-f"});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("error:"));
}

TEST_F(KpxTest, DoubleDashMultipleRestArgs) {
  CliResult result = RunCli({"-p", "password", "--", "-f", "other.kdbx"});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("unexpected extra argument 'other.kdbx'"));
}

TEST_F(KpxTest, LongOptionsMissingValues) {
  for (const char* option : {"--keyfile", "--format", "--output", "--export"}) {
    CliResult result = RunCli({option});
    EXPECT_EQ(1, result.code) << option;
    EXPECT_NE(std::string::npos, result.err.find("requires a value")) << option;
  }
}

TEST_F(KpxTest, ShortOptionsMissingValues) {
  for (const char* option : {"-k", "-f", "-o", "-e"}) {
    CliResult result = RunCli({option});
    EXPECT_EQ(1, result.code) << option;
    EXPECT_NE(std::string::npos, result.err.find("requires a value")) << option;
  }
}

TEST_F(KpxTest, ShortOptionAttachedValues) {
  const std::string output_path = GetTmpPath("cli-attached.csv");
  const std::string export_path = GetTmpPath("cli-attached-export.kdbx");
  std::remove(output_path.c_str());
  std::remove(export_path.c_str());

  CliResult format = RunCli({"-fjson", "-p", "password", Kdbx()});
  EXPECT_EQ(0, format.code);
  EXPECT_EQ('{', format.out[0]);

  CliResult out = RunCli({"-o" + output_path, "-p", "password", Kdbx()});
  EXPECT_EQ(0, out.code);
  EXPECT_FALSE(ReadFile(output_path).empty());

  CliResult exp = RunCli({"-e" + export_path, "-p", "password", Kdbx()});
  EXPECT_EQ(0, exp.code);
  EXPECT_FALSE(ReadFile(export_path).empty());

  const std::string database = GetDataPath("complex-1-key_pw-aes.kdbx");
  const std::string keyfile = GetDataPath("complex-1-key_pw-aes.key");
  CliResult key = RunCli({"-k" + keyfile, "-p", "password", database});
  EXPECT_EQ(0, key.code);
  EXPECT_GT(key.out.size(), 0);
}

TEST_F(KpxTest, RootEntryPrinted) {
  CliResult result = RunCli({"-p", "password", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("- RootEntry (rootuser) [https://root.example]"));
}

TEST_F(KpxTest, ParseArgsOverrides) {
  Options opt;
  const char* argv[] = {
      "kpx",      "-ppw", "--password", "pw2", "--keyfile",        "kf",        "--format", "csv",
      "--output", "out",  "--export",   "exp", "--with-passwords", "--verbose", "-h",       "db"};
  EXPECT_TRUE(ParseArgs(16, argv, opt));
  EXPECT_EQ("db", opt.input);
  EXPECT_EQ("pw2", opt.password);
  EXPECT_EQ("kf", opt.keyfile);
  EXPECT_EQ("csv", opt.format);
  EXPECT_EQ("out", opt.output);
  EXPECT_EQ("exp", opt.export_path);
  EXPECT_TRUE(opt.with_passwords);
  EXPECT_TRUE(opt.verbose);
  EXPECT_TRUE(opt.help);
}

TEST_F(KpxTest, IsKdbPath) {
  EXPECT_TRUE(IsKdbPath("database.kdb"));
  EXPECT_TRUE(IsKdbPath("DATABASE.KDB"));
  EXPECT_FALSE(IsKdbPath("database.kdbx"));
}

TEST_F(KpxTest, ResolvePasswordPrecedence) {
  Options opt;
  opt.password = "explicit";
  EXPECT_EQ("explicit", ResolvePassword(opt));

  Options env_opt;
  {
    EnvGuard env("KEEPASS_PASSWORD", "from_env");
    EXPECT_EQ("from_env", ResolvePassword(env_opt));
  }

#ifndef _WIN32
  if (!isatty(STDIN_FILENO)) {
    Options empty_opt;
    EXPECT_TRUE(ResolvePassword(empty_opt).empty());
  }
#endif
}

TEST_F(KpxTest, PrintUsage) {
  std::stringstream os;
  PrintUsage("prog", os);
  EXPECT_NE(std::string::npos, os.str().find("Usage: prog [options] <database>"));
  EXPECT_NE(std::string::npos, os.str().find("Exit code: 0 on success, 1 on any error."));
}

TEST_F(KpxTest, SearchFiltersTextOutput) {
  CliResult result = RunCli({"-p", "password", "--search", "ALICE", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("- mail, \"quoted\" (alice) [https://example.com]"));
  EXPECT_EQ(std::string::npos, result.out.find("RootEntry"));
  EXPECT_EQ(std::string::npos, result.out.find("Empty/"));
}

TEST_F(KpxTest, SearchMatchesNotesAndUrl) {
  CliResult by_url = RunCli({"-p", "password", "--search", "root.example", Kdbx()});
  EXPECT_EQ(0, by_url.code);
  EXPECT_NE(std::string::npos, by_url.out.find("RootEntry"));
  EXPECT_EQ(std::string::npos, by_url.out.find("mail"));

  CliResult by_notes = RunCli({"-p", "password", "--search", "IMPORTANT", Kdbx()});
  EXPECT_EQ(0, by_notes.code);
  EXPECT_NE(std::string::npos, by_notes.out.find("mail"));
}

TEST_F(KpxTest, SearchNoMatchPrintsEmptyTree) {
  CliResult result = RunCli({"-p", "password", "--search", "doesnotexist", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("root/"));
  EXPECT_EQ(std::string::npos, result.out.find("Internet"));
}

TEST_F(KpxTest, SearchRegex) {
  CliResult result = RunCli({"-p", "password", "--search", "q[uo]oted", "--regex", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("mail"));
  EXPECT_EQ(std::string::npos, result.out.find("RootEntry"));
}

TEST_F(KpxTest, SearchInvalidRegex) {
  CliResult result = RunCli({"-p", "password", "--search", "[", "--regex", Kdbx()});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("invalid regular expression"));
}

TEST_F(KpxTest, SearchCsvAndJson) {
  CliResult csv = RunCli({"-p", "password", "--search", "alice", "-f", "csv", Kdbx()});
  EXPECT_EQ(0, csv.code);
  EXPECT_NE(std::string::npos, csv.out.find("Group,Title,Username,Password,Url,Notes"));
  EXPECT_NE(std::string::npos, csv.out.find("alice"));
  EXPECT_EQ(std::string::npos, csv.out.find("RootEntry"));

  CliResult json = RunCli({"-p", "password", "--search", "quoted", "-f", "json", Kdbx()});
  EXPECT_EQ(0, json.code);
  EXPECT_EQ('{', json.out[0]);
  EXPECT_NE(std::string::npos, json.out.find("quoted"));
}

TEST_F(KpxTest, GroupFilter) {
  CliResult text = RunCli({"-p", "password", "--group", "Empty", Kdbx()});
  EXPECT_EQ(0, text.code);
  EXPECT_NE(std::string::npos, text.out.find("Empty/"));
  EXPECT_EQ(std::string::npos, text.out.find("Internet"));

  CliResult csv = RunCli({"-p", "password", "--group", "Internet", "-f", "csv", Kdbx()});
  EXPECT_EQ(0, csv.code);
  EXPECT_NE(std::string::npos, csv.out.find("alice"));
  EXPECT_EQ(std::string::npos, csv.out.find("RootEntry"));
}

TEST_F(KpxTest, GroupNotFound) {
  CliResult result = RunCli({"-p", "password", "--group", "Missing", Kdbx()});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("group 'Missing' not found"));
}

TEST_F(KpxTest, GroupAndSearchCombined) {
  CliResult result = RunCli({"-p", "password", "--group", "Internet", "--search", "alice", Kdbx()});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("Internet/"));
  EXPECT_NE(std::string::npos, result.out.find("mail"));
  EXPECT_EQ(std::string::npos, result.out.find("RootEntry"));
}

TEST_F(KpxTest, GeneratePasswordDefault) {
  CliResult result = RunCli({"--generate"});
  EXPECT_EQ(0, result.code);
  const std::string password = result.out.substr(0, result.out.size() - 1);
  EXPECT_EQ(16, password.size());
  for (const char c : password)
    EXPECT_NE(std::string::npos, std::string(kGenerateCharset).find(c))
        << "unexpected character '" << c << "'";
}

TEST_F(KpxTest, GeneratePasswordLength) {
  CliResult short_pw = RunCli({"--generate", "10"});
  EXPECT_EQ(0, short_pw.code);
  EXPECT_EQ(10, short_pw.out.size() - 1);

  CliResult attached = RunCli({"--generate=64"});
  EXPECT_EQ(0, attached.code);
  EXPECT_EQ(64, attached.out.size() - 1);
}

TEST_F(KpxTest, GeneratePasswordInvalidLength) {
  CliResult zero = RunCli({"--generate", "0"});
  EXPECT_EQ(1, zero.code);
  EXPECT_NE(std::string::npos, zero.err.find("length between 1 and 256"));

  CliResult too_long = RunCli({"--generate", "999"});
  EXPECT_EQ(1, too_long.code);
  EXPECT_NE(std::string::npos, too_long.err.find("length between 1 and 256"));

  CliResult non_numeric = RunCli({"--generate=abc"});
  EXPECT_EQ(1, non_numeric.code);
  EXPECT_NE(std::string::npos, non_numeric.err.find("length between 1 and 256"));
}

TEST_F(KpxTest, AddEntryToRoot) {
  const std::string db = CreateEditFixture("cli-edit-add-root.kdbx");

  CliResult result =
      RunCli({"-p", "password", "add", "--title", "Added", "--user", "newu", "--pass", "pw123",
              "--url", "https://added.example", "--notes", "a note", db});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("added entry 'Added' to 'root'"));

  CliResult printed = RunCli({"-p", "password", "--search", "Added", "--with-passwords", db});
  EXPECT_NE(std::string::npos, printed.out.find("- Added (newu) [https://added.example]"));
  EXPECT_NE(std::string::npos, printed.out.find("password: pw123"));

  std::remove(db.c_str());
}

TEST_F(KpxTest, AddEntryToGroup) {
  const std::string db = CreateEditFixture("cli-edit-add-group.kdbx");

  CliResult result = RunCli(
      {"-p", "password", "add", "--group", "Internet", "--title", "Grouped", "--user", "guy", db});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("added entry 'Grouped' to 'Internet'"));

  CliResult printed = RunCli({"-p", "password", "--group", "Internet", db});
  EXPECT_NE(std::string::npos, printed.out.find("- Grouped (guy)"));

  std::remove(db.c_str());
}

TEST_F(KpxTest, AddEntryMissingGroup) {
  const std::string db = CreateEditFixture("cli-edit-add-badgroup.kdbx");
  CliResult result = RunCli({"-p", "password", "add", "--group", "Nope", "--title", "X", db});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("group 'Nope' not found"));
  std::remove(db.c_str());
}

TEST_F(KpxTest, AddEntryRequiresTitle) {
  CliResult result = RunCli({"-p", "password", "add", Kdbx()});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("add requires --title"));
}

TEST_F(KpxTest, AddEntryWithGeneratedPassword) {
  const std::string db = CreateEditFixture("cli-edit-add-gen.kdbx");

  CliResult result = RunCli({"-p", "password", "add", "--title", "Gen", "--generate", "24", db});
  EXPECT_EQ(0, result.code);

  CliResult printed = RunCli({"-p", "password", "--search", "Gen", "--with-passwords", db});
  const std::size_t pos = printed.out.find("password: ");
  ASSERT_NE(std::string::npos, pos);
  const std::string password =
      printed.out.substr(pos + 10, printed.out.find('\n', pos) - (pos + 10));
  EXPECT_EQ(24, password.size());

  std::remove(db.c_str());
}

TEST_F(KpxTest, UpdateEntries) {
  const std::string db = CreateEditFixture("cli-edit-update.kdbx");

  CliResult result = RunCli(
      {"-p", "password", "update", "--search", "quoted", "--user", "updated", "--notes", "n2", db});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("updated 1 entry"));

  CliResult printed = RunCli({"-p", "password", "--search", "quoted", db});
  EXPECT_NE(std::string::npos, printed.out.find("- mail, \"quoted\" (updated)"));

  std::remove(db.c_str());
}

TEST_F(KpxTest, UpdateAllMatches) {
  const std::string db = CreateEditFixture("cli-edit-update-all.kdbx");

  CliResult result = RunCli({"-p", "password", "update", "--search", "e", "--notes", "common", db});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("updated 2 entries"));

  std::remove(db.c_str());
}

TEST_F(KpxTest, UpdateNoMatch) {
  const std::string db = CreateEditFixture("cli-edit-update-nomatch.kdbx");
  CliResult result = RunCli({"-p", "password", "update", "--search", "zzz", "--user", "x", db});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("no entries match 'zzz'"));
  std::remove(db.c_str());
}

TEST_F(KpxTest, UpdateRequiresSearch) {
  CliResult result = RunCli({"-p", "password", "update", "--user", "x", Kdbx()});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("update requires --search"));
}

TEST_F(KpxTest, UpdateRequiresField) {
  CliResult result = RunCli({"-p", "password", "update", "--search", "quoted", Kdbx()});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("update requires at least one"));
}

TEST_F(KpxTest, UpdateInvalidRegex) {
  const std::string db = CreateEditFixture("cli-edit-update-regex.kdbx");
  CliResult result =
      RunCli({"-p", "password", "update", "--search", "[", "--regex", "--title", "x", db});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("invalid regular expression"));
  std::remove(db.c_str());
}

TEST_F(KpxTest, RemoveByTitle) {
  const std::string db = CreateEditFixture("cli-edit-rm-title.kdbx");

  CliResult result = RunCli({"-p", "password", "rm", "--title", "RootEntry", db});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("removed 1 entry"));

  CliResult printed = RunCli({"-p", "password", db});
  EXPECT_EQ(std::string::npos, printed.out.find("RootEntry"));
  EXPECT_NE(std::string::npos, printed.out.find("mail"));

  std::remove(db.c_str());
}

TEST_F(KpxTest, RemoveBySearch) {
  const std::string db = CreateEditFixture("cli-edit-rm-search.kdbx");

  CliResult result = RunCli({"-p", "password", "rm", "--search", "rootuser", db});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("removed 1 entry"));

  CliResult printed = RunCli({"-p", "password", db});
  EXPECT_EQ(std::string::npos, printed.out.find("RootEntry"));
  EXPECT_NE(std::string::npos, printed.out.find("mail"));

  std::remove(db.c_str());
}

TEST_F(KpxTest, RemoveGroup) {
  const std::string db = CreateEditFixture("cli-edit-rm-group.kdbx");

  CliResult result = RunCli({"-p", "password", "rm", "--group", "Empty", db});
  EXPECT_EQ(0, result.code);
  EXPECT_NE(std::string::npos, result.out.find("removed group 'Empty'"));

  CliResult printed = RunCli({"-p", "password", db});
  EXPECT_EQ(std::string::npos, printed.out.find("Empty/"));
  EXPECT_NE(std::string::npos, printed.out.find("Internet/"));

  std::remove(db.c_str());
}

TEST_F(KpxTest, RemoveMissingGroup) {
  const std::string db = CreateEditFixture("cli-edit-rm-badgroup.kdbx");
  CliResult result = RunCli({"-p", "password", "rm", "--group", "Nope", db});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("group 'Nope' not found"));
  std::remove(db.c_str());
}

TEST_F(KpxTest, RemoveNoMatch) {
  const std::string db = CreateEditFixture("cli-edit-rm-nomatch.kdbx");
  CliResult result = RunCli({"-p", "password", "rm", "--search", "zzz", db});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("no matching entries"));
  std::remove(db.c_str());
}

TEST_F(KpxTest, RemoveRequiresSelector) {
  CliResult result = RunCli({"-p", "password", "rm", Kdbx()});
  EXPECT_EQ(1, result.code);
  EXPECT_NE(std::string::npos, result.err.find("rm requires"));
}

TEST_F(KpxTest, ParseArgsEditOptions) {
  Options opt;
  const char* argv[] = {"kpx",    "--search",   "q",      "--regex", "--group",
                        "g",      "--generate", "20",     "--title", "t",
                        "--user", "u",          "--pass", "pw",      "--url",
                        "url",    "--notes",    "n",      "add",     "db"};
  const int argc = static_cast<int>(sizeof(argv) / sizeof(argv[0]));
  EXPECT_TRUE(ParseArgs(argc, argv, opt));
  EXPECT_EQ("add", opt.command);
  EXPECT_EQ("db", opt.input);
  EXPECT_EQ("q", opt.search);
  EXPECT_TRUE(opt.regex);
  EXPECT_EQ("g", opt.group);
  EXPECT_EQ(20, opt.generate);
  EXPECT_TRUE(opt.has_title);
  EXPECT_TRUE(opt.has_user);
  EXPECT_TRUE(opt.has_pass);
  EXPECT_TRUE(opt.has_url);
  EXPECT_TRUE(opt.has_notes);
  EXPECT_EQ("t", opt.title);
  EXPECT_EQ("u", opt.user);
  EXPECT_EQ("pw", opt.entry_password);
  EXPECT_EQ("url", opt.url);
  EXPECT_EQ("n", opt.notes);
}

TEST_F(KpxTest, ParseArgsRmCommand) {
  Options opt;
  const char* argv[] = {"kpx", "rm", "--search", "q", "db"};
  const int argc = static_cast<int>(sizeof(argv) / sizeof(argv[0]));
  EXPECT_TRUE(ParseArgs(argc, argv, opt));
  EXPECT_EQ("rm", opt.command);
  EXPECT_EQ("q", opt.search);
  EXPECT_EQ("db", opt.input);
}

TEST_F(KpxTest, ParseArgsGenerateWithoutValue) {
  Options opt;
  const char* argv[] = {"kpx", "--generate", "db"};
  const int argc = static_cast<int>(sizeof(argv) / sizeof(argv[0]));
  EXPECT_TRUE(ParseArgs(argc, argv, opt));
  EXPECT_EQ(kDefaultGenerateLength, opt.generate);
  EXPECT_EQ("db", opt.input);
}

TEST_F(KpxTest, GenerateCharSetIsPrintable) {
  CliResult result = RunCli({"--generate", "128"});
  EXPECT_EQ(0, result.code);
  const std::string password = result.out.substr(0, result.out.size() - 1);
  EXPECT_EQ(128, password.size());
  for (const char c : password) {
    EXPECT_NE(std::string::npos, std::string(kGenerateCharset).find(c))
        << "unexpected character '" << c << "'";
    EXPECT_TRUE(std::isprint(static_cast<unsigned char>(c)));
  }
}

} // namespace