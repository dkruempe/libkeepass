class Libkeepass < Formula
  desc "C++17 library for importing and exporting KeePass databases"
  homepage "https://github.com/dkruempe/libkeepass"
  url "https://github.com/dkruempe/libkeepass/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "7660e099916f2d3ac561370ad66e317263867a36a4dcf8c71f5bb157a676bc47"
  license "GPL-3.0-only"
  head "https://github.com/dkruempe/libkeepass.git", branch: "master"

  depends_on "argon2"
  depends_on "cmake" => :build
  depends_on "openssl@3"
  depends_on "pugixml"
  depends_on "zlib"

  def install
    args = std_cmake_args + %w[
      -DLIBKEEPASS_CONAN_CREATE=ON
      -DBUILD_TESTING=OFF
      -DLIBKEEPASS_BUILD_SHARED=ON
      -DLIBKEEPASS_BUILD_C_API=ON
    ]

    system "cmake", "-S", ".", "-B", "build", *args
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end

  test do
    (testpath/"test.cc").write <<~CPP
      #include <libkeepass/database.hh>
      int main() { keepass::Database db; return db.EntryCount() == 0 ? 0 : 1; }
    CPP
    system ENV.cxx, "-std=c++17", "test.cc", "-o", "test",
           "-I#{include}", "-L#{lib}", "-llibkeepass",
           "-lssl", "-lcrypto", "-lz", "-lpugixml", "-largon2"
    system "./test"
  end
end
