from conan import ConanFile
from conan.tools.cmake import CMakeDeps, CMakeToolchain, cmake_layout


class ClientWardenConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"

    # The core only uses Boost.URL; skip the compiled components it doesn't need (some don't
    # build with every toolchain, e.g. cobalt with GCC 14 or context with MinGW).
    default_options = {
        f"boost/*:without_{component}": True
        for component in ("cobalt", "context", "coroutine", "fiber", "process", "stacktrace",
                          "log", "locale", "wave", "graph", "graph_parallel", "mpi", "python",
                          "test", "contract", "nowide", "iostreams", "serialization", "timer",
                          "type_erasure", "cobalt")
    }

    def requirements(self):
        self.requires("botan/3.11.1")
        self.requires("nlohmann_json/3.12.0")
        self.requires("cpp-httplib/0.47.0")
        self.requires("openssl/3.6.3")
        self.requires("boost/1.91.0")
        self.requires("spdlog/1.17.0")
        self.requires("msgpack-cxx/7.0.0")

    def layout(self):
        cmake_layout(self)