#pragma once
#include <string>
#include <vector>
namespace catl {
// XTree-Gold-style interactive browser. Returns a process exit code.
int
runTui(std::vector<std::string> const& paths);
}  // namespace catl
