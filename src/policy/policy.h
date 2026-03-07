#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "scheme.h"

namespace cs::policy
{

std::vector<uint8_t> load_policy_bytes(const std::string &path,
                                       size_t max_size_bytes = (1ull << 20));

void canonicalize_policy(const std::vector<uint8_t> &in,
                         std::vector<uint8_t> &out_canon,
                         policy_summary &out_summary);

void load_canonical_policy(const std::string &path,
                           std::vector<uint8_t> &out_canon,
                           policy_summary &out_summary,
                           size_t max_size_bytes = (1ull << 20));

void load_and_canonicalize_policy(const std::string &path,
                                  std::vector<uint8_t> &out_input,
                                  std::vector<uint8_t> &out_canon,
                                  policy_summary &out_summary,
                                  bool &out_input_was_canonical,
                                  size_t max_size_bytes = (1ull << 20));

} // namespace cs::policy