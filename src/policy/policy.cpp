#include "policy.h"

#include <vector>

#include "../io_utils/io_utils.h"

namespace cs::policy
{

std::vector<uint8_t> load_policy_bytes(const std::string &path, size_t max_size_bytes)
{
    return cs::io_utils::read_file_all(path, max_size_bytes);
}

void canonicalize_policy(const std::vector<uint8_t> &in,
                         std::vector<uint8_t> &out_canon,
                         policy_summary &out_summary)
{
    cs::policy_error err;
    if (!cs::policy_parse_validate_canonical(in, out_canon, out_summary, err))
        cs::io_utils::die("policy invalid: " + err.msg);
}

void load_canonical_policy(const std::string &path,
                           std::vector<uint8_t> &out_canon,
                           policy_summary &out_summary,
                           size_t max_size_bytes)
{
    const auto input = load_policy_bytes(path, max_size_bytes);
    canonicalize_policy(input, out_canon, out_summary);
}

void load_and_canonicalize_policy(const std::string &path,
                                  std::vector<uint8_t> &out_input,
                                  std::vector<uint8_t> &out_canon,
                                  policy_summary &out_summary,
                                  bool &out_input_was_canonical,
                                  size_t max_size_bytes)
{
    out_input = load_policy_bytes(path, max_size_bytes);
    canonicalize_policy(out_input, out_canon, out_summary);
    out_input_was_canonical = (out_input == out_canon);
}

} // namespace cs::policy