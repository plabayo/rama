# JSONPath compliance test suite (vendored)

The files in this directory are vendored from
[jsonpath-standard/jsonpath-compliance-test-suite](https://github.com/jsonpath-standard/jsonpath-compliance-test-suite)
at commit `7be7c1fc28057c91e8eefaf197060fba7ed43acd`.

## How rama uses this corpus

`rama-json` implements the RFC 9535 selectors that can be matched from the
concrete path of a value observed by a forward streaming parser. The compliance
runner therefore splits the corpus into:

- selectors supported by rama's streaming matcher, which must produce the CTS
  values and concrete paths;
- selectors that require unsupported RFC features, such as filters or
  end-relative array selectors, which must be rejected explicitly instead of
  being parsed with different semantics.

The upstream `cts.json` and `cts.schema.json` files are kept verbatim.

