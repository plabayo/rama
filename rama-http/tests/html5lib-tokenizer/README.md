# html5lib tokenizer test corpus (vendored)

The `*.test` files in this directory are the **tokenizer** test data from
[html5lib/html5lib-tests](https://github.com/html5lib/html5lib-tests).

## How rama uses this corpus

rama's tokenizer (`rama_http::protocols::html::tokenizer`) is a
**byte-faithful** streaming tokenizer: it exposes raw byte spans and does
**not** entity-decode text/attribute values (decoding is a separate, opt-in
step). html5lib's expected `output` is an *entity-decoded* token stream, so
we do not compare token streams field-for-field against it.

Instead the corpus is exercised for the property that actually matters for a
rewriter: **identity** — every test `input` must tokenize and re-serialize
back to the exact same bytes. This runs each input (including the
`doubleEscaped` ones) through the tokenizer over the full, real-world set of
adversarial cases. Structural correctness is covered by the in-crate unit
tests.
