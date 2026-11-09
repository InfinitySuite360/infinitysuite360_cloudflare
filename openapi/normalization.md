# Schema normalization

Cloudflare's official OpenAPI schema ([cloudflare/api-schemas](https://github.com/cloudflare/api-schemas)) contains a few
constructs that Kiota cannot turn into C#. `tools/generate.cs` rewrites them before generation. The rules are generic
(no per-schema patches), so they keep working when the schema changes. None of them changes the wire format: requests and
responses stay byte-compatible with the API; at most a type becomes less specific.

| Rule | Problem in the schema | Rewrite | Effect on the generated client |
|---|---|---|---|
| R1 | `enum` containing `""` (empty string) | enum removed, type stays `string` | value is a `string` instead of a C# enum |
| R2 | object with `properties` but no `type` | `type: object` added | none (typed as before) |
| R3a | `allOf` with a single `$ref` and no own properties (often used only to attach `description`, `example` or `minLength`) | replaced by the plain `$ref` | none; no extra wrapper class |
| R3b | `allOf` member that is a pure union or an empty object, next to own properties | member dropped, `additionalProperties: true` | fields of the dropped union land in `AdditionalData` |
| R4 | `allOf` of primitives only (for example `uuid` + `minLength`) | merged into one primitive schema | none |
| R5 | nested unions (`anyOf` of `oneOf`) | flattened into one union | none |
| R6 | union of objects without `type` | `type: object` added | none |
| R7 | inline `allOf` union member without `type` | `type: object` added | none |
| R8 | literal `-` path segment (wildcard) | path parameter `wildcard` with default `-` | pass `"-"` for the segment |
| R9 | component schema that is only a `$ref` (alias) | references point to the final target, aliases removed | none; one class per real schema |
| R10 | derived schema overrides an inherited property and gives it a `default` (for example zone settings) | that `default` is removed | the property starts empty instead of pre-filled; the server still applies its default |

After generation one fix is applied to the generated code:

| Fix | Problem | Fix | Effect |
|---|---|---|---|
| P1 | a literal path segment `item` becomes a property `Item`, which collides with the C# indexer (metadata name `Item`) | `[IndexerName("ItemAt")]` on the indexer | none for C# callers (`builder[id]` and `builder.Item` both work) |

`openapi/COVERAGE.md` lists how often each rule was applied for the pinned schema version.
