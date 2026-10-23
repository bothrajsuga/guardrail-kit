# Google ADK compatibility

Google ADK is optional. Core SQL validation does not import it. Install the integration with `pip install 'guardrail-kit[google-adk]'`.

| ADK version | Python tested | APIs exercised | Private API | Execution and callback mutation test | Status |
| --- | --- | --- | --- | --- | --- |
| 2.0.0 | 3.12 | BaseTool with core metadata only | `_get_declaration` | 36 passed, including real-runner mutation test | **Tested compatible** |
| 2.3.0 | 3.12 | BaseTool with core metadata only | `_get_declaration` | 36 passed, including real-runner mutation test | **Tested compatible** |
| 2.6.0 | 3.12 | Adds `response_scheduling` metadata | `_get_declaration` | 36 passed, including real-runner mutation test | **Tested compatible** |
| 2.9.2 | 3.12 | BaseTool without `behavior`; adapter omits unavailable metadata | `_get_declaration` | 36 passed, including real-runner mutation test | **Tested compatible** |
| 2.10.0 | 3.12 | BaseTool, FunctionTool, App, LlmAgent, InMemoryRunner | `_get_declaration` | 36 passed, including real-runner mutation test | **Supported** |
| 2.11.0 | 3.12 | Same verified surface | `_get_declaration` | 36 passed, including real-runner mutation test | **Supported** |
| 2.12.0 | 3.12 | Same verified surface | `_get_declaration` | 36 passed, including real-runner mutation test | **Supported** |

Unlisted releases in the `2.x` series are **expected compatible** through the same capability adapter, but are not individually claimed as tested. Releases newer than 2.12.0 are also expected compatible only after the latest-version CI job succeeds.

The declared range is `google-adk>=2.0.0`; 2.0.0 is a published release. The adapter copies only metadata accepted by the installed BaseTool constructor, while requiring the registration capabilities that preserve guarded `run_async`. Unknown future releases are expected, not verified, and fail closed if those capabilities disappear. CI tests historical API points and a separately resolved latest release so breakage is visible.

The private `_get_declaration` dependency is currently unavoidable: it delegates only schema declaration while ensuring ADK registers the guarded wrapper's `run_async`, not the original callable. SQL is validated immediately inside that method before the exact argument dictionary is passed to the protected tool. Missing or invalid SQL, rejected SQL, and validator exceptions never invoke the protected callable. Custom `process_llm_request` implementations are rejected because they can replace registration with an unguarded tool.

The compatibility callback and plugin provide early rejection but are not an execution boundary because later callbacks may mutate arguments. Streaming and live tool execution are not claimed as supported. Only Python 3.12 is used for the multi-version integration matrix. Google ADK 2.0–2.11 metadata permits Python 3.10+, while 2.12 requires Python 3.11+; guardrail-kit itself requires Python 3.11+.
