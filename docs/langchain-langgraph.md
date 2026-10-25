# LangChain and LangGraph integration

Install the integration explicitly:

```bash
pip install 'guardrail-kit[langchain]'
pip install 'guardrail-kit[langgraph]'
```

Phase 3 is verified with `langchain-core==1.7.0`, `langgraph==1.2.17`, and
`langgraph-prebuilt==1.1.1`. The declared compatibility range is the tested
major line (`>=1.0,<2`); releases other than those named versions are not
individually certified.

## LangChain tools

```python
from guardrail_kit.integrations.langchain import ToolGuardPolicy, guard_tool

secured = guard_tool(
    original_tool,
    policy=ToolGuardPolicy(
        sql_validator=validator,
        sql_argument="query",
        input_guard=redacting_pii_guard,
        output_guard=redacting_pii_guard,
    ),
)
result = secured.invoke({"query": "SELECT id FROM users LIMIT 10"})
result = await secured.ainvoke({"query": "SELECT id FROM users LIMIT 10"})
```

`BaseTool` and `StructuredTool` instances using their standard schema-driven
invocation path are supported. `invoke`, `ainvoke`, `run`, `arun`, `batch`, and
`abatch` converge on the wrapper's execution boundary. The name, description,
argument schema, tags, metadata, `return_direct`, and response format are
preserved. Framework callback configuration is intentionally not forwarded to
the protected tool; attach observability to the guarded tool and never log raw
arguments or results.

The SQL validator checks the configured top-level argument. The PII guard walks
string values in dictionaries, lists, and tuples. Masked or redacted copies are
passed to the tool without mutating the caller's containers. Dictionary keys
and arbitrary custom objects are not inspected. Custom input hooks receive a
deeply immutable view and return exactly `True` to allow execution; false
results and exceptions block.

Policy and protected-tool exceptions become `GuardedToolError` with a stable,
value-free reason. A block never invokes the protected tool. Output inspection
happens after execution and therefore cannot undo database writes, network
requests, or any other side effect. Use input authorization and least-privilege
credentials as the primary control.

Schema-validation failures are converted to a fixed safe message because
Pydantic's default error text can contain the rejected input. When PII masking
or redaction and SQL validation are both enabled, transformation runs first and
the exact final SQL passed to the tool is then parsed and authorized. A
transformation that makes SQL invalid therefore blocks execution.

## LangGraph ToolNode

```python
from guardrail_kit.integrations.langgraph import create_guarded_tool_node

node = create_guarded_tool_node(
    [search_tool, query_tool],
    policies={"search": search_policy, "query": query_policy},
)
```

The helper refuses an unconfigured tool, wraps each tool, and returns a normal
`ToolNode`. It is verified inside a compiled `StateGraph` for synchronous,
asynchronous, multiple, and concurrent tool calls. Tool errors may be converted
to safe error `ToolMessage` objects by `handle_errors=True`.

Protection is attached to the returned wrappers, not to the original tools or
the graph globally. Invoking an original tool directly, registering it in a
different node, dynamically replacing tools, or routing around the guarded
node bypasses this integration. Subgraphs are protected only where they use the
guarded tools. Dynamic tool registration and custom `BaseTool` invocation
overrides are unsupported. Incremental/token streaming and remote/distributed
tool executors have not been independently verified and are not claimed. Graph
state is inspected only when it is supplied as a declared tool argument.
