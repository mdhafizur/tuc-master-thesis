# Code Guardian Sequence Diagram

sequenceDiagram
    participant User
    participant VSCode
    participant Extension as Code Guardian
    participant Webview
    participant LLM Server

    %% Function Analysis (Real-time)
    User->>VSCode: Edits code / moves cursor in function
    VSCode->>Extension: Triggers real-time function analysis
    Extension->>LLM Server: Sends function code for security analysis
    LLM Server-->>Extension: Returns issues & fix suggestions (JSON)
    Extension->>VSCode: Reports diagnostics & quick fixes (💡)

    %% File Analysis
    User->>VSCode: Runs "Analyze Full File" command
    VSCode->>Extension: Triggers file analysis
    Extension->>LLM Server: Sends full file for security analysis
    LLM Server-->>Extension: Returns issues & fix suggestions (JSON)
    Extension->>VSCode: Reports diagnostics & quick fixes (💡)

    %% Selection/Line Analysis (AI Copilot)
    User->>VSCode: Runs "Analyze Selected Code with AI" command
    VSCode->>Extension: Triggers selection analysis
    Extension->>Webview: Opens analysis webview
    Extension->>LLM Server: Sends selected code for analysis
    LLM Server-->>Extension: Streams answer (Markdown)
    Extension->>Webview: Updates with streamed answer
    Webview->>User: Shows analysis, enables follow-up

    %% Q/A Analysis (Contextual)
    User->>VSCode: Runs "Contextual Q&A" command
    VSCode->>Extension: Triggers Q&A webview
    Extension->>Webview: Opens Q&A webview
    User->>Webview: Selects files/folders, asks question
    Webview->>Extension: Sends context & question
    Extension->>LLM Server: Sends context & question for analysis
    LLM Server-->>Extension: Returns answer (Markdown/JSON)
    Extension->>Webview: Updates with answer
    Webview->>User: Shows answer, enables follow-up

    %% Real-time Security Fix Suggestions
    Note over Extension,VSCode: For any detected issue, quick fix (💡) is attached and shown in the editor